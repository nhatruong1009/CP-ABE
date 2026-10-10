"""Client CLI cho PoC (chạy trong container `client`, thuộc vùng máy user).

Mọi phép mã hóa / giải mã CP-ABE diễn ra Ở ĐÂY, không ở APP.
Trạng thái mỗi user (token, SK) lưu trong $CLIENT_HOME/<user>/.

Ví dụ:
  cli login bob bob123
  cli fetch-key bob
  cli put alice BA-0001 --policy "Dept:Cardiology AND Role:Doctor" --text "..."
  cli get bob BA-0001
  cli set-policy alice BA-0001 --policy "Dept:Cardiology AND (Role:Doctor OR Role:Nurse)"
  cli revoke admin bob
  cli worker-rewrap            (dùng SERVICE_TOKEN)
"""
import argparse
import base64
import json
import os
import sys
import time
from pathlib import Path

import httpx

from cpabe.crypto.backends import get_provider
from cpabe.crypto.errors import AccessDenied, CryptoError
from cpabe.crypto.record import open_record, rewrap_header, seal_record
from cpabe.policy.simple import compile_policy

APP = os.environ.get("APP_URL", "http://app:8000")
KGC = os.environ.get("KGC_URL", "http://kgc:8000")
AUTH = os.environ.get("AUTH_URL", "http://auth:8000")
KV = os.environ.get("KEYVAULT_URL", "http://keyvault:8000")
HOME = Path(os.environ.get("CLIENT_HOME", "/data"))
SERVICE_TOKEN = os.environ.get("SERVICE_TOKEN", "")


# --- trạng thái user ---------------------------------------------------------
def _dir(user: str) -> Path:
    d = HOME / user
    d.mkdir(parents=True, exist_ok=True)
    return d


def _token(user: str) -> str:
    p = _dir(user) / "token.json"
    if not p.exists():
        sys.exit(f"[{user}] chưa đăng nhập: chạy `login {user} <password>`")
    return json.loads(p.read_text())["access_token"]


def _auth_headers(user: str) -> dict:
    return {"Authorization": f"Bearer {_token(user)}"}


def _svc_headers() -> dict:
    return {"X-Service-Token": SERVICE_TOKEN}


def _check(r: httpx.Response):
    if r.status_code >= 400:
        sys.exit(f"HTTP {r.status_code}: {r.text}")
    return r.json()


def _mpk():
    data = _check(httpx.get(f"{KGC}/mpk", timeout=10))
    return data["backend"], data["mpk"]


def _epoch() -> int:
    return _check(httpx.get(f"{KGC}/epoch", timeout=10))["epoch"]


class KeyvaultClient:
    """Cài đặt giao diện KekWrapper bằng API của keyvault."""

    def __init__(self, headers: dict):
        self.headers = headers

    def wrap(self, cek: bytes, context: bytes) -> bytes:
        r = _check(httpx.post(f"{KV}/wrap", headers=self.headers, timeout=10,
                              json={"cek": base64.b64encode(cek).decode(), "context": context.decode()}))
        return base64.b64decode(r["blob"])

    def unwrap(self, blob: bytes, context: bytes) -> bytes:
        r = _check(httpx.post(f"{KV}/unwrap", headers=self.headers, timeout=10,
                              json={"blob": base64.b64encode(blob).decode(), "context": context.decode()}))
        return base64.b64decode(r["cek"])


def _get_record(record_id: str, headers: dict):
    r = httpx.get(f"{APP}/records/{record_id}", headers=headers, timeout=10)
    if r.status_code == 404:
        return None
    return _check(r)


# --- lệnh ------------------------------------------------------------------------
def cmd_login(a):
    data = _check(httpx.post(f"{AUTH}/login", json={"username": a.user, "password": a.password},
                             timeout=10))
    (_dir(a.user) / "token.json").write_text(json.dumps(data))
    print(f"[{a.user}] đăng nhập thành công")


def cmd_fetch_key(a):
    data = _check(httpx.post(f"{KGC}/keys", headers=_auth_headers(a.user), timeout=30))
    p = _dir(a.user) / "sk.json"
    p.write_text(json.dumps(data))
    p.chmod(0o600)
    print(f"[{a.user}] nhận khóa epoch={data['epoch']} thuộc tính={data['attributes']}")


def cmd_put(a):
    backend, mpk = _mpk()
    provider = get_provider(backend)
    headers = _auth_headers(a.user)
    epoch = _epoch()
    policy_abe = compile_policy(a.policy, epoch)
    old = _get_record(a.record_id, headers)
    version = 1 if old is None else old["version"] + 1
    cversion = 1 if old is None else old["content_version"] + 1
    data = a.text.encode("utf-8") if a.text is not None else Path(a.file).read_bytes()
    rec = seal_record(provider, mpk, KeyvaultClient(headers), record_id=a.record_id,
                      policy_abe=policy_abe, data=data, version=version, content_version=cversion,
                      policy_ref={"src": a.policy, "epoch": epoch})
    _check(httpx.put(f"{APP}/records/{a.record_id}", headers=headers, json=rec, timeout=30))
    print(f"[{a.user}] {'tạo' if old is None else 'cập nhật'} {a.record_id} "
          f"v{version}/cv{cversion} policy={policy_abe}")


def cmd_get(a):
    p = _dir(a.user) / "sk.json"
    if not p.exists():
        sys.exit(f"[{a.user}] chưa có khóa: chạy `fetch-key {a.user}`")
    sk = json.loads(p.read_text())
    rec = _get_record(a.record_id, _auth_headers(a.user))
    if rec is None:
        sys.exit("không có bản ghi")
    _, mpk = _mpk()
    try:
        data = open_record(mpk, sk["sk"], rec)
    except AccessDenied:
        sys.exit(f"[{a.user}] TỪ CHỐI: thuộc tính {sk['attributes']} không thỏa policy "
                 f"{rec['policy_abe']}")
    except CryptoError as e:
        sys.exit(f"[{a.user}] LỖI TOÀN VẸN: {e}")
    print(f"[{a.user}] {a.record_id} v{rec['version']}: {data.decode('utf-8', 'replace')}")


def _rewrap(rec: dict, new_src: str, epoch: int, kek, provider, mpk) -> dict:
    out = rewrap_header(provider, mpk, kek, rec, new_policy_abe=compile_policy(new_src, epoch))
    out["policy_ref"] = {**out["policy_ref"], "src": new_src, "epoch": epoch}
    return out


def cmd_set_policy(a):
    backend, mpk = _mpk()
    headers = _auth_headers(a.user)
    rec = _get_record(a.record_id, headers)
    if rec is None:
        sys.exit("không có bản ghi")
    out = _rewrap(rec, a.policy, _epoch(), KeyvaultClient(headers), get_provider(backend), mpk)
    _check(httpx.patch(f"{APP}/records/{a.record_id}/header", headers=headers, json=out,
                       timeout=30))
    print(f"[{a.user}] đổi policy {a.record_id} → {out['policy_abe']} (ciphertext giữ nguyên)")


def cmd_delete(a):
    _check(httpx.delete(f"{APP}/records/{a.record_id}", headers=_auth_headers(a.user), timeout=10))
    print(f"[{a.user}] đã xóa {a.record_id}")


def cmd_list(a):
    for r in _check(httpx.get(f"{APP}/records", headers=_auth_headers(a.user), timeout=10)):
        print(f"{r['record_id']:<12} v{r['version']}/cv{r['content_version']}  "
              f"epoch={r['policy_ref'].get('epoch')}  policy={r['policy_ref'].get('src')}")


def cmd_revoke(a):
    data = _check(httpx.post(f"{KGC}/revoke", headers=_auth_headers(a.user),
                             json={"sub": a.sub}, timeout=10))
    print(f"[{a.user}] thu hồi {a.sub}: epoch mới = {data['epoch']}, danh sách = {data['revoked']}")
    print("→ chạy `worker-rewrap` để bọc lại header theo epoch mới; user còn hợp lệ cần fetch-key lại")


def cmd_worker_rewrap(a):
    """Thu hồi mức L1: bọc lại abe_header theo epoch mới, ciphertext giữ nguyên."""
    t0 = time.time()
    backend, mpk = _mpk()
    provider = get_provider(backend)
    epoch = _epoch()
    headers = _svc_headers()
    kek = KeyvaultClient(headers)
    done = skipped = 0
    for item in _check(httpx.get(f"{APP}/records", headers=headers, timeout=30)):
        if item["policy_ref"].get("epoch") == epoch:
            skipped += 1
            continue
        rec = _get_record(item["record_id"], headers)
        out = _rewrap(rec, rec["policy_ref"]["src"], epoch, kek, provider, mpk)
        _check(httpx.patch(f"{APP}/records/{rec['record_id']}/header", headers=headers, json=out,
                           timeout=30))
        done += 1
    print(f"[worker] re-wrap sang epoch {epoch}: {done} bản ghi, bỏ qua {skipped}, "
          f"{time.time() - t0:.2f}s")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="cli", description="CP-ABE PoC client")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("login"); s.add_argument("user"); s.add_argument("password")
    s.set_defaults(fn=cmd_login)
    s = sub.add_parser("fetch-key"); s.add_argument("user"); s.set_defaults(fn=cmd_fetch_key)
    s = sub.add_parser("put"); s.add_argument("user"); s.add_argument("record_id")
    s.add_argument("--policy", required=True)
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--text"); g.add_argument("--file")
    s.set_defaults(fn=cmd_put)
    s = sub.add_parser("get"); s.add_argument("user"); s.add_argument("record_id")
    s.set_defaults(fn=cmd_get)
    s = sub.add_parser("set-policy"); s.add_argument("user"); s.add_argument("record_id")
    s.add_argument("--policy", required=True); s.set_defaults(fn=cmd_set_policy)
    s = sub.add_parser("delete"); s.add_argument("user"); s.add_argument("record_id")
    s.set_defaults(fn=cmd_delete)
    s = sub.add_parser("list"); s.add_argument("user"); s.set_defaults(fn=cmd_list)
    s = sub.add_parser("revoke"); s.add_argument("user"); s.add_argument("sub")
    s.set_defaults(fn=cmd_revoke)
    s = sub.add_parser("worker-rewrap"); s.set_defaults(fn=cmd_worker_rewrap)

    a = ap.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
