"""Thư viện client dùng chung cho Web UI: gọi auth / kgc / keyvault / app và
thực hiện mã hóa, giải mã CP-ABE PHÍA USER. Lỗi được ném ra dưới dạng
exception (khác cli.py, nơi lỗi kết thúc bằng sys.exit)."""
import base64
import os
import time
from functools import lru_cache
from typing import Optional

import httpx

from cpabe.crypto.backends import get_provider
from cpabe.crypto.record import open_record, rewrap_header, seal_record
from cpabe.policy.simple import compile_policy

APP = os.environ.get("APP_URL", "http://app:8000")
KGC = os.environ.get("KGC_URL", "http://kgc:8000")
AUTH = os.environ.get("AUTH_URL", "http://auth:8000")
KV = os.environ.get("KEYVAULT_URL", "http://keyvault:8000")
SERVICE_TOKEN = os.environ.get("SERVICE_TOKEN", "")


class ApiError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(f"HTTP {status}: {detail}")
        self.status, self.detail = status, detail


def _call(method: str, url: str, **kw):
    r = httpx.request(method, url, timeout=30, **kw)
    if r.status_code >= 400:
        try:
            detail = r.json().get("detail", r.text)
        except ValueError:
            detail = r.text
        raise ApiError(r.status_code, str(detail))
    return r.json()


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def service_headers() -> dict:
    return {"X-Service-Token": SERVICE_TOKEN}


class KeyvaultClient:
    def __init__(self, headers: dict):
        self.headers = headers

    def wrap(self, cek: bytes, context: bytes) -> bytes:
        r = _call("POST", f"{KV}/wrap", headers=self.headers,
                  json={"cek": base64.b64encode(cek).decode(), "context": context.decode()})
        return base64.b64decode(r["blob"])

    def unwrap(self, blob: bytes, context: bytes) -> bytes:
        r = _call("POST", f"{KV}/unwrap", headers=self.headers,
                  json={"blob": base64.b64encode(blob).decode(), "context": context.decode()})
        return base64.b64decode(r["cek"])


@lru_cache(maxsize=1)
def mpk():
    data = _call("GET", f"{KGC}/mpk")
    return data["backend"], data["mpk"]


def epoch() -> int:
    return _call("GET", f"{KGC}/epoch")["epoch"]


def login(username: str, password: str) -> dict:
    return _call("POST", f"{AUTH}/login", json={"username": username, "password": password})


def fetch_key(token: str) -> dict:
    return _call("POST", f"{KGC}/keys", headers=bearer(token))


def list_records(headers: dict) -> list:
    return _call("GET", f"{APP}/records", headers=headers)


def get_record(record_id: str, headers: dict) -> Optional[dict]:
    try:
        return _call("GET", f"{APP}/records/{record_id}", headers=headers)
    except ApiError as e:
        if e.status == 404:
            return None
        raise


def decrypt(sk: dict, rec: dict) -> bytes:
    _, m = mpk()
    return open_record(m, sk, rec)


def put_record(token: str, record_id: str, policy_src: str, data: bytes) -> dict:
    backend, m = mpk()
    headers = bearer(token)
    e = epoch()
    old = get_record(record_id, headers)
    version = 1 if old is None else old["version"] + 1
    cversion = 1 if old is None else old["content_version"] + 1
    rec = seal_record(get_provider(backend), m, KeyvaultClient(headers), record_id=record_id,
                      policy_abe=compile_policy(policy_src, e), data=data, version=version,
                      content_version=cversion, policy_ref={"src": policy_src, "epoch": e})
    _call("PUT", f"{APP}/records/{record_id}", headers=headers, json=rec)
    return {"created": old is None, "version": version, "content_version": cversion,
            "policy_abe": rec["policy_abe"]}


def _rewrap(rec: dict, new_src: str, e: int, kek) -> dict:
    backend, m = mpk()
    out = rewrap_header(get_provider(backend), m, kek, rec,
                        new_policy_abe=compile_policy(new_src, e))
    out["policy_ref"] = {**out["policy_ref"], "src": new_src, "epoch": e}
    return out


def set_policy(token: str, record_id: str, policy_src: str) -> dict:
    headers = bearer(token)
    rec = get_record(record_id, headers)
    if rec is None:
        raise ApiError(404, "không có bản ghi")
    out = _rewrap(rec, policy_src, epoch(), KeyvaultClient(headers))
    _call("PATCH", f"{APP}/records/{record_id}/header", headers=headers, json=out)
    return {"version": out["version"], "policy_abe": out["policy_abe"],
            "ciphertext_unchanged": out["ciphertext"] == rec["ciphertext"]}


def delete_record(token: str, record_id: str) -> dict:
    return _call("DELETE", f"{APP}/records/{record_id}", headers=bearer(token))


def revoke(token: str, sub: str) -> dict:
    return _call("POST", f"{KGC}/revoke", headers=bearer(token), json={"sub": sub})


def rewrap_all() -> dict:
    """Worker: bọc lại abe_header của mọi bản ghi sang epoch hiện tại (thu hồi L1)."""
    t0 = time.time()
    e = epoch()
    headers = service_headers()
    kek = KeyvaultClient(headers)
    done = skipped = 0
    for item in list_records(headers):
        if item["policy_ref"].get("epoch") == e:
            skipped += 1
            continue
        rec = get_record(item["record_id"], headers)
        out = _rewrap(rec, rec["policy_ref"]["src"], e, kek)
        _call("PATCH", f"{APP}/records/{rec['record_id']}/header", headers=headers, json=out)
        done += 1
    return {"epoch": e, "rewrapped": done, "skipped": skipped, "seconds": round(time.time() - t0, 3)}


def cloud_view() -> list:
    """Những gì cloud / DBA nhìn thấy: EncryptedRecord thô."""
    headers = service_headers()
    return [get_record(i["record_id"], headers) for i in list_records(headers)]
