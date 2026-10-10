"""Web UI cho demo — đóng vai "máy của user" (client agent, vùng tin cậy).

Trình duyệt chỉ hiển thị. Server này thay mặt user đã đăng nhập:
  - giữ JWT và SK của từng user (lưu ở $CLIENT_HOME/<user>/, giống CLI;
    nhờ vậy khóa epoch cũ vẫn còn để minh họa thu hồi),
  - mã hóa / giải mã CP-ABE cục bộ,
  - gọi auth / kgc / keyvault / app.
APP vẫn chỉ nhận và trả ciphertext.
"""
import json
import os
import secrets
from pathlib import Path
from typing import Optional

from fastapi import Cookie, FastAPI, HTTPException, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel

from cpabe.client import core
from cpabe.common.security import decode_user
from cpabe.crypto.errors import AccessDenied, CryptoError

HOME = Path(os.environ.get("CLIENT_HOME", "/data"))
STATIC = Path(__file__).parent / "static"
DEMO_USERS = json.loads(os.environ.get("DEMO_USERS", "{}"))  # {"bob": "bob123", ...}

app = FastAPI(title="cpabe-webui")
SESSIONS: dict = {}  # session_id -> username


# --- trạng thái từng user (mô phỏng thiết bị của user) --------------------------
def _udir(user: str) -> Path:
    d = HOME / user
    d.mkdir(parents=True, exist_ok=True)
    return d


def _read(user: str, name: str) -> Optional[dict]:
    p = _udir(user) / name
    return json.loads(p.read_text()) if p.exists() else None


def _write(user: str, name: str, data: dict):
    p = _udir(user) / name
    p.write_text(json.dumps(data))
    p.chmod(0o600)


def _session_user(sid: Optional[str]) -> str:
    user = SESSIONS.get(sid or "")
    if not user:
        raise HTTPException(401, "chưa đăng nhập")
    return user


def _token(user: str) -> str:
    t = _read(user, "token.json")
    if not t:
        raise HTTPException(401, "chưa đăng nhập")
    return t["access_token"]


def _role(user: str) -> str:
    try:
        return decode_user(_token(user))["app_role"]
    except HTTPException:
        raise HTTPException(401, "token hết hạn, hãy đăng nhập lại")


def _require_role(user: str, *roles: str):
    if _role(user) not in roles:
        raise HTTPException(403, f"cần vai trò {roles}")


def _api(fn, *args, **kw):
    try:
        return fn(*args, **kw)
    except core.ApiError as e:
        raise HTTPException(e.status, e.detail)
    except ValueError as e:  # lỗi cú pháp policy...
        raise HTTPException(422, str(e))


# --- models ---------------------------------------------------------------
class LoginReq(BaseModel):
    username: str
    password: Optional[str] = None


class PutReq(BaseModel):
    policy: str
    text: str


class PolicyReq(BaseModel):
    policy: str


class RevokeReq(BaseModel):
    sub: str


# --- routes ---------------------------------------------------------------
@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/demo-users")
def demo_users():
    return sorted(DEMO_USERS)


@app.post("/api/login")
def login(req: LoginReq, response: Response):
    password = req.password or DEMO_USERS.get(req.username)
    if not password:
        raise HTTPException(400, "thiếu mật khẩu")
    data = _api(core.login, req.username, password)
    _write(req.username, "token.json", data)
    sid = secrets.token_urlsafe(24)
    SESSIONS[sid] = req.username
    response.set_cookie("sid", sid, httponly=True, samesite="strict")
    return {"user": req.username}


@app.post("/api/logout")
def logout(response: Response, sid: Optional[str] = Cookie(None)):
    SESSIONS.pop(sid or "", None)
    response.delete_cookie("sid")
    return {"ok": True}


@app.get("/api/me")
def me(sid: Optional[str] = Cookie(None)):
    user = _session_user(sid)
    key = _read(user, "sk.json")
    return {"user": user, "role": _role(user), "current_epoch": _api(core.epoch),
            "key": None if not key else {"epoch": key["epoch"], "attributes": key["attributes"]}}


@app.post("/api/fetch-key")
def fetch_key(sid: Optional[str] = Cookie(None)):
    user = _session_user(sid)
    data = _api(core.fetch_key, _token(user))
    _write(user, "sk.json", data)
    return {"epoch": data["epoch"], "attributes": data["attributes"]}


@app.get("/api/records")
def records(sid: Optional[str] = Cookie(None)):
    user = _session_user(sid)
    return _api(core.list_records, core.bearer(_token(user)))


@app.get("/api/records/{record_id}")
def read(record_id: str, sid: Optional[str] = Cookie(None)):
    user = _session_user(sid)
    rec = _api(core.get_record, record_id, core.bearer(_token(user)))
    if rec is None:
        raise HTTPException(404, "không có bản ghi")
    key = _read(user, "sk.json")
    result = {"record": rec, "plaintext": None, "status": None, "reason": None}
    if not key:
        result.update(status="no_key", reason="chưa có khóa CP-ABE — bấm 'Lấy khóa'")
        return result
    try:
        result.update(status="ok", plaintext=core.decrypt(key["sk"], rec).decode("utf-8", "replace"))
    except AccessDenied:
        result.update(status="denied",
                      reason=f"thuộc tính {key['attributes']} không thỏa policy {rec['policy_abe']}")
    except CryptoError as e:
        result.update(status="integrity", reason=f"lỗi toàn vẹn: {e}")
    return result


@app.put("/api/records/{record_id}")
def put(record_id: str, req: PutReq, sid: Optional[str] = Cookie(None)):
    user = _session_user(sid)
    return _api(core.put_record, _token(user), record_id, req.policy, req.text.encode("utf-8"))


@app.patch("/api/records/{record_id}/policy")
def set_policy(record_id: str, req: PolicyReq, sid: Optional[str] = Cookie(None)):
    user = _session_user(sid)
    return _api(core.set_policy, _token(user), record_id, req.policy)


@app.delete("/api/records/{record_id}")
def delete(record_id: str, sid: Optional[str] = Cookie(None)):
    user = _session_user(sid)
    return _api(core.delete_record, _token(user), record_id)


@app.post("/api/admin/revoke")
def revoke(req: RevokeReq, sid: Optional[str] = Cookie(None)):
    user = _session_user(sid)
    return _api(core.revoke, _token(user), req.sub)


@app.post("/api/admin/rewrap")
def rewrap(sid: Optional[str] = Cookie(None)):
    _require_role(_session_user(sid), "admin")  # worker chạy bằng service token
    return _api(core.rewrap_all)


@app.get("/api/cloud-view")
def cloud_view(sid: Optional[str] = Cookie(None)):
    _session_user(sid)  # góc nhìn mô phỏng DBA của cloud: chỉ ciphertext
    return _api(core.cloud_view)
