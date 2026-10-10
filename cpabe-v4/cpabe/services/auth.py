"""Service xác thực (auth): đăng nhập → JWT EdDSA; cung cấp thuộc tính user cho KGC.

PoC: danh sách user và mật khẩu demo lấy từ /config/users.json.
Bản thật sẽ thay bằng IdP (Keycloak / OIDC) + HR directory.
"""
import hmac
import json
import logging
import os
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from cpabe.common.security import AUDIENCE, require_service

log = logging.getLogger("auth")
logging.basicConfig(level=logging.INFO)

DATA = Path(os.environ.get("DATA_DIR", "/data"))
USERS_FILE = Path(os.environ.get("USERS_FILE", "/config/users.json"))
TOKEN_TTL = int(os.environ.get("TOKEN_TTL", "3600"))

app = FastAPI(title="cpabe-auth")


def _load_key() -> Ed25519PrivateKey:
    DATA.mkdir(parents=True, exist_ok=True)
    path = DATA / "jwt_ed25519.pem"
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    path.chmod(0o600)
    log.info("đã sinh khóa ký JWT mới")
    return key


PRIV = _load_key()
PUB_PEM = PRIV.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
USERS = json.loads(USERS_FILE.read_text(encoding="utf-8"))


class LoginReq(BaseModel):
    username: str
    password: str


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/public-key", response_class=PlainTextResponse)
def public_key():
    return PUB_PEM.decode("ascii")


@app.post("/login")
def login(req: LoginReq):
    u = USERS.get(req.username)
    # so sánh thời gian hằng; với user không tồn tại vẫn so với chuỗi giả
    expected = (u or {}).get("password", "\x00invalid")
    if not hmac.compare_digest(req.password.encode(), expected.encode()) or u is None:
        log.info("LOGIN_FAIL user=%s", req.username)
        raise HTTPException(401, "sai tên đăng nhập hoặc mật khẩu")
    now = int(time.time())
    claims = {"sub": req.username, "app_role": u["app_role"], "aud": AUDIENCE,
              "iat": now, "exp": now + TOKEN_TTL}
    log.info("LOGIN_OK user=%s role=%s", req.username, u["app_role"])
    return {"access_token": jwt.encode(claims, PRIV, algorithm="EdDSA"), "expires_in": TOKEN_TTL}


@app.get("/internal/attributes/{sub}", dependencies=[Depends(require_service)])
def attributes(sub: str):
    u = USERS.get(sub)
    if u is None:
        raise HTTPException(404, "không có user")
    return {"sub": sub, "attributes": u.get("attributes", {})}
