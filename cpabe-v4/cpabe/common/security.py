"""Xác thực dùng chung cho các service.

- User: JWT (EdDSA) do service `auth` phát. Các service khác lấy public key của
  auth qua GET /public-key (lazy, có retry) và kiểm tra mọi request.
- Service-to-service: header `X-Service-Token`, so khớp với biến môi trường
  SERVICE_TOKEN (PoC; bản thật nên dùng mTLS).
"""
import hmac
import os
import time
from typing import Optional

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from fastapi import Depends, Header, HTTPException

AUDIENCE = "cpabe-poc"
AUTH_URL = os.environ.get("AUTH_URL", "http://auth:8000")
SERVICE_TOKEN = os.environ.get("SERVICE_TOKEN", "")

_public_key = None


def auth_public_key():
    global _public_key
    if _public_key is None:
        last = None
        for _ in range(30):
            try:
                r = httpx.get(f"{AUTH_URL}/public-key", timeout=3)
                r.raise_for_status()
                _public_key = serialization.load_pem_public_key(r.content)
                break
            except Exception as e:  # auth chưa sẵn sàng
                last = e
                time.sleep(1)
        else:
            raise RuntimeError(f"không lấy được public key của auth: {last}")
    return _public_key


def _bearer(authorization: Optional[str]) -> Optional[str]:
    if authorization and authorization.startswith("Bearer "):
        return authorization[len("Bearer "):]
    return None


def decode_user(token: str) -> dict:
    try:
        return jwt.decode(token, auth_public_key(), algorithms=["EdDSA"], audience=AUDIENCE)
    except jwt.PyJWTError as e:
        raise HTTPException(401, f"token không hợp lệ: {e}")


def is_service(x_service_token: Optional[str]) -> bool:
    return bool(SERVICE_TOKEN) and bool(x_service_token) and \
        hmac.compare_digest(x_service_token, SERVICE_TOKEN)


def principal(authorization: Optional[str] = Header(None),
              x_service_token: Optional[str] = Header(None)) -> dict:
    """User (từ JWT) hoặc service (từ X-Service-Token)."""
    if is_service(x_service_token):
        return {"kind": "service", "sub": "service"}
    token = _bearer(authorization)
    if not token:
        raise HTTPException(401, "thiếu Authorization: Bearer <token>")
    claims = decode_user(token)
    return {"kind": "user", **claims}


def require_service(p: dict = Depends(principal)) -> dict:
    if p["kind"] != "service":
        raise HTTPException(403, "chỉ dành cho service nội bộ")
    return p


def require_roles(*roles: str):
    """Cho phép user có app_role thuộc `roles`; thêm 'service' để cho phép service."""
    def dep(p: dict = Depends(principal)) -> dict:
        if p["kind"] == "service":
            if "service" in roles:
                return p
            raise HTTPException(403, "service không được phép")
        if p.get("app_role") not in roles:
            raise HTTPException(403, f"cần vai trò {roles}, có {p.get('app_role')}")
        return p
    return dep


def require_user(p: dict = Depends(principal)) -> dict:
    if p["kind"] != "user":
        raise HTTPException(403, "chỉ dành cho user")
    return p
