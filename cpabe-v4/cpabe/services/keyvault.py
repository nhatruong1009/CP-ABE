"""Keyvault: nơi duy nhất giữ KEK. Bọc / mở CEK qua API, mọi lần gọi đều ghi log.

- /wrap   : owner hoặc worker (service)
- /unwrap : owner hoặc worker (service) — dùng khi đổi policy / re-wrap thu hồi
PoC: KEK lưu trong file của volume. Bản thật dùng HSM / Vault Transit.
"""
import base64
import logging
import os
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from cpabe.common.security import require_roles
from cpabe.crypto.envelope import LocalKek
from cpabe.crypto.errors import IntegrityError

log = logging.getLogger("keyvault")
logging.basicConfig(level=logging.INFO)

DATA = Path(os.environ.get("DATA_DIR", "/data"))
app = FastAPI(title="cpabe-keyvault")


def _load_kek() -> LocalKek:
    DATA.mkdir(parents=True, exist_ok=True)
    p = DATA / "kek.bin"
    if not p.exists():
        p.write_bytes(os.urandom(32))
        p.chmod(0o600)
        log.info("đã sinh KEK mới")
    return LocalKek(p.read_bytes())


KEK = _load_kek()
allowed = require_roles("owner", "service")


class WrapReq(BaseModel):
    cek: str      # base64
    context: str  # record_id


class UnwrapReq(BaseModel):
    blob: str     # base64
    context: str


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/wrap")
def wrap(req: WrapReq, p: dict = Depends(allowed)):
    blob = KEK.wrap(base64.b64decode(req.cek), req.context.encode())
    log.info("WRAP by=%s context=%s", p["sub"], req.context)
    return {"blob": base64.b64encode(blob).decode()}


@app.post("/unwrap")
def unwrap(req: UnwrapReq, p: dict = Depends(allowed)):
    try:
        cek = KEK.unwrap(base64.b64decode(req.blob), req.context.encode())
    except IntegrityError:
        log.warning("UNWRAP_FAIL by=%s context=%s", p["sub"], req.context)
        raise HTTPException(400, "kek_header không hợp lệ cho context này")
    log.info("UNWRAP by=%s context=%s", p["sub"], req.context)
    return {"cek": base64.b64encode(cek).decode()}
