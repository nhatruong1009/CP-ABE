"""Key Generation Center.

- Setup lần đầu: sinh MPK, MSK. MSK được seal bằng AES-GCM với KGC_SEAL_KEY.
- POST /keys: user đăng nhập → lấy thuộc tính từ auth → KeyGen(attrs + epoch).
- POST /revoke (admin): thêm user vào danh sách thu hồi, epoch+1 (cơ chế R1).
- GET /internal/revocations: app và worker đọc danh sách thu hồi và epoch hiện tại.
"""
import json
import logging
import os
import threading
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from cpabe.common.security import AUTH_URL, SERVICE_TOKEN, require_roles, require_service, \
    require_user
from cpabe.crypto.attrs import attr_token, epoch_token
from cpabe.crypto.backends.fame import FameProvider

log = logging.getLogger("kgc")
logging.basicConfig(level=logging.INFO)

DATA = Path(os.environ.get("DATA_DIR", "/data"))
SEAL_KEY = bytes.fromhex(os.environ["KGC_SEAL_KEY"])  # 32 byte hex, bắt buộc
_lock = threading.Lock()

app = FastAPI(title="cpabe-kgc")
provider = FameProvider()


def _seal(obj: dict) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(SEAL_KEY).encrypt(nonce, json.dumps(obj).encode(), b"kgc-msk")


def _unseal(blob: bytes) -> dict:
    return json.loads(AESGCM(SEAL_KEY).decrypt(blob[:12], blob[12:], b"kgc-msk"))


def _init():
    DATA.mkdir(parents=True, exist_ok=True)
    mpk_p, msk_p, st_p = DATA / "mpk.json", DATA / "msk.sealed", DATA / "state.json"
    if mpk_p.exists() and msk_p.exists():
        mpk, msk = json.loads(mpk_p.read_text()), _unseal(msk_p.read_bytes())
        log.info("đã nạp MPK/MSK từ volume")
    else:
        mpk, msk = provider.setup()
        mpk_p.write_text(json.dumps(mpk))
        msk_p.write_bytes(_seal(msk))
        msk_p.chmod(0o600)
        log.info("SETUP: đã sinh MPK/MSK mới (backend=%s)", provider.backend_id)
    state = json.loads(st_p.read_text()) if st_p.exists() else {"epoch": 1, "revoked": []}
    return mpk, msk, state


MPK, MSK, STATE = _init()


def _save_state():
    (DATA / "state.json").write_text(json.dumps(STATE))


class RevokeReq(BaseModel):
    sub: str


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/mpk")
def get_mpk():
    return {"backend": provider.backend_id, "mpk": MPK}


@app.get("/epoch")
def get_epoch():
    return {"epoch": STATE["epoch"]}


@app.post("/keys")
def issue_key(user: dict = Depends(require_user)):
    sub = user["sub"]
    if sub in STATE["revoked"]:
        log.info("KEYGEN_DENIED user=%s (đã bị thu hồi)", sub)
        raise HTTPException(403, "user đã bị thu hồi")
    r = httpx.get(f"{AUTH_URL}/internal/attributes/{sub}",
                  headers={"X-Service-Token": SERVICE_TOKEN}, timeout=5)
    if r.status_code != 200:
        raise HTTPException(502, f"không lấy được thuộc tính từ auth: {r.status_code}")
    attrs = r.json()["attributes"]
    with _lock:
        epoch = STATE["epoch"]
    tokens = [attr_token(k, v) for k, v in sorted(attrs.items())] + [epoch_token(epoch)]
    sk = provider.keygen(MPK, MSK, tokens)
    log.info("KEYGEN user=%s epoch=%s attrs=%s", sub, epoch, tokens)
    return {"sk": sk, "epoch": epoch, "attributes": tokens, "backend": provider.backend_id}


@app.post("/revoke")
def revoke(req: RevokeReq, admin: dict = Depends(require_roles("admin"))):
    with _lock:
        if req.sub not in STATE["revoked"]:
            STATE["revoked"].append(req.sub)
        STATE["epoch"] += 1
        _save_state()
        log.info("REVOKE user=%s by=%s new_epoch=%s", req.sub, admin["sub"], STATE["epoch"])
        return {"revoked": STATE["revoked"], "epoch": STATE["epoch"]}


@app.get("/internal/revocations", dependencies=[Depends(require_service)])
def revocations():
    return {"revoked": STATE["revoked"], "epoch": STATE["epoch"]}
