"""APP / API gateway.

- Không giữ khóa mật mã nào: chỉ nhận và trả EncryptedRecord (ciphertext).
- Xác thực JWT từ auth; chặn user nằm trong danh sách thu hồi của KGC
  (lớp vận hành, cache REVOCATION_TTL giây).
- Ghi xuống outsource-db (PostgreSQL ở vùng cloud).
- Ràng buộc version: PUT tăng version và content_version; PATCH header chỉ tăng
  version, không được đổi ciphertext (đổi policy / re-wrap).
"""
import logging
import os
import time
from typing import Optional

import httpx
import psycopg
from fastapi import Body, Depends, FastAPI, HTTPException
from psycopg.types.json import Jsonb

from cpabe.common.security import SERVICE_TOKEN, principal, require_roles

log = logging.getLogger("app")
logging.basicConfig(level=logging.INFO)

DB_URL = os.environ["DATABASE_URL"]
KGC_URL = os.environ.get("KGC_URL", "http://kgc:8000")
REVOCATION_TTL = float(os.environ.get("REVOCATION_TTL", "2"))

app = FastAPI(title="cpabe-app")
_rev_cache = {"at": 0.0, "revoked": set(), "epoch": None}

REQUIRED = ("record_id", "version", "content_version", "policy_abe", "abe_backend",
            "abe_header", "kek_header", "aead", "ciphertext")


def _revoked() -> set:
    now = time.time()
    if now - _rev_cache["at"] > REVOCATION_TTL:
        r = httpx.get(f"{KGC_URL}/internal/revocations",
                      headers={"X-Service-Token": SERVICE_TOKEN}, timeout=5)
        r.raise_for_status()
        data = r.json()
        _rev_cache.update(at=now, revoked=set(data["revoked"]), epoch=data["epoch"])
    return _rev_cache["revoked"]


def not_revoked(p: dict = Depends(principal)) -> dict:
    if p["kind"] == "user" and p["sub"] in _revoked():
        log.info("BLOCKED_REVOKED user=%s", p["sub"])
        raise HTTPException(403, "user đã bị thu hồi")
    return p


def _db():
    return psycopg.connect(DB_URL, autocommit=False)


def _validate(record_id: str, rec: dict):
    missing = [k for k in REQUIRED if k not in rec]
    if missing:
        raise HTTPException(422, f"thiếu trường: {missing}")
    if rec["record_id"] != record_id:
        raise HTTPException(422, "record_id trong body khác đường dẫn")
    if not isinstance(rec["version"], int) or not isinstance(rec["content_version"], int):
        raise HTTPException(422, "version / content_version phải là số nguyên")


def _current(cur, record_id: str) -> Optional[dict]:
    cur.execute("SELECT doc FROM encrypted_records WHERE record_id = %s FOR UPDATE", (record_id,))
    row = cur.fetchone()
    return row[0] if row else None


def _store(cur, rec: dict):
    cur.execute(
        """INSERT INTO encrypted_records (record_id, version, content_version, doc, updated_at)
           VALUES (%s, %s, %s, %s, now())
           ON CONFLICT (record_id) DO UPDATE
             SET version = EXCLUDED.version, content_version = EXCLUDED.content_version,
                 doc = EXCLUDED.doc, updated_at = now()""",
        (rec["record_id"], rec["version"], rec["content_version"], Jsonb(rec)))


@app.get("/health")
def health():
    return {"ok": True}


@app.put("/records/{record_id}")
def put_record(record_id: str, rec: dict = Body(...), p: dict = Depends(require_roles("owner"))):
    """Create (version=1) hoặc Update nội dung (version, content_version đều +1)."""
    _validate(record_id, rec)
    with _db() as conn, conn.cursor() as cur:
        old = _current(cur, record_id)
        if old is None:
            if rec["version"] != 1 or rec["content_version"] != 1:
                raise HTTPException(409, "bản ghi mới phải có version = content_version = 1")
        elif rec["version"] != old["version"] + 1 or \
                rec["content_version"] != old["content_version"] + 1:
            raise HTTPException(409, f"version không khớp (hiện tại {old['version']}/"
                                     f"{old['content_version']})")
        _store(cur, rec)
    log.info("PUT record=%s v=%s cv=%s by=%s", record_id, rec["version"], rec["content_version"],
             p["sub"])
    return {"record_id": record_id, "version": rec["version"]}


@app.patch("/records/{record_id}/header")
def patch_header(record_id: str, rec: dict = Body(...),
                 p: dict = Depends(require_roles("owner", "service"))):
    """Đổi policy / re-wrap: chỉ abe_header + policy được đổi; ciphertext phải giữ nguyên."""
    _validate(record_id, rec)
    with _db() as conn, conn.cursor() as cur:
        old = _current(cur, record_id)
        if old is None:
            raise HTTPException(404, "không có bản ghi")
        if rec["version"] != old["version"] + 1:
            raise HTTPException(409, f"version phải là {old['version'] + 1}")
        for k in ("content_version", "ciphertext", "aead", "kek_header"):
            if rec[k] != old[k]:
                raise HTTPException(409, f"PATCH header không được đổi trường {k}")
        _store(cur, rec)
    log.info("PATCH_HEADER record=%s v=%s by=%s", record_id, rec["version"], p["sub"])
    return {"record_id": record_id, "version": rec["version"]}


@app.get("/records/{record_id}")
def get_record(record_id: str, p: dict = Depends(not_revoked)):
    with _db() as conn, conn.cursor() as cur:
        cur.execute("SELECT doc FROM encrypted_records WHERE record_id = %s", (record_id,))
        row = cur.fetchone()
    if not row:
        raise HTTPException(404, "không có bản ghi")
    log.info("GET record=%s by=%s", record_id, p["sub"])
    return row[0]


@app.get("/records")
def list_records(p: dict = Depends(not_revoked)):
    """Danh sách metadata (id, version, policy). Không chứa nội dung; mọi user chưa bị thu hồi đều xem được."""
    with _db() as conn, conn.cursor() as cur:
        cur.execute("""SELECT record_id, version, content_version, doc->'policy_ref', updated_at
                       FROM encrypted_records ORDER BY record_id""")
        rows = cur.fetchall()
    return [{"record_id": r[0], "version": r[1], "content_version": r[2], "policy_ref": r[3],
             "updated_at": r[4].isoformat()} for r in rows]


@app.delete("/records/{record_id}")
def delete_record(record_id: str, p: dict = Depends(require_roles("owner"))):
    with _db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM encrypted_records WHERE record_id = %s", (record_id,))
        if cur.rowcount == 0:
            raise HTTPException(404, "không có bản ghi")
    log.info("DELETE record=%s by=%s", record_id, p["sub"])
    return {"deleted": record_id}
