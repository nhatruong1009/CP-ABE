"""Tạo và mở EncryptedRecord.

Cấu trúc ba lớp:
    data       --cAEAD(CEK, data_aad)-->           ciphertext + nonce + commit
    CEK        --AES-GCM(k_abe, header_aad)-->     abe_header.wrap   (đường cho user)
    k_abe      --CP-ABE KEM(policy)-->             abe_header.kem
    CEK        --KEK(record_id)-->                 kek_header        (đường cho hệ thống)

    data_aad   = record_id || content_version
    header_aad = record_id || version || abe_backend || policy_hash

- Re-wrap / đổi policy: chỉ thay abe_header, tăng version. Ciphertext dữ liệu
  giữ nguyên (thu hồi mức L1).
- Update nội dung: CEK mới, tăng cả content_version và version.
- owner_sig và transparency log được thêm ở tầng T5.
"""
import base64
import hashlib
import json
import os
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cpabe.crypto import caead
from cpabe.crypto.backends import get_provider
from cpabe.crypto.envelope import KekWrapper
from cpabe.crypto.errors import CommitmentError, IntegrityError
from cpabe.crypto.provider import KEY_LEN, AbeProvider


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def _canon(*parts) -> bytes:
    return json.dumps(list(parts), separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def policy_hash(policy_abe: str) -> str:
    return "sha256:" + hashlib.sha256(policy_abe.encode("utf-8")).hexdigest()


def data_aad(record_id: str, content_version: int) -> bytes:
    return _canon("cpabe-v4/data-aad/v1", record_id, content_version)


def header_aad(record_id: str, version: int, abe_backend: str, p_hash: str) -> bytes:
    return _canon("cpabe-v4/header-aad/v1", record_id, version, abe_backend, p_hash)


# --- lớp bọc CEK bằng k_abe ----------------------------------------------
def _make_abe_header(provider: AbeProvider, mpk: dict, cek: bytes, aad: bytes,
                     policy_abe: str) -> dict:
    k_abe, kem = provider.encaps(mpk, policy_abe)
    nonce = os.urandom(12)
    wrap = AESGCM(k_abe).encrypt(nonce, cek, aad)
    return {"kem": kem, "wrap": _b64(nonce + wrap)}


def _open_abe_header(provider: AbeProvider, mpk: dict, sk: dict, policy_abe: str,
                     abe_header: dict, aad: bytes) -> bytes:
    k_abe = provider.decaps(mpk, sk, policy_abe, abe_header["kem"])
    blob = _unb64(abe_header["wrap"])
    try:
        cek = AESGCM(k_abe).decrypt(blob[:12], blob[12:], aad)
    except InvalidTag as e:
        # sai k_abe (ghép khóa, header bị tráo) hoặc metadata/policy bị sửa
        raise IntegrityError("không mở được lớp bọc CEK") from e
    if len(cek) != KEY_LEN:
        raise IntegrityError("CEK có độ dài sai")
    return cek


# --- helpers đọc bản ghi ----------------------------------------------------
def _sealed(record: dict) -> caead.Sealed:
    a = record["aead"]
    if a.get("alg") != caead.ALG_ID:
        raise ValueError(f"thuật toán AEAD không hỗ trợ: {a.get('alg')}")
    return caead.Sealed(nonce=_unb64(a["nonce"]), commit=_unb64(a["commit"]),
                        ciphertext=_unb64(record["ciphertext"]))


def _header_aad_of(record: dict) -> bytes:
    # policy_hash luôn được tính lại từ policy_abe, không tin giá trị lưu sẵn trong bản ghi.
    return header_aad(record["record_id"], record["version"], record["abe_backend"],
                      policy_hash(record["policy_abe"]))


def _data_aad_of(record: dict) -> bytes:
    return data_aad(record["record_id"], record["content_version"])


# --- API -------------------------------------------------------------------
def seal_record(provider: AbeProvider, mpk: dict, kek: KekWrapper, *, record_id: str,
                policy_abe: str, data: bytes, version: int = 1, content_version: int = 1,
                policy_ref: Optional[dict] = None) -> dict:
    """Create / Update nội dung: luôn sinh CEK mới."""
    cek = os.urandom(KEY_LEN)
    p_hash = policy_hash(policy_abe)
    sealed = caead.seal(cek, data, data_aad(record_id, content_version))
    return {
        "record_id": record_id,
        "version": version,
        "content_version": content_version,
        "policy_ref": {**(policy_ref or {}), "policy_hash": p_hash},
        "policy_abe": policy_abe,
        "abe_backend": provider.backend_id,
        "abe_header": _make_abe_header(provider, mpk, cek,
                                       header_aad(record_id, version, provider.backend_id, p_hash),
                                       policy_abe),
        "kek_header": _b64(kek.wrap(cek, record_id.encode("utf-8"))),
        "aead": {"alg": caead.ALG_ID, "nonce": _b64(sealed.nonce),
                 "commit": _b64(sealed.commit)},
        "ciphertext": _b64(sealed.ciphertext),
    }


def open_record(mpk: dict, sk: dict, record: dict) -> bytes:
    """Đường của user: decaps → mở lớp bọc CEK → kiểm tra commit → giải mã."""
    provider = get_provider(record["abe_backend"])
    cek = _open_abe_header(provider, mpk, sk, record["policy_abe"], record["abe_header"],
                           _header_aad_of(record))
    return caead.open_(cek, _sealed(record), _data_aad_of(record))


def unwrap_cek(kek: KekWrapper, record: dict) -> bytes:
    """Đường của hệ thống (worker): lấy CEK qua KEK, kiểm tra khớp commit của dữ liệu."""
    cek = kek.unwrap(_unb64(record["kek_header"]), record["record_id"].encode("utf-8"))
    if not caead.verify_commit(cek, _sealed(record), _data_aad_of(record)):
        raise CommitmentError("CEK từ kek_header không khớp ciphertext")
    return cek


def rewrap_header(provider: AbeProvider, mpk: dict, kek: KekWrapper, record: dict, *,
                  new_policy_abe: str) -> dict:
    """Đổi policy / thu hồi L1: thay abe_header, version+1, dữ liệu giữ nguyên.

    `provider` có thể khác backend cũ (crypto-agility: chuyển backend khi re-wrap).
    """
    cek = unwrap_cek(kek, record)
    out = dict(record)
    out["version"] = record["version"] + 1
    out["policy_abe"] = new_policy_abe
    out["abe_backend"] = provider.backend_id
    out["policy_ref"] = {**record.get("policy_ref", {}),
                         "policy_hash": policy_hash(new_policy_abe)}
    out["abe_header"] = _make_abe_header(provider, mpk, cek, _header_aad_of(out), new_policy_abe)
    return out
