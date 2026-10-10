"""Key-committing AEAD (tầng T3).

Từ CEK, dùng HKDF-SHA256 sinh hai khóa độc lập:
    K_enc — khóa AES-256-GCM
    K_com — khóa tính commitment
commit = HMAC-SHA256(K_com, "commit" || nonce || AAD)

Khi giải mã, kiểm tra commit (so sánh thời gian hằng) TRƯỚC khi giải mã GCM.
Nhờ đó, một ciphertext chỉ hợp lệ với đúng một CEK, chặn được tấn công
"một ciphertext, nhiều khóa" (partitioning oracle / invisible salamanders).
Commit cũng phủ lên AAD, nên tráo header hay sửa metadata đều bị phát hiện.
"""
import hmac
import os
from dataclasses import dataclass
from hashlib import sha256

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cpabe.crypto.errors import CommitmentError, IntegrityError

ALG_ID = "AES-256-GCM+HMAC-SHA256-commit"
NONCE_LEN = 12


def _derive(cek: bytes):
    if len(cek) != 32:
        raise ValueError("CEK phải dài 32 byte")
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=None,
               info=b"cpabe-v4|caead|v1").derive(cek)
    return okm[:32], okm[32:]


def _commit(k_com: bytes, nonce: bytes, aad: bytes) -> bytes:
    return hmac.new(k_com, b"commit|" + nonce + aad, sha256).digest()


@dataclass(frozen=True)
class Sealed:
    nonce: bytes
    commit: bytes
    ciphertext: bytes


def seal(cek: bytes, plaintext: bytes, aad: bytes) -> Sealed:
    k_enc, k_com = _derive(cek)
    nonce = os.urandom(NONCE_LEN)  # mỗi CEK chỉ dùng cho một lần mã hóa
    ct = AESGCM(k_enc).encrypt(nonce, plaintext, aad)
    return Sealed(nonce=nonce, commit=_commit(k_com, nonce, aad), ciphertext=ct)


def open_(cek: bytes, sealed: Sealed, aad: bytes) -> bytes:
    k_enc, k_com = _derive(cek)
    if not hmac.compare_digest(_commit(k_com, sealed.nonce, aad), sealed.commit):
        raise CommitmentError("commitment không khớp")
    try:
        return AESGCM(k_enc).decrypt(sealed.nonce, sealed.ciphertext, aad)
    except InvalidTag as e:
        raise IntegrityError("AEAD tag không hợp lệ") from e


def verify_commit(cek: bytes, sealed: Sealed, aad: bytes) -> bool:
    """Kiểm tra CEK có đúng là khóa của ciphertext này không, mà không cần giải mã.
    Dùng khi re-wrap, để chắc chắn KEK trả về đúng CEK."""
    _, k_com = _derive(cek)
    return hmac.compare_digest(_commit(k_com, sealed.nonce, aad), sealed.commit)
