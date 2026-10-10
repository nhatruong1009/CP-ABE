"""Bọc CEK bằng KEK (kek_header) — đường dành cho hệ thống: re-wrap, đổi policy.

Ở bước 1 dùng LocalKek, giữ KEK ngay trong process.
Từ bước sau sẽ dùng KeyvaultClient (gọi API /wrap, /unwrap của container
keyvault). Hai class có cùng giao diện nên code gọi không phải sửa.
"""
import os
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cpabe.crypto.errors import IntegrityError


class KekWrapper(Protocol):
    def wrap(self, cek: bytes, context: bytes) -> bytes: ...
    def unwrap(self, blob: bytes, context: bytes) -> bytes: ...


class LocalKek:
    """AES-256-GCM với KEK. Context (record_id) được đưa vào AAD để kek_header
    không dùng được cho bản ghi khác."""

    def __init__(self, kek: bytes):
        if len(kek) != 32:
            raise ValueError("KEK phải dài 32 byte")
        self._aead = AESGCM(kek)

    @classmethod
    def generate(cls) -> "LocalKek":
        return cls(os.urandom(32))

    def wrap(self, cek: bytes, context: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + self._aead.encrypt(nonce, cek, b"kek-wrap|" + context)

    def unwrap(self, blob: bytes, context: bytes) -> bytes:
        try:
            return self._aead.decrypt(blob[:12], blob[12:], b"kek-wrap|" + context)
        except InvalidTag as e:
            raise IntegrityError("kek_header không hợp lệ") from e
