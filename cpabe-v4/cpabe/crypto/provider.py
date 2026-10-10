"""Giao diện AbeProvider (crypto-agility).

Mọi backend ABE (fame, sau này là covercrypt, tinyabe...) đều cài đặt cùng
một giao diện KEM:
    encaps(mpk, policy) -> (k_abe, kem_header)
    decaps(mpk, sk, policy, kem_header) -> k_abe
k_abe KHÔNG phải CEK. Tầng record dùng k_abe để bọc một CEK độc lập, nhờ đó
re-wrap / đổi policy giữ nguyên được CEK và ciphertext dữ liệu.
Mọi khóa và header đều ở dạng JSON-able, không dùng pickle, vì header được
đọc lại từ cloud (dữ liệu không tin cậy).
"""
from abc import ABC, abstractmethod
from typing import List, Tuple

KEY_LEN = 32


class AbeProvider(ABC):
    #: Ghi vào bản ghi để biết bản ghi được tạo bằng backend nào.
    backend_id: str = ""

    @abstractmethod
    def setup(self) -> Tuple[dict, dict]:
        """Trả về (mpk, msk) ở dạng JSON-able."""

    @abstractmethod
    def keygen(self, mpk: dict, msk: dict, attrs: List[str]) -> dict:
        """Cấp khóa bí mật cho một tập thuộc tính (token từ attrs.py)."""

    @abstractmethod
    def encaps(self, mpk: dict, policy: str) -> Tuple[bytes, dict]:
        """Sinh k_abe ngẫu nhiên (KEY_LEN byte) và kem_header bọc nó theo policy."""

    @abstractmethod
    def decaps(self, mpk: dict, sk: dict, policy: str, kem_header: dict) -> bytes:
        """Khôi phục k_abe. Ném AccessDenied nếu thuộc tính không thỏa policy."""
