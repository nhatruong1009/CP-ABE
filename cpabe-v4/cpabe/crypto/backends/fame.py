"""Backend mặc định: FAME (Agrawal–Chase 2017) qua Charm `ac17`.

KEM: chọn ngẫu nhiên phần tử m thuộc GT, mã hóa m bằng CP-ABE, rồi suy ra
k_abe = SHA-256(nhãn || serialize(m)). k_abe chỉ dùng để bọc CEK ở tầng record.
Header KHÔNG chứa cây policy. Lúc giải mã, cây được dựng lại từ chuỗi
policy_abe của bản ghi; chuỗi này được ràng buộc (qua policy_hash) vào AAD của lớp bọc CEK.
"""
import hashlib
import re
from typing import List, Tuple

from charm.schemes.abenc.ac17 import AC17CPABE
from charm.toolbox.pairinggroup import GT, PairingGroup

from cpabe.crypto.attrs import check_token
from cpabe.crypto.backends.charm_json import from_json, to_json
from cpabe.crypto.errors import AccessDenied, IntegrityError
from cpabe.crypto.provider import KEY_LEN, AbeProvider

_KEM_LABEL = b"cpabe-v4|fame-kem|"


class FameProvider(AbeProvider):
    def __init__(self, group_name: str = "BN254", assump_size: int = 2):
        self.group_name = group_name
        self.assump_size = assump_size
        self.backend_id = f"fame-{group_name.lower()}-k{assump_size}-v1"
        self.group = PairingGroup(group_name)
        self.scheme = AC17CPABE(self.group, assump_size)

    @classmethod
    def from_backend_id(cls, backend_id: str) -> "FameProvider":
        # dạng: fame-<group>-k<assump>-v1
        parts = backend_id.split("-")
        if len(parts) != 4 or parts[0] != "fame" or not parts[2].startswith("k"):
            raise ValueError(f"backend_id không hợp lệ: {backend_id}")
        return cls(group_name=parts[1].upper(), assump_size=int(parts[2][1:]))

    # --- helpers ---------------------------------------------------------
    def _dump(self, obj) -> dict:
        return to_json(obj, self.group)

    def _load(self, obj):
        return from_json(obj, self.group)

    def _derive_key(self, m) -> bytes:
        return hashlib.sha256(_KEM_LABEL + self.group.serialize(m)).digest()[:KEY_LEN]

    def _parse_policy(self, policy: str):
        # Kiểm tra trên chuỗi gốc: sau khi parse, Charm đã viết hoa và cắt index nên không còn thấy lỗi.
        for word in re.findall(r"[A-Za-z0-9_]+", policy):
            if word.lower() not in ("and", "or"):
                check_token(word)
        return self.scheme.util.createPolicy(policy)

    # --- AbeProvider ------------------------------------------------------
    def setup(self) -> Tuple[dict, dict]:
        pk, msk = self.scheme.setup()
        return self._dump(pk), self._dump(msk)

    def keygen(self, mpk: dict, msk: dict, attrs: List[str]) -> dict:
        if not attrs:
            raise ValueError("tập thuộc tính rỗng")
        for a in attrs:
            check_token(a)
        key = self.scheme.keygen(self._load(mpk), self._load(msk), list(attrs))
        return self._dump(key)

    def encaps(self, mpk: dict, policy: str) -> Tuple[bytes, dict]:
        self._parse_policy(policy)  # kiểm tra token trước khi mã hóa
        m = self.group.random(GT)
        ct = self.scheme.encrypt(self._load(mpk), m, policy)
        ct.pop("policy", None)  # cây policy được dựng lại khi giải mã
        return self._derive_key(m), self._dump(ct)

    def decaps(self, mpk: dict, sk: dict, policy: str, kem_header: dict) -> bytes:
        ct = self._load(kem_header)
        ct["policy"] = self._parse_policy(policy)
        key = self._load(sk)
        # Kiểm tra thuộc tính có thỏa policy không trước khi giải mã (tránh phụ thuộc
        # vào cách ac17.decrypt báo lỗi: in ra màn hình rồi trả None).
        if not self.scheme.util.prune(ct["policy"], key["attr_list"]):
            raise AccessDenied("thuộc tính không thỏa policy")
        try:
            m = self.scheme.decrypt(self._load(mpk), ct, key)
        except Exception as e:
            # Charm 0.63: InvalidCiphertext (khóa ghép / header bị sửa) hoặc ValueError
            # (policy không khớp cấu trúc ciphertext). Cả hai đều là bản ghi không hợp lệ.
            raise IntegrityError(f"KEM không hợp lệ: {type(e).__name__}") from e
        if m is None or m is False:
            raise AccessDenied("thuộc tính không thỏa policy")
        return self._derive_key(m)
