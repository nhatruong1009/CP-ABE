from functools import lru_cache

from cpabe.crypto.provider import AbeProvider


@lru_cache(maxsize=8)
def get_provider(backend_id: str) -> AbeProvider:
    """Chọn backend theo trường abe_backend lưu trong bản ghi (có cache vì khởi tạo
    pairing group tốn thời gian)."""
    if backend_id.startswith("fame-"):
        from cpabe.crypto.backends.fame import FameProvider

        return FameProvider.from_backend_id(backend_id)
    raise ValueError(f"backend không hỗ trợ: {backend_id}")
