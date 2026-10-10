class CryptoError(Exception):
    """Lỗi chung của tầng mật mã."""


class AccessDenied(CryptoError):
    """Khóa của user không thỏa policy của bản ghi."""


class CommitmentError(CryptoError):
    """Commitment không khớp: sai CEK, bị tráo header hoặc metadata bị sửa."""


class IntegrityError(CryptoError):
    """AEAD không xác thực được ciphertext."""
