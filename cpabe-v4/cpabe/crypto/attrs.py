"""Mã hóa tên thuộc tính sang token an toàn cho bộ parse policy của Charm.

Thuộc tính logic:  Dept:Cardiology@v1   ->  token:  DEPTXCARDIOLOGYXV1
Epoch:             Epoch:7               ->  token:  EPOCHX7

Ràng buộc từ Charm 0.63 (đã kiểm tra trong mã nguồn):
- toolbox/node.py VIẾT HOA mọi thuộc tính trong policy, còn danh sách thuộc tính
  của khóa thì giữ nguyên. Vì vậy token phải viết hoa toàn bộ, nếu không user
  hợp lệ cũng bị từ chối.
- toolbox/msp.py strip_index cắt phần sau '_' cuối cùng nếu phần đó toàn là
  chữ số ("EPOCH_7" -> "EPOCH"). Vì vậy token không được chứa '_'.

Định dạng: NAME + 'X' + VALUE + 'XV' + version. Tên thuộc tính lấy từ danh mục
cố định trong schema, nên token được phân tách duy nhất: version là phần
'XV<số>' ở cuối, phần còn lại sau 'NAMEX' là value.
"""
import re

_SAFE = re.compile(r"[^A-Za-z0-9]+")
_TOKEN = re.compile(r"^[A-Z0-9]+$")
SEP = "X"


def _norm(part: str) -> str:
    cleaned = _SAFE.sub("", part).upper()
    if not cleaned:
        raise ValueError(f"thành phần thuộc tính rỗng sau khi chuẩn hóa: {part!r}")
    return cleaned


def attr_token(name: str, value: str, version: int = 1) -> str:
    """Thuộc tính có phiên bản (dùng cho cơ chế thu hồi R2)."""
    if version < 1:
        raise ValueError("version phải >= 1")
    return f"{_norm(name)}{SEP}{_norm(value)}{SEP}V{version}"


def epoch_token(epoch: int) -> str:
    """Thuộc tính epoch (dùng cho cơ chế thu hồi R1)."""
    if epoch < 0:
        raise ValueError("epoch phải >= 0")
    return f"EPOCH{SEP}{epoch}"


def check_token(token: str) -> str:
    """Từ chối token mà Charm sẽ xử lý sai (chữ thường, '_', ký tự lạ)."""
    if not _TOKEN.match(token):
        raise ValueError(f"token thuộc tính không hợp lệ cho Charm: {token!r}")
    return token
