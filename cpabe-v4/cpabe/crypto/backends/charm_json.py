"""Chuyển đối tượng Charm <-> JSON một cách an toàn.

Không dùng charm.core.engine.util.objectToBytes/bytesToObject, vì hai hàm này
dựa trên pickle: unpickle header lấy từ cloud là lỗ hổng thực thi mã từ xa (RCE).
Chỉ hỗ trợ dict / list / tuple / str / int / bool / None và phần tử pairing.
Gặp kiểu nào khác (ví dụ cây policy) thì báo lỗi, không serialize ngầm.
"""
from charm.core.math.pairing import pc_element

_EL = "__el__"
_TUPLE = "__tuple__"
_MAP = "__map__"


def to_json(obj, group):
    if isinstance(obj, pc_element):
        return {_EL: group.serialize(obj).decode("ascii")}
    if isinstance(obj, dict):
        if all(isinstance(k, str) for k in obj):
            return {k: to_json(v, group) for k, v in obj.items()}
        return {_MAP: [[to_json(k, group), to_json(v, group)] for k, v in obj.items()]}
    if isinstance(obj, tuple):
        return {_TUPLE: [to_json(v, group) for v in obj]}
    if isinstance(obj, list):
        return [to_json(v, group) for v in obj]
    if obj is None or isinstance(obj, (str, int, bool)):
        return obj
    raise TypeError(f"không serialize được kiểu {type(obj).__name__}")


def from_json(obj, group):
    if isinstance(obj, dict):
        if set(obj) == {_EL}:
            return group.deserialize(obj[_EL].encode("ascii"))
        if set(obj) == {_TUPLE}:
            return tuple(from_json(v, group) for v in obj[_TUPLE])
        if set(obj) == {_MAP}:
            return {from_json(k, group): from_json(v, group) for k, v in obj[_MAP]}
        return {k: from_json(v, group) for k, v in obj.items()}
    if isinstance(obj, list):
        return [from_json(v, group) for v in obj]
    if obj is None or isinstance(obj, (str, int, bool)):
        return obj
    raise TypeError(f"JSON không hợp lệ: kiểu {type(obj).__name__}")
