"""Bộ dịch policy dạng đọc được → policy Charm (bản tối giản cho PoC; Cedar ở tầng T1 sau).

Cú pháp:  Dept:Cardiology AND (Role:Doctor OR Role:Director)
          - thuộc tính: Name:Value   (chữ, số, khoảng trắng không được phép trong value)
          - toán tử: AND, OR (không phân biệt hoa thường), ngoặc ()
          - KHÔNG hỗ trợ NOT (CP-ABE chỉ hỗ trợ policy đơn điệu)
Kết quả luôn được ghép thêm epoch:  (<expr>) and EPOCHX<e>
"""
import re

from cpabe.crypto.attrs import attr_token, epoch_token

_TOK = re.compile(r"\s*(\(|\)|[A-Za-z]+:[A-Za-z0-9]+|AND\b|OR\b|NOT\b)", re.IGNORECASE)


def _tokens(src: str):
    pos, out = 0, []
    src = src.strip()
    while pos < len(src):
        m = _TOK.match(src, pos)
        if not m:
            raise ValueError(f"policy sai cú pháp tại vị trí {pos}: {src[pos:pos + 20]!r}")
        out.append(m.group(1))
        pos = m.end()
    return out


def compile_policy(src: str, epoch: int) -> str:
    toks = _tokens(src)
    if not toks:
        raise ValueError("policy rỗng")
    depth, out, expect_operand = 0, [], True
    for t in toks:
        up = t.upper()
        if up == "NOT":
            raise ValueError("NOT không được hỗ trợ: CP-ABE chỉ hỗ trợ policy đơn điệu (AND/OR)")
        if t == "(":
            if not expect_operand:
                raise ValueError("thiếu toán tử trước '('")
            depth += 1
            out.append("(")
        elif t == ")":
            if expect_operand or depth == 0:
                raise ValueError("ngoặc ')' không hợp lệ")
            depth -= 1
            out.append(")")
        elif up in ("AND", "OR"):
            if expect_operand:
                raise ValueError(f"thiếu thuộc tính trước {up}")
            out.append(up.lower())
            expect_operand = True
        else:
            if not expect_operand:
                raise ValueError(f"thiếu toán tử trước {t}")
            name, value = t.split(":", 1)
            out.append(attr_token(name, value))
            expect_operand = False
    if expect_operand or depth != 0:
        raise ValueError("policy chưa hoàn chỉnh (thiếu thuộc tính hoặc ngoặc)")
    return f"({' '.join(out)}) and {epoch_token(epoch)}"
