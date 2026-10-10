import re, sys, zlib
data = open(sys.argv[1], 'rb').read()
out = []
def unesc(s):
    s = re.sub(rb'\\([0-7]{1,3})', lambda m: bytes([int(m.group(1), 8) & 255]), s)
    s = s.replace(b'\\(', b'(').replace(b'\\)', b')').replace(b'\\\\', b'\\').replace(b'\\n', b' ')
    return s
for m in re.finditer(rb'stream\r?\n(.*?)\r?\nendstream', data, re.S):
    raw = m.group(1)
    try:
        d = zlib.decompress(raw)
    except Exception:
        try: d = zlib.decompressobj().decompress(raw)
        except Exception: continue
    if b'BT' not in d: continue
    for bt in re.finditer(rb'BT(.*?)ET', d, re.S):
        blk = bt.group(1)
        line = []
        for tok in re.finditer(rb'\[(.*?)\]\s*TJ|\((.*?)(?<!\\)\)\s*(?:Tj|\'|")|(T\*|Td|TD|Tm)|<([0-9A-Fa-f]+)>\s*Tj', blk, re.S):
            if tok.group(1) is not None:
                parts = re.findall(rb'\(((?:\\.|[^\\)])*)\)|(-?\d+\.?\d*)', tok.group(1))
                for s, n in parts:
                    if s: line.append(unesc(s))
                    elif n and float(n) < -200: line.append(b' ')
            elif tok.group(2) is not None:
                line.append(unesc(tok.group(2)))
            elif tok.group(3):
                line.append(b'\n' if tok.group(3) in (b'T*', b'TD', b'Tm') else b' ')
            elif tok.group(4):
                line.append(bytes.fromhex(tok.group(4).decode()))
        out.append(b''.join(line))
sys.stdout.write(b'\n'.join(out).decode('latin-1'))
