import base64
import html
import json
import quopri
import re
import urllib.parse

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _base_encode(data: bytes, alphabet: str) -> bytes:
    if not data:
        return b""
    base = len(alphabet)
    num = int.from_bytes(data, "big")
    chars = []
    while num > 0:
        num, rem = divmod(num, base)
        chars.append(alphabet[rem])
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return (alphabet[0] * pad + "".join(reversed(chars))).encode("ascii")


def _base_decode(data: bytes, alphabet: str) -> bytes:
    s = re.sub(r"\s+", "", data.decode("ascii"))
    if not s:
        return b""
    base = len(alphabet)
    num = 0
    for ch in s:
        idx = alphabet.find(ch)
        if idx == -1:
            raise ValueError(f"Invalid character {ch!r} for base-{base} alphabet.")
        num = num * base + idx
    pad = 0
    for ch in s:
        if ch == alphabet[0]:
            pad += 1
        else:
            break
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num > 0 else b""
    return (b"\x00" * pad) + raw


def b58_encode(data: bytes) -> bytes:
    return _base_encode(data, B58_ALPHABET)


def b58_decode(data: bytes) -> bytes:
    return _base_decode(data, B58_ALPHABET)


def b62_encode(data: bytes) -> bytes:
    return _base_encode(data, B62_ALPHABET)


def b62_decode(data: bytes) -> bytes:
    return _base_decode(data, B62_ALPHABET)


def rot13(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if 65 <= b <= 90:
            out.append(65 + (b - 65 + 13) % 26)
        elif 97 <= b <= 122:
            out.append(97 + (b - 97 + 13) % 26)
        else:
            out.append(b)
    return bytes(out)


def xor_bytes(data: bytes, key: str = "0x55") -> bytes:
    k = key.strip()
    key_bytes = bytes.fromhex(k[2:]) if k.startswith(("0x", "0X")) else k.encode("utf-8")
    if not key_bytes:
        raise ValueError("Provide a non-empty XOR key (e.g., 0x55 or secret).")
    return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))


def json_beautify(data: bytes) -> bytes:
    obj = json.loads(data.decode("utf-8"))
    return json.dumps(obj, indent=2, ensure_ascii=False).encode("utf-8")


def url_double_encode(data: bytes) -> bytes:
    once = urllib.parse.quote_from_bytes(data).encode("ascii")
    return urllib.parse.quote_from_bytes(once).encode("ascii")


def url_double_decode(data: bytes) -> bytes:
    s = data.decode("latin-1")
    return urllib.parse.unquote_to_bytes(urllib.parse.unquote(s))


def html_encode(data: bytes) -> bytes:
    return html.escape(data.decode("utf-8", errors="replace")).encode("utf-8")


def html_decode(data: bytes) -> bytes:
    return html.unescape(data.decode("utf-8", errors="replace")).encode("utf-8")


def unicode_unescape(data: bytes) -> bytes:
    return data.decode("utf-8").encode("latin-1").decode("unicode_escape").encode("utf-8")


def qp_encode(data: bytes) -> bytes:
    return quopri.encodestring(data)


def qp_decode(data: bytes) -> bytes:
    return quopri.decodestring(data)


def b16_encode(data: bytes) -> bytes:
    return base64.b16encode(data)


def b16_decode(data: bytes) -> bytes:
    return base64.b16decode(re.sub(rb"\s+", b"", data), casefold=True)


def b32_encode(data: bytes) -> bytes:
    return base64.b32encode(data)


def b32_decode(data: bytes) -> bytes:
    return base64.b32decode(re.sub(rb"\s+", b"", data), casefold=True)


def b64_encode(data: bytes) -> bytes:
    return base64.b64encode(data)


def b64_decode(data: bytes) -> bytes:
    return base64.b64decode(re.sub(rb"\s+", b"", data))


def b64url_encode(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data)


def b64url_decode(data: bytes) -> bytes:
    cleaned = re.sub(rb"\s+", b"", data)
    pad = (-len(cleaned)) % 4
    return base64.urlsafe_b64decode(cleaned + b"=" * pad)


def a85_encode(data: bytes) -> bytes:
    return base64.a85encode(data)


def a85_decode(data: bytes) -> bytes:
    return base64.a85decode(data)


def url_encode(data: bytes) -> bytes:
    return urllib.parse.quote_from_bytes(data).encode("ascii")


def url_decode(data: bytes) -> bytes:
    return urllib.parse.unquote_to_bytes(data.decode("latin-1"))
