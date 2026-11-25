import bz2
import gzip
import lzma
import re
import zlib

MAX_DECOMPRESS_BYTES = 10 * 1024 * 1024  # 10 MB safety ceiling against decompression bombs


def detect_compression(data: bytes) -> tuple[str, float]:
    """Return (algorithm_name, confidence_0_to_1) from magic headers."""
    if len(data) >= 2 and data[:2] == b"\x1f\x8b":
        return ("GZIP", 0.99)
    if len(data) >= 3 and data[:3] == b"BZh" and data[3:4] in b"123456789":
        return ("BZIP2", 0.98)
    if len(data) >= 6 and data[:6] == b"\xfd7zXZ\x00":
        return ("XZ", 0.99)
    if len(data) >= 2 and data[0] == 0x78 and ((data[0] << 8) + data[1]) % 31 == 0:
        return ("ZLIB", 0.92)
    if len(data) >= 4 and data[:4] == b"\x28\xb5\x2f\xfd":
        return ("ZSTD (external lib required)", 0.99)
    return ("None detected", 0.0)


def decode_http_chunked(body: bytes) -> bytes:
    pos = 0
    out = bytearray()
    n = len(body)
    while pos < n:
        line_end = body.find(b"\r\n", pos)
        if line_end == -1:
            break
        size_token = body[pos:line_end].split(b";", 1)[0].strip()
        if not size_token:
            pos = line_end + 2
            continue
        chunk_size = int(size_token, 16)
        if chunk_size == 0:
            break
        data_start = line_end + 2
        data_end = min(data_start + chunk_size, n)
        out.extend(body[data_start:data_end])
        pos = data_end + 2
    return bytes(out)


def _bounded_zlib(payload: bytes, wbits: int, max_bytes: int = MAX_DECOMPRESS_BYTES) -> bytes:
    dobj = zlib.decompressobj(wbits)
    out = bytearray()
    mv = memoryview(payload)
    for i in range(0, len(mv), 16384):
        rem = max_bytes - len(out)
        if rem <= 0:
            raise ValueError(f"Decompression aborted: exceeded {max_bytes // (1024 * 1024)} MB safety limit.")
        try:
            out.extend(dobj.decompress(mv[i:i + 16384], rem))
        except zlib.error as exc:
            if out:
                return bytes(out)
            if wbits == 16 + zlib.MAX_WBITS and len(payload) > 18 and "incorrect data check" in str(exc):
                return _bounded_zlib(payload[10:-8], -zlib.MAX_WBITS, max_bytes)
            raise ValueError(f"Corrupt Zlib/Gzip/Deflate stream: {exc}") from exc
        if dobj.unconsumed_tail and len(out) >= max_bytes:
            raise ValueError(f"Decompression aborted: exceeded {max_bytes // (1024 * 1024)} MB safety limit.")
        if dobj.eof:
            break
    try:
        rem = max_bytes - len(out)
        if rem > 0:
            out.extend(dobj.flush(rem))
    except zlib.error:
        pass
    return bytes(out)


def gzip_decompress(data: bytes, max_bytes: int = MAX_DECOMPRESS_BYTES) -> bytes:
    sep = data.find(b"\r\n\r\n")
    if not data.startswith(b"\x1f\x8b") and sep != -1:
        headers, body = data[:sep], data[sep + 4:]
        if re.search(rb"(?i)^transfer-encoding:\s*chunked\b", headers, re.M):
            body = decode_http_chunked(body)
        if body.startswith(b"\x1f\x8b"):
            return headers + b"\r\n\r\n" + _bounded_zlib(body, 16 + zlib.MAX_WBITS, max_bytes)
    return _bounded_zlib(data, 16 + zlib.MAX_WBITS, max_bytes)


def gzip_compress(data: bytes) -> bytes:
    return gzip.compress(data)


def zlib_decompress(data: bytes, max_bytes: int = MAX_DECOMPRESS_BYTES) -> bytes:
    return _bounded_zlib(data, zlib.MAX_WBITS, max_bytes)


def zlib_compress(data: bytes) -> bytes:
    return zlib.compress(data)


def deflate_decompress(data: bytes, max_bytes: int = MAX_DECOMPRESS_BYTES) -> bytes:
    return _bounded_zlib(data, -zlib.MAX_WBITS, max_bytes)


def bz2_decompress(data: bytes, max_bytes: int = MAX_DECOMPRESS_BYTES) -> bytes:
    dec = bz2.BZ2Decompressor()
    out = bytearray()
    for i in range(0, len(data), 16384):
        out.extend(dec.decompress(data[i:i + 16384], max_length=max_bytes - len(out)))
        if len(out) >= max_bytes and not dec.eof:
            raise ValueError(f"BZIP2 decompression aborted: exceeded {max_bytes // (1024 * 1024)} MB safety limit.")
    return bytes(out)


def bz2_compress(data: bytes) -> bytes:
    return bz2.compress(data)


def lzma_decompress(data: bytes, max_bytes: int = MAX_DECOMPRESS_BYTES) -> bytes:
    dec = lzma.LZMADecompressor()
    out = bytearray()
    for i in range(0, len(data), 16384):
        out.extend(dec.decompress(data[i:i + 16384], max_length=max_bytes - len(out)))
        if len(out) >= max_bytes and not dec.eof:
            raise ValueError(f"LZMA/XZ decompression aborted: exceeded {max_bytes // (1024 * 1024)} MB safety limit.")
    return bytes(out)


def xz_compress(data: bytes) -> bytes:
    return lzma.compress(data, format=lzma.FORMAT_XZ)


def auto_decompress(data: bytes, max_bytes: int = MAX_DECOMPRESS_BYTES) -> bytes:
    algo, _ = detect_compression(data)
    if algo == "BZIP2":
        return bz2_decompress(data, max_bytes)
    if algo == "XZ":
        return lzma_decompress(data, max_bytes)
    if algo == "ZLIB":
        return zlib_decompress(data, max_bytes)
    return gzip_decompress(data, max_bytes)
