from __future__ import annotations

import bz2
import gzip
import lzma
import math
import re
import zlib

MAX_DECOMPRESS_BYTES = 10 * 1024 * 1024  # 10 MB safety ceiling against decompression bombs


def _quick_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def detect_compression(data: bytes) -> tuple[str, float]:
    """Return (algorithm_name, confidence_0_to_1) from magic headers."""
    if len(data) >= 3 and data[:3] == b"\x1f\x8b\x08":
        return ("GZIP", 0.99)
    if len(data) >= 4 and data[:3] == b"BZh" and data[3:4] in b"123456789":
        return ("BZIP2", 0.98)
    if len(data) >= 6 and data[:6] == b"\xfd7zXZ\x00":
        return ("XZ", 0.99)
    # Valid zlib CMF + FLG mod 31 == 0, FDICT clear, verified via trial decompression
    if (
        len(data) >= 6
        and data[0] in (0x08, 0x18, 0x28, 0x38, 0x48, 0x58, 0x68, 0x78)
        and ((data[0] << 8) + data[1]) % 31 == 0
        and not (data[1] & 0x20)
    ):
        try:
            dobj = zlib.decompressobj()
            dobj.decompress(data[:128], 1024)
            return ("ZLIB", 0.92)
        except zlib.error:
            pass
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
    """Bounded decompression with multi-member GZIP support and truncated-stream recovery."""
    out = bytearray()
    remaining_payload = memoryview(payload)

    while len(remaining_payload) > 0:
        dobj = zlib.decompressobj(wbits)
        member_out = bytearray()
        for i in range(0, len(remaining_payload), 16384):
            rem = max_bytes - (len(out) + len(member_out))
            if rem <= 0:
                raise ValueError(f"Decompression aborted: exceeded {max_bytes // (1024 * 1024)} MB safety limit.")
            try:
                member_out.extend(dobj.decompress(remaining_payload[i:i + 16384], rem))
            except zlib.error as exc:
                if out or member_out:
                    out.extend(member_out)
                    return bytes(out)
                if wbits == 16 + zlib.MAX_WBITS and len(remaining_payload) > 18 and "incorrect data check" in str(exc):
                    return _bounded_zlib(bytes(remaining_payload[10:-8]), -zlib.MAX_WBITS, max_bytes)
                raise ValueError(f"Corrupt Zlib/Gzip/Deflate stream: {exc}") from exc
            if dobj.unconsumed_tail and (len(out) + len(member_out)) >= max_bytes:
                raise ValueError(f"Decompression aborted: exceeded {max_bytes // (1024 * 1024)} MB safety limit.")
            if dobj.eof:
                break

        try:
            rem = max_bytes - (len(out) + len(member_out))
            if rem > 0:
                member_out.extend(dobj.flush(rem))
        except zlib.error:
            pass

        out.extend(member_out)
        if wbits == 16 + zlib.MAX_WBITS and dobj.eof and len(dobj.unused_data) >= 3 and dobj.unused_data[:2] == b"\x1f\x8b":
            remaining_payload = memoryview(dobj.unused_data)
        else:
            break

    return bytes(out)


def http_extract_body(data: bytes, max_bytes: int = MAX_DECOMPRESS_BYTES) -> bytes:
    """Strip HTTP/1.x headers, respect Content-Length / chunked framing, and decompress gzip/deflate."""
    sep = data.find(b"\r\n\r\n")
    if sep == -1:
        raise ValueError("No HTTP header/body separator (\\r\\n\\r\\n) found.")
    headers, body = data[:sep], data[sep + 4:]
    if re.search(rb"(?i)^transfer-encoding:\s*chunked\b", headers, re.M):
        body = decode_http_chunked(body)
    else:
        cl_match = re.search(rb"(?i)^content-length:\s*(\d+)\b", headers, re.M)
        if cl_match:
            body = body[:int(cl_match.group(1))]

    ce_match = re.search(rb"(?i)^content-encoding:\s*([^\r\n]+)", headers, re.M)
    encoding = ce_match.group(1).strip().lower() if ce_match else b""
    if b"br" in encoding:
        raise ValueError("HTTP body uses Brotli (Content-Encoding: br), which requires an external library.")
    if b"zstd" in encoding:
        raise ValueError("HTTP body uses Zstandard (Content-Encoding: zstd), which requires an external library.")
    if body.startswith(b"\x1f\x8b") or b"gzip" in encoding:
        return _bounded_zlib(body, 16 + zlib.MAX_WBITS, max_bytes)
    if b"deflate" in encoding:
        try:
            return _bounded_zlib(body, zlib.MAX_WBITS, max_bytes)
        except ValueError:
            return _bounded_zlib(body, -zlib.MAX_WBITS, max_bytes)
    return body


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
    out = bytearray()
    remaining = memoryview(data)
    while len(remaining) > 0:
        dec = bz2.BZ2Decompressor()
        for i in range(0, len(remaining), 16384):
            rem = max_bytes - len(out)
            if rem <= 0:
                raise ValueError(f"BZIP2 decompression aborted: exceeded {max_bytes // (1024 * 1024)} MB safety limit.")
            out.extend(dec.decompress(remaining[i:i + 16384], max_length=rem))
            if len(out) >= max_bytes and not dec.eof:
                raise ValueError(f"BZIP2 decompression aborted: exceeded {max_bytes // (1024 * 1024)} MB safety limit.")
            if dec.eof:
                break
        if not dec.eof:
            raise ValueError("Truncated or incomplete BZIP2 stream (missing end-of-stream marker).")
        if dec.unused_data and dec.unused_data.startswith(b"BZh"):
            remaining = memoryview(dec.unused_data)
        else:
            break
    return bytes(out)


def bz2_compress(data: bytes) -> bytes:
    return bz2.compress(data)


def lzma_decompress(data: bytes, max_bytes: int = MAX_DECOMPRESS_BYTES) -> bytes:
    out = bytearray()
    remaining = memoryview(data)
    while len(remaining) > 0:
        dec = lzma.LZMADecompressor()
        for i in range(0, len(remaining), 16384):
            rem = max_bytes - len(out)
            if rem <= 0:
                raise ValueError(f"LZMA/XZ decompression aborted: exceeded {max_bytes // (1024 * 1024)} MB safety limit.")
            out.extend(dec.decompress(remaining[i:i + 16384], max_length=rem))
            if len(out) >= max_bytes and not dec.eof:
                raise ValueError(f"LZMA/XZ decompression aborted: exceeded {max_bytes // (1024 * 1024)} MB safety limit.")
            if dec.eof:
                break
        if not dec.eof:
            raise ValueError("Truncated or incomplete LZMA/XZ stream.")
        if dec.unused_data and dec.unused_data.startswith(b"\xfd7zXZ\x00"):
            remaining = memoryview(dec.unused_data)
        else:
            break
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
