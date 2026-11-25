import hashlib
import hmac
import zlib


def compute_all_digests(data: bytes, hmac_key: str = "") -> str:
    lines = [
        f"Length       : {len(data):,} bytes",
        f"CRC32        : {zlib.crc32(data) & 0xFFFFFFFF:08x}",
        f"Adler-32     : {zlib.adler32(data) & 0xFFFFFFFF:08x}",
        f"MD5 (legacy) : {hashlib.md5(data).hexdigest()}",
        f"SHA-1(legacy): {hashlib.sha1(data).hexdigest()}",
        f"SHA-256      : {hashlib.sha256(data).hexdigest()}",
        f"SHA-384      : {hashlib.sha384(data).hexdigest()}",
        f"SHA-512      : {hashlib.sha512(data).hexdigest()}",
        f"SHA3-256     : {hashlib.sha3_256(data).hexdigest()}",
        f"BLAKE2b      : {hashlib.blake2b(data).hexdigest()}",
        f"BLAKE2s      : {hashlib.blake2s(data).hexdigest()}",
    ]
    if hmac_key:
        kb = hmac_key.encode("utf-8")
        lines.append(f"HMAC-SHA256  : {hmac.new(kb, data, hashlib.sha256).hexdigest()}")
        lines.append(f"HMAC-SHA512  : {hmac.new(kb, data, hashlib.sha512).hexdigest()}")
    return "\n".join(lines).encode("utf-8")
