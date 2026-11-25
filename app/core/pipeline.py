import json
from dataclasses import asdict, dataclass
from typing import Callable

from app.compression.engines import (
    auto_decompress,
    bz2_compress,
    bz2_decompress,
    deflate_decompress,
    gzip_compress,
    gzip_decompress,
    lzma_decompress,
    xz_compress,
    zlib_compress,
    zlib_decompress,
)
from app.crypto.digests import compute_all_digests
from app.encoders.codecs import (
    a85_decode,
    a85_encode,
    b16_decode,
    b16_encode,
    b32_decode,
    b32_encode,
    b58_decode,
    b58_encode,
    b62_decode,
    b62_encode,
    b64_decode,
    b64_encode,
    b64url_decode,
    b64url_encode,
    html_decode,
    html_encode,
    json_beautify,
    qp_decode,
    qp_encode,
    rot13,
    unicode_unescape,
    url_decode,
    url_double_decode,
    url_double_encode,
    url_encode,
    xor_bytes,
)

OPERATIONS: dict[str, tuple[str, Callable]] = {
    "Auto Decompress (Gzip/Zlib/BZ2/XZ)": ("Compression", lambda d, p: auto_decompress(d)),
    "GZIP Decompress": ("Compression", lambda d, p: gzip_decompress(d)),
    "GZIP Compress": ("Compression", lambda d, p: gzip_compress(d)),
    "ZLIB Decompress": ("Compression", lambda d, p: zlib_decompress(d)),
    "ZLIB Compress": ("Compression", lambda d, p: zlib_compress(d)),
    "Raw DEFLATE Decompress": ("Compression", lambda d, p: deflate_decompress(d)),
    "BZIP2 Decompress": ("Compression", lambda d, p: bz2_decompress(d)),
    "BZIP2 Compress": ("Compression", lambda d, p: bz2_compress(d)),
    "LZMA / XZ Decompress": ("Compression", lambda d, p: lzma_decompress(d)),
    "XZ Compress": ("Compression", lambda d, p: xz_compress(d)),
    "Base64 Decode": ("Encoding", lambda d, p: b64_decode(d)),
    "Base64 Encode": ("Encoding", lambda d, p: b64_encode(d)),
    "Base64 URL-Safe Decode": ("Encoding", lambda d, p: b64url_decode(d)),
    "Base64 URL-Safe Encode": ("Encoding", lambda d, p: b64url_encode(d)),
    "Base16 (Hex) Decode": ("Encoding", lambda d, p: b16_decode(d)),
    "Base16 (Hex) Encode": ("Encoding", lambda d, p: b16_encode(d)),
    "Base32 Decode": ("Encoding", lambda d, p: b32_decode(d)),
    "Base32 Encode": ("Encoding", lambda d, p: b32_encode(d)),
    "Base58 Decode": ("Encoding", lambda d, p: b58_decode(d)),
    "Base58 Encode": ("Encoding", lambda d, p: b58_encode(d)),
    "Base62 Decode": ("Encoding", lambda d, p: b62_decode(d)),
    "Base62 Encode": ("Encoding", lambda d, p: b62_encode(d)),
    "ASCII85 (Base85) Decode": ("Encoding", lambda d, p: a85_decode(d)),
    "ASCII85 (Base85) Encode": ("Encoding", lambda d, p: a85_encode(d)),
    "URL Decode": ("Web", lambda d, p: url_decode(d)),
    "URL Encode": ("Web", lambda d, p: url_encode(d)),
    "Double URL Decode": ("Web", lambda d, p: url_double_decode(d)),
    "Double URL Encode": ("Web", lambda d, p: url_double_encode(d)),
    "HTML Entity Decode": ("Web", lambda d, p: html_decode(d)),
    "HTML Entity Encode": ("Web", lambda d, p: html_encode(d)),
    "Quoted-Printable Decode": ("Web", lambda d, p: qp_decode(d)),
    "Quoted-Printable Encode": ("Web", lambda d, p: qp_encode(d)),
    "Unicode Escape Decode": ("Web", lambda d, p: unicode_unescape(d)),
    "JSON Beautify": ("Structured", lambda d, p: json_beautify(d)),
    "XOR (Param = Key)": ("Cipher / Misc", lambda d, p: xor_bytes(d, p or "0x55")),
    "ROT13": ("Cipher / Misc", lambda d, p: rot13(d)),
    "Hash & Checksum Report (Param = HMAC Key)": ("Crypto / Hash", lambda d, p: compute_all_digests(d, p)),
}


@dataclass
class RecipeStep:
    op_name: str
    param: str = ""
    enabled: bool = True


class TransformationPipeline:
    def __init__(self):
        self.steps: list[RecipeStep] = []

    def add_step(self, op_name: str, param: str = ""):
        if op_name not in OPERATIONS:
            raise ValueError(f"Unknown operation: {op_name}")
        self.steps.append(RecipeStep(op_name=op_name, param=param, enabled=True))

    def execute(self, initial_bytes: bytes) -> tuple[bytes, list[str]]:
        data = initial_bytes
        trace = []
        for idx, step in enumerate(self.steps, start=1):
            if not step.enabled:
                trace.append(f"{idx:02d}. [SKIPPED] {step.op_name}")
                continue
            _cat, fn = OPERATIONS[step.op_name]
            before_len = len(data)
            data = fn(data, step.param)
            trace.append(f"{idx:02d}. {step.op_name} ({before_len:,} B -> {len(data):,} B)")
        return data, trace

    def to_json(self) -> str:
        return json.dumps([asdict(s) for s in self.steps], indent=2)

    def load_json(self, raw_json: str):
        items = json.loads(raw_json)
        self.steps = [
            RecipeStep(op_name=i["op_name"], param=i.get("param", ""), enabled=i.get("enabled", True))
            for i in items
            if i.get("op_name") in OPERATIONS
        ]
