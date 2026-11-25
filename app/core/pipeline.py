from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Callable

from app.compression.engines import (
    auto_decompress,
    bz2_compress,
    bz2_decompress,
    deflate_decompress,
    gzip_compress,
    gzip_decompress,
    http_extract_body,
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

# Stable operation ID -> (Display Name, Category, Function)
OP_REGISTRY: dict[str, tuple[str, str, Callable[[bytes, str], bytes]]] = {
    "http_extract_body": ("HTTP Extract Body (Dechunk + Decompress)", "Web", lambda d, p: http_extract_body(d)),
    "auto_decompress": ("Auto Decompress (Gzip/Zlib/BZ2/XZ)", "Compression", lambda d, p: auto_decompress(d)),
    "gzip_decompress": ("GZIP Decompress", "Compression", lambda d, p: gzip_decompress(d)),
    "gzip_compress": ("GZIP Compress", "Compression", lambda d, p: gzip_compress(d)),
    "zlib_decompress": ("ZLIB Decompress", "Compression", lambda d, p: zlib_decompress(d)),
    "zlib_compress": ("ZLIB Compress", "Compression", lambda d, p: zlib_compress(d)),
    "deflate_decompress": ("Raw DEFLATE Decompress", "Compression", lambda d, p: deflate_decompress(d)),
    "bz2_decompress": ("BZIP2 Decompress", "Compression", lambda d, p: bz2_decompress(d)),
    "bz2_compress": ("BZIP2 Compress", "Compression", lambda d, p: bz2_compress(d)),
    "lzma_decompress": ("LZMA / XZ Decompress", "Compression", lambda d, p: lzma_decompress(d)),
    "xz_compress": ("XZ Compress", "Compression", lambda d, p: xz_compress(d)),
    "b64_decode": ("Base64 Decode", "Encoding", lambda d, p: b64_decode(d)),
    "b64_encode": ("Base64 Encode", "Encoding", lambda d, p: b64_encode(d)),
    "b64url_decode": ("Base64 URL-Safe Decode", "Encoding", lambda d, p: b64url_decode(d)),
    "b64url_encode": ("Base64 URL-Safe Encode", "Encoding", lambda d, p: b64url_encode(d)),
    "b16_decode": ("Base16 (Hex) Decode", "Encoding", lambda d, p: b16_decode(d)),
    "b16_encode": ("Base16 (Hex) Encode", "Encoding", lambda d, p: b16_encode(d)),
    "b32_decode": ("Base32 Decode", "Encoding", lambda d, p: b32_decode(d)),
    "b32_encode": ("Base32 Encode", "Encoding", lambda d, p: b32_encode(d)),
    "b58_decode": ("Base58 Decode", "Encoding", lambda d, p: b58_decode(d)),
    "b58_encode": ("Base58 Encode", "Encoding", lambda d, p: b58_encode(d)),
    "b62_decode": ("Base62 Decode", "Encoding", lambda d, p: b62_decode(d)),
    "b62_encode": ("Base62 Encode", "Encoding", lambda d, p: b62_encode(d)),
    "a85_decode": ("ASCII85 (Base85) Decode", "Encoding", lambda d, p: a85_decode(d)),
    "a85_encode": ("ASCII85 (Base85) Encode", "Encoding", lambda d, p: a85_encode(d)),
    "url_decode": ("URL Decode", "Web", lambda d, p: url_decode(d)),
    "url_encode": ("URL Encode", "Web", lambda d, p: url_encode(d)),
    "url_double_decode": ("Double URL Decode", "Web", lambda d, p: url_double_decode(d)),
    "url_double_encode": ("Double URL Encode", "Web", lambda d, p: url_double_encode(d)),
    "html_decode": ("HTML Entity Decode", "Web", lambda d, p: html_decode(d)),
    "html_encode": ("HTML Entity Encode", "Web", lambda d, p: html_encode(d)),
    "qp_decode": ("Quoted-Printable Decode", "Web", lambda d, p: qp_decode(d)),
    "qp_encode": ("Quoted-Printable Encode", "Web", lambda d, p: qp_encode(d)),
    "unicode_unescape": ("Unicode Escape Decode", "Web", lambda d, p: unicode_unescape(d)),
    "json_beautify": ("JSON Beautify", "Structured", lambda d, p: json_beautify(d)),
    "xor": ("XOR (Param = Key)", "Cipher / Misc", lambda d, p: xor_bytes(d, p or "0x55")),
    "rot13": ("ROT13", "Cipher / Misc", lambda d, p: rot13(d)),
    "hash_report": ("Hash & Checksum Report (Param = HMAC Key)", "Crypto / Hash", lambda d, p: compute_all_digests(d, p)),
}

# Backwards-compatible mapping from display name -> op_id
OPERATIONS: dict[str, tuple[str, Callable[[bytes, str], bytes]]] = {
    disp: (cat, fn) for _op_id, (disp, cat, fn) in OP_REGISTRY.items()
}
DISPLAY_TO_ID: dict[str, str] = {disp: op_id for op_id, (disp, _cat, _fn) in OP_REGISTRY.items()}


class PipelineStepError(Exception):
    def __init__(self, step_num: int, op_name: str, message: str):
        self.step_num = step_num
        self.op_name = op_name
        super().__init__(f"Step {step_num:02d} ({op_name}) failed: {message}")


@dataclass
class RecipeStep:
    op_id: str
    param: str = ""
    enabled: bool = True

    @property
    def op_name(self) -> str:
        return OP_REGISTRY[self.op_id][0] if self.op_id in OP_REGISTRY else self.op_id


class TransformationPipeline:
    RECIPE_VERSION = 2

    def __init__(self):
        self.steps: list[RecipeStep] = []

    def add_step(self, op_identifier: str, param: str = ""):
        op_id = op_identifier if op_identifier in OP_REGISTRY else DISPLAY_TO_ID.get(op_identifier)
        if not op_id:
            raise ValueError(f"Unknown operation: {op_identifier}")
        self.steps.append(RecipeStep(op_id=op_id, param=param, enabled=True))

    def execute(self, initial_bytes: bytes) -> tuple[bytes, list[str], list[bytes]]:
        data = initial_bytes
        trace: list[str] = []
        snapshots: list[bytes] = []
        for idx, step in enumerate(self.steps, start=1):
            if not step.enabled:
                trace.append(f"{idx:02d}. [OFF] {step.op_name}")
                snapshots.append(data)
                continue
            disp, _cat, fn = OP_REGISTRY[step.op_id]
            before_len = len(data)
            try:
                data = fn(data, step.param)
            except Exception as exc:
                raise PipelineStepError(idx, disp, str(exc)) from exc
            trace.append(f"{idx:02d}. {disp} ({before_len:,} B -> {len(data):,} B)")
            snapshots.append(data)
        return data, trace, snapshots

    def to_json(self) -> str:
        return json.dumps(
            {
                "version": self.RECIPE_VERSION,
                "steps": [asdict(s) for s in self.steps],
            },
            indent=2,
        )

    def load_json(self, raw_json: str):
        parsed = json.loads(raw_json)
        items = parsed["steps"] if isinstance(parsed, dict) and "steps" in parsed else parsed
        if not isinstance(items, list):
            raise ValueError("Invalid recipe JSON structure.")
        loaded: list[RecipeStep] = []
        for idx, item in enumerate(items, start=1):
            if not isinstance(item, dict):
                raise ValueError(f"Invalid recipe step #{idx}: expected object, got {type(item).__name__}.")
            raw_id = item.get("op_id") or item.get("op_name", "")
            op_id = raw_id if raw_id in OP_REGISTRY else DISPLAY_TO_ID.get(raw_id)
            if not op_id:
                raise ValueError(f"Unknown recipe operation at step #{idx}: {raw_id!r}")
            loaded.append(RecipeStep(op_id=op_id, param=str(item.get("param", "")), enabled=bool(item.get("enabled", True))))
        self.steps = loaded
