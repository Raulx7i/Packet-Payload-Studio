from __future__ import annotations

import json
import math
import re
from app.compression.engines import detect_compression


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def analyze_payload(data: bytes) -> dict:
    """Identify protocol, compression, encoding, and structural anomalies."""
    if not data:
        return {"protocol": "Empty", "confidence": 0, "entropy": 0.0, "notes": [], "suggestions": []}

    ent = shannon_entropy(data)
    max_possible_ent = math.log2(min(len(data), 256)) if len(data) > 1 else 1.0
    norm_ent = ent / max_possible_ent if max_possible_ent > 0 else 0.0

    comp_algo, comp_conf = detect_compression(data)
    protocol = "Unknown Binary / Custom Protocol"
    confidence = 40
    notes = []
    suggestions = []

    head = data[:512]
    if re.match(rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|HTTP/1\.[01])\b", head):
        protocol = "HTTP/1.x Message"
        confidence = 99
        if re.search(rb"(?i)content-encoding:\s*gzip", head):
            notes.append("HTTP header declares Content-Encoding: gzip")
        if re.search(rb"(?i)transfer-encoding:\s*chunked", head):
            notes.append("HTTP uses Transfer-Encoding: chunked")
        if b"\r\n\r\n" in data:
            suggestions.append("HTTP Extract Body")
    elif len(data) >= 5 and data[0] in (0x14, 0x15, 0x16, 0x17) and data[1:3] in (b"\x03\x01", b"\x03\x02", b"\x03\x03", b"\x03\x04"):
        rec_types = {0x14: "ChangeCipherSpec", 0x15: "Alert", 0x16: "Handshake", 0x17: "ApplicationData"}
        protocol = f"TLS Record ({rec_types[data[0]]})"
        confidence = 96
        notes.append("TLS record header detected (encrypted payload cannot be decrypted without session keys)")
    elif comp_conf >= 0.90:
        protocol = f"{comp_algo} Compressed Stream"
        confidence = int(comp_conf * 100)
        suggestions.append("Auto Decompress")
    elif data.lstrip()[:1] in (b"{", b"["):
        try:
            json.loads(data.decode("utf-8"))
            protocol = "JSON Document"
            confidence = 98
            suggestions.append("JSON Beautify")
        except Exception:
            notes.append("Starts with JSON delimiter but failed strict UTF-8 JSON parse")
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        protocol = "PNG Image"
        confidence = 99
    elif data.startswith(b"%PDF-"):
        protocol = "PDF Document"
        confidence = 99
    elif data.startswith(b"\x7fELF"):
        protocol = "ELF Executable"
        confidence = 99
    elif data.startswith(b"MZ"):
        protocol = "PE/DOS Executable"
        confidence = 90
    elif re.fullmatch(rb"[A-Za-z0-9+/=\r\n]+", data[:256]) and len(data.strip()) >= 16 and len(data.strip()) % 4 == 0:
        protocol = "Likely Base64 Text"
        confidence = 82
        suggestions.append("Base64 Decode")

    if len(data) >= 32 and norm_ent > 0.92:
        notes.append(f"High normalized entropy ({ent:.2f}/8.00, {norm_ent * 100:.0f}% of max)")
    elif len(data) >= 32 and norm_ent < 0.20:
        notes.append(f"Very low entropy ({ent:.2f}/8.00) — repetitive or padded data")

    null_ratio = data.count(0) / len(data)
    if null_ratio > 0.30:
        notes.append(f"High null-byte density ({null_ratio * 100:.1f}% 0x00)")

    return {
        "protocol": protocol,
        "confidence": confidence,
        "entropy": ent,
        "compression": comp_algo,
        "notes": notes,
        "suggestions": suggestions,
    }
