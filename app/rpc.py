"""NDJSON over stdin/stdout IPC server wired directly to Packet Payload Studio."""
from __future__ import annotations

import inspect
import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.pipeline import OPERATIONS
from app.formats.converter import FORMATS, ConversionEngine
from app.pcap.reassembler import parse_capture_flows
from app.protocols.inspector import analyze_payload


def _format_hex_preview(data: bytes, max_bytes: int = 4096) -> str:
    chunk = data[:max_bytes]
    lines = []
    for offset in range(0, len(chunk), 16):
        row = chunk[offset : offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in row)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in row)
        lines.append(f"{offset:08x}  {hex_part:<47}  |{ascii_part}|")
    if len(data) > max_bytes:
        lines.append(f"... ({len(data) - max_bytes} additional bytes truncated in preview)")
    return "\n".join(lines)


def _categorize_operations() -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {
        "HTTP & Compression": [],
        "Base Encodings": [],
        "Web & Escaping": [],
        "Crypto & Digests": [],
    }
    for op_id in OPERATIONS.keys():
        low = op_id.lower()
        if any(k in low for k in ("http", "gzip", "zlib", "deflate", "bzip", "lzma", "xz", "decompress", "compress", "json")):
            cat = "HTTP & Compression"
        elif any(k in low for k in ("base", "hex", "ascii85")):
            cat = "Base Encodings"
        elif any(k in low for k in ("url", "html", "quoted", "unicode")):
            cat = "Web & Escaping"
        else:
            cat = "Crypto & Digests"
        has_param = "param =" in low
        placeholder = "e.g. 0x55 or secret" if "xor" in low else ("Optional HMAC key" if "hmac" in low else "Parameter")
        grouped[cat].append({"id": op_id, "label": op_id, "has_param": has_param, "placeholder": placeholder})
    return [{"id": k.lower().replace(" ", "_"), "label": k, "ops": v} for k, v in grouped.items() if v]


def handle_request(method: str, params: dict[str, Any]) -> Any:
    if method == "ping":
        return {"status": "ok", "python": sys.version.split()[0], "formats": list(FORMATS)}

    if method == "list_capabilities":
        return {"formats": list(FORMATS), "categories": _categorize_operations()}

    if method == "auto_detect_format":
        text = params.get("input_text", "")
        return {"detected_format": ConversionEngine.auto_detect(text)}

    if method == "convert_and_transform":
        raw_text = params.get("input_text", "")
        file_path = params.get("file_path")
        in_format = params.get("in_format", "UTF-8")
        out_format = params.get("out_format", "UTF-8")
        peer = params.get("peer") or "All Streams"
        steps = params.get("steps", [])

        if file_path:
            file_bytes = Path(file_path).read_bytes()
            if in_format.strip().lower() == "raw":
                raw_bytes = file_bytes
            else:
                raw_bytes = ConversionEngine.to_bytes(
                    file_bytes.decode("utf-8", errors="replace"), in_format, peer_filter=peer
                )
        else:
            raw_bytes = ConversionEngine.to_bytes(raw_text, in_format, peer_filter=peer)

        cur = raw_bytes
        trace: list[dict[str, Any]] = []
        for idx, step in enumerate(steps):
            if not step.get("enabled", True):
                continue
            op_id = str(step.get("op_id", "")).strip()
            param = str(step.get("param", ""))
            if not op_id:
                continue
            fn = OPERATIONS.get(op_id)
            if not callable(fn):
                raise ValueError(f"Unsupported operation: {op_id}")
            sig = inspect.signature(fn)
            cur = fn(cur, param) if len(sig.parameters) >= 2 else fn(cur)
            trace.append({
                "index": idx,
                "op_id": op_id,
                "byte_length": len(cur),
                "preview_utf8": cur[:1024].decode("utf-8", errors="replace"),
                "preview_hex": " ".join(f"{b:02x}" for b in cur[:64]),
            })

        output_text = ConversionEngine.from_bytes(cur, out_format)
        return {
            "output_text": output_text,
            "input_bytes": len(raw_bytes),
            "output_bytes": len(cur),
            "trace": trace,
        }

    if method == "analyze_payload":
        raw_text = params.get("input_text", "")
        in_format = params.get("in_format", "UTF-8")
        peer = params.get("peer") or "All Streams"
        data = ConversionEngine.to_bytes(raw_text, in_format, peer_filter=peer)
        info = analyze_payload(data)
        return {
            "byte_length": info.get("size", len(data)),
            "entropy": round(float(info.get("entropy", 0.0)), 4),
            "printable_ratio": round(float(info.get("printable_pct", info.get("printable_ratio", 0.0))), 2),
            "detected_protocol": str(info.get("protocol", info.get("detected_protocol", "Unknown"))),
            "hashes": {
                "md5": info.get("md5", ""),
                "sha1": info.get("sha1", ""),
                "sha256": info.get("sha256", ""),
            },
            "details": info,
            "hex_preview": _format_hex_preview(data, max_bytes=4096),
            "ascii_preview": "".join(chr(b) if 32 <= b <= 126 or b in (9, 10, 13) else "." for b in data[:4096]),
        }

    if method == "list_pcap_streams":
        pcap_path = params.get("pcap_path", "")
        if not pcap_path or not os.path.isfile(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        flows = parse_capture_flows(Path(pcap_path).read_bytes())
        streams = []
        for idx, (key, flow) in enumerate(flows.items()):
            payload = getattr(flow, "payload", b"")
            pkts = getattr(flow, "packets", getattr(flow, "packet_count", 0))
            retrans = getattr(flow, "retransmissions", getattr(flow, "retrans", 0))
            streams.append({
                "index": idx,
                "key": str(key),
                "summary": f"{key} | packets={pkts} | retrans={retrans} | bytes={len(payload)}",
                "byte_length": len(payload),
            })
        return {"pcap_path": pcap_path, "streams": streams}

    if method == "extract_pcap_stream":
        pcap_path = params.get("pcap_path", "")
        stream_key = params.get("stream_key")
        stream_index = int(params.get("stream_index", 0))
        out_format = params.get("out_format", "UTF-8")
        if not pcap_path or not os.path.isfile(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        flows = parse_capture_flows(Path(pcap_path).read_bytes())
        items = list(flows.items())
        if not items:
            raise ValueError("No streams found in PCAP file")
        if stream_key and stream_key in flows:
            flow = flows[stream_key]
        else:
            _, flow = items[min(stream_index, len(items) - 1)]
        payload = getattr(flow, "payload", b"")
        return {
            "payload_text": ConversionEngine.from_bytes(payload, out_format),
            "byte_length": len(payload),
        }

    if method == "compare_payloads":
        left_text = params.get("left_text", "")
        right_text = params.get("right_text", "")
        left_fmt = params.get("left_format", "UTF-8")
        right_fmt = params.get("right_format", "UTF-8")
        left_peer = params.get("left_peer") or "All Streams"
        right_peer = params.get("right_peer") or "All Streams"

        left_bytes = ConversionEngine.to_bytes(left_text, left_fmt, peer_filter=left_peer)
        right_bytes = ConversionEngine.to_bytes(right_text, right_fmt, peer_filter=right_peer)

        max_len = max(len(left_bytes), len(right_bytes))
        min_len = min(len(left_bytes), len(right_bytes))
        differing_offsets = [i for i in range(min_len) if left_bytes[i] != right_bytes[i]]
        differing_offsets.extend(range(min_len, max_len))

        rows = []
        preview_limit = min(max_len, 4096)
        for offset in range(0, preview_limit, 16):
            l_chunk = left_bytes[offset : offset + 16]
            r_chunk = right_bytes[offset : offset + 16]
            row_diff = [i for i in range(16) if (l_chunk[i] if i < len(l_chunk) else None) != (r_chunk[i] if i < len(r_chunk) else None)]
            rows.append({
                "offset": f"{offset:08x}",
                "left_hex": [f"{b:02x}" for b in l_chunk],
                "right_hex": [f"{b:02x}" for b in r_chunk],
                "left_ascii": "".join(chr(b) if 32 <= b <= 126 else "." for b in l_chunk),
                "right_ascii": "".join(chr(b) if 32 <= b <= 126 else "." for b in r_chunk),
                "diff_cols": row_diff,
            })

        similarity = round(((max_len - len(differing_offsets)) / max_len) * 100.0, 2) if max_len else 100.0
        return {
            "left_bytes": len(left_bytes),
            "right_bytes": len(right_bytes),
            "diff_count": len(differing_offsets),
            "similarity_pct": similarity,
            "rows": rows,
            "truncated": max_len > preview_limit,
        }

    if method == "list_example_recipes":
        ex_dir = ROOT / "examples"
        recipes = []
        if ex_dir.is_dir():
            for p in sorted(ex_dir.glob("*.json")):
                try:
                    recipes.append({"name": p.stem, "filename": p.name, "content": json.loads(p.read_text(encoding="utf-8"))})
                except Exception:
                    pass
        return {"recipes": recipes}

    raise ValueError(f"Unknown RPC method: {method}")


def main() -> None:
    for line in sys.stdin:
        raw = line.strip()
        if not raw:
            continue
        req_id = None
        try:
            req = json.loads(raw)
            req_id = req.get("id")
            method = req.get("method", "")
            params = req.get("params") or {}
            result = handle_request(method, params)
            resp = {"id": req_id, "result": result, "error": None}
        except Exception as exc:
            resp = {
                "id": req_id,
                "result": None,
                "error": {
                    "code": type(exc).__name__,
                    "message": str(exc),
                    "traceback": traceback.format_exc(limit=3),
                },
            }
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
