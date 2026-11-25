from __future__ import annotations

import base64
import gzip
import struct
import unittest

from app.compression.engines import (
    auto_decompress,
    bz2_compress,
    detect_compression,
    gzip_decompress,
    http_extract_body,
    xz_compress,
)
from app.core.pipeline import PipelineStepError, TransformationPipeline
from app.encoders.codecs import (
    b58_decode,
    b58_encode,
    b62_decode,
    b62_encode,
    unicode_unescape,
    url_decode,
    url_double_decode,
    url_double_encode,
    xor_bytes,
)
from app.formats.converter import ConversionEngine, FORMATS
from app.pcap.reassembler import parse_capture_flows
from app.protocols.inspector import analyze_payload


class TestWorkbench(unittest.TestCase):
    def test_all_seven_formats_roundtrip(self):
        sample = b"Welcome to Packet Payload Studio!"
        for fmt in ("C Array", "Hex Dump", "YAML", "ASCII", "UTF-8", "EBCDIC", "Raw"):
            encoded = ConversionEngine.from_bytes(sample, fmt)
            decoded = ConversionEngine.to_bytes(encoded, fmt)
            self.assertEqual(decoded, sample, f"Roundtrip failed for {fmt}")

    def test_hexdump_variants_and_c_array_edge_cases(self):
        # xxd format
        xxd_str = "00000000: 4865 6c6c 6f21                           Hello!"
        self.assertEqual(ConversionEngine.to_bytes(xxd_str, "Hex Dump"), b"Hello!")
        # Bare hex starting with "dead" must not be stripped as an offset
        self.assertEqual(ConversionEngine.to_bytes("dead beef", "Hex Dump"), b"\xde\xad\xbe\xef")
        # C array with comments, decimal, negative byte, and char literal
        c_src = "/* 0x99 */ char buf[] = { 0x48, 101, 'l', 'l', -1 }; // 0x88"
        self.assertEqual(ConversionEngine.to_bytes(c_src, "C Array"), b"Hell\xff")
        with self.assertRaises(ValueError):
            ConversionEngine.to_bytes("char bad[] = { 0x1234 };", "C Array")

    def test_base_url_high_bytes_unicode_and_xor(self):
        msg = b"\x00\x01Hello World!@#"
        self.assertEqual(b58_decode(b58_encode(msg)), msg)
        self.assertEqual(b62_decode(b62_encode(msg)), msg)
        self.assertEqual(url_double_encode(b"Hello World!"), b"Hello%2520World%2521")
        self.assertEqual(url_double_decode(b"Hello%2520World%2521"), b"Hello World!")
        # High bytes (0x80..0xFF) must survive URL decode intact
        self.assertEqual(url_decode(b"%ff%fe%80"), b"\xff\xfe\x80")
        self.assertEqual(url_double_decode(b"%25ff%2580"), b"\xff\x80")
        # Non-Latin-1 (CJK) with unicode escape
        self.assertEqual(unicode_unescape("你好 \\u0041".encode("utf-8")), "你好 A".encode("utf-8"))
        # Odd-length hex XOR key raises clear error
        with self.assertRaises(ValueError):
            xor_bytes(b"abc", "0x5")

    def test_http_extract_body_and_pipeline_steps(self):
        raw_json = b'{"status":"ok","count":42}'
        gz = gzip.compress(raw_json)
        chunk = f"{len(gz):x}\r\n".encode("ascii") + gz + b"\r\n0\r\n\r\n"
        http_msg = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk
        self.assertEqual(http_extract_body(http_msg), raw_json)

        pipe = TransformationPipeline()
        pipe.add_step("http_extract_body")
        pipe.add_step("json_beautify")
        out, trace, snaps = pipe.execute(http_msg)
        self.assertIn(b'"count": 42', out)
        self.assertEqual(len(trace), 2)
        self.assertEqual(len(snaps), 2)

        # Recipe serialization roundtrip
        pipe2 = TransformationPipeline()
        pipe2.load_json(pipe.to_json())
        out2, _, _ = pipe2.execute(http_msg)
        self.assertEqual(out2, out)

        # Step error reports exact step index
        bad_pipe = TransformationPipeline()
        bad_pipe.add_step("b64_decode")
        with self.assertRaises(PipelineStepError) as ctx:
            bad_pipe.execute(b"%%%not_base64%%%")
        self.assertIn("Step 01", str(ctx.exception))

    def test_compression_false_positive_and_bomb_limit(self):
        # "x marks the spot" starts with 0x78 0x20 (mod 31 == 0) and must NOT be detected as ZLIB
        algo, conf = detect_compression(b"x marks the spot in plain English")
        self.assertEqual(algo, "None detected")
        self.assertEqual(conf, 0.0)

        self.assertEqual(auto_decompress(bz2_compress(b"bz2-test")), b"bz2-test")
        self.assertEqual(auto_decompress(xz_compress(b"xz-test")), b"xz-test")
        bomb = gzip.compress(b"X" * 50000)
        with self.assertRaises(ValueError):
            gzip_decompress(bomb, max_bytes=1024)

    def test_tcp_out_of_order_and_idempotent_retransmission_reassembly(self):
        eth = b"\x00" * 12 + b"\x08\x00"

        def make_tcp_pkt(seq, payload):
            ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 1, 0, 64, 6, 0, b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
            tcp = struct.pack("!HHIIBBHHH", 50000, 80, seq, 1, 0x50, 0x18, 8192, 0, 0)
            frame = eth + ip + tcp + payload
            return struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame

        pcap_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        pcap = pcap_hdr + make_tcp_pkt(1005, b"WORLD") + make_tcp_pkt(1000, b"HELLO") + make_tcp_pkt(1000, b"HELLO")
        flows = parse_capture_flows(pcap)
        flow = next(iter(flows.values()))
        self.assertEqual(flow.reconstructed_bytes(), b"HELLOWORLD")
        self.assertEqual(flow.retransmissions, 1)
        # Re-selecting the same flow must not inflate retransmissions
        self.assertEqual(flow.reconstructed_bytes(), b"HELLOWORLD")
        self.assertEqual(flow.retransmissions, 1)

    def test_protocol_detector(self):
        info = analyze_payload(b"POST /api/v1/login HTTP/1.1\r\nContent-Encoding: gzip\r\n\r\n")
        self.assertEqual(info["protocol"], "HTTP/1.x Message")
        self.assertIn("HTTP Extract Body", info["suggestions"])



    def test_headless_cli_pcap_and_recipe_pipeline(self):
        import gzip
        import json
        import struct
        import tempfile
        from pathlib import Path
        from app.__main__ import main as cli_main

        body = json.dumps({"status": "ok", "v": 1}).encode("utf-8")
        gz = gzip.compress(body)
        http_payload = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Encoding: gzip\r\n"
            + f"Content-Length: {len(gz)}\r\n\r\n".encode("ascii")
            + gz
        )

        # Build minimal Ethernet + IPv4 + TCP PCAP
        eth = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00"
        tcp_len = 20 + len(http_payload)
        ip_total = 20 + tcp_len
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_total, 1, 0, 64, 6, 0, b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
        tcp = struct.pack("!HHIIBBHHH", 12345, 80, 1000, 1, (5 << 4), 0x18, 65535, 0, 0)
        frame = eth + ip + tcp + http_payload
        pcap_bytes = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            pcap_file = tmp_path / "sample.pcap"
            recipe_file = tmp_path / "recipe.json"
            out_file = tmp_path / "decoded.json"

            pcap_file.write_bytes(pcap_bytes)
            recipe_file.write_text(json.dumps({
                "version": 2,
                "steps": [
                    {"op_id": "http_extract_body", "param": "", "enabled": True},
                    {"op_id": "json_beautify", "param": "", "enabled": True},
                ]
            }), encoding="utf-8")

            rc = cli_main(["--pcap", str(pcap_file), "--recipe", str(recipe_file), "--out", str(out_file)])
            self.assertEqual(rc, 0)
            parsed = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(parsed, {"status": "ok", "v": 1})

if __name__ == "__main__":
    unittest.main()
