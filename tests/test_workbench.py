import base64
import gzip
import struct
import unittest

from app.compression.engines import auto_decompress, bz2_compress, gzip_decompress, xz_compress
from app.core.pipeline import TransformationPipeline
from app.encoders.codecs import b58_decode, b58_encode, b62_decode, b62_encode, url_double_decode, url_double_encode
from app.pcap.reassembler import parse_capture_flows
from app.protocols.inspector import analyze_payload


class TestWorkbench(unittest.TestCase):
    def test_base_and_double_url_roundtrip(self):
        msg = b"\x00\x01Hello World!@#"
        self.assertEqual(b58_decode(b58_encode(msg)), msg)
        self.assertEqual(b62_decode(b62_encode(msg)), msg)
        self.assertEqual(url_double_encode(b"Hello World!"), b"Hello%2520World%2521")
        self.assertEqual(url_double_decode(b"Hello%2520World%2521"), b"Hello World!")

    def test_cyberchef_pipeline_chain(self):
        raw_json = b'{"status":"ok","count":42}'
        encoded = base64.b64encode(gzip.compress(raw_json))
        pipe = TransformationPipeline()
        pipe.add_step("Base64 Decode")
        pipe.add_step("GZIP Decompress")
        pipe.add_step("JSON Beautify")
        out, trace = pipe.execute(encoded)
        self.assertIn(b'"count": 42', out)
        self.assertEqual(len(trace), 3)

    def test_compression_auto_and_bomb_limit(self):
        self.assertEqual(auto_decompress(bz2_compress(b"bz2-test")), b"bz2-test")
        self.assertEqual(auto_decompress(xz_compress(b"xz-test")), b"xz-test")
        bomb = gzip.compress(b"X" * 50000)
        with self.assertRaises(ValueError):
            gzip_decompress(bomb, max_bytes=1024)

    def test_tcp_out_of_order_and_retransmission_reassembly(self):
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

    def test_protocol_detector(self):
        info = analyze_payload(b"POST /api/v1/login HTTP/1.1\r\nContent-Encoding: gzip\r\n\r\n")
        self.assertEqual(info["protocol"], "HTTP/1.x Message")


if __name__ == "__main__":
    unittest.main()
