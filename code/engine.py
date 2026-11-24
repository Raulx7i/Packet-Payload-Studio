import base64
import gzip
import hashlib
import math
import re
import struct
import urllib.parse
import zlib

FORMATS = ["C Array", "Hex Dump", "YAML", "ASCII", "UTF-8", "EBCDIC", "Raw"]


class ConversionEngine:
    """Hub-and-spoke packet engine: Any Format -> canonical bytes -> Any Format."""

    @staticmethod
    def auto_detect(text: str) -> str:
        sample = text.strip()
        if not sample:
            return "ASCII"
        if re.search(r"0x[0-9a-fA-F]{2}", sample) and ("{" in sample or "," in sample):
            return "C Array"
        if re.match(r"^[0-9a-fA-F]{4,8}\s+([0-9a-fA-F]{2}\s+){2,}", sample):
            return "Hex Dump"
        if sample.startswith("---") or re.search(r"^(packets|data|payload|stream):", sample, re.M):
            return "YAML"
        return "UTF-8"

    @staticmethod
    def filter_c_array_stream(text: str, peer_filter: str) -> str:
        """Filter Wireshark C Array declarations by peer0 (Client) or peer1 (Server)."""
        if peer_filter == "All Streams":
            return text
        blocks = re.findall(r"(char\s+([a-zA-Z0-9_]+)\[\]\s*=\s*\{[\s\S]*?\};)", text)
        if not blocks:
            return text
        prefix = "peer0" if peer_filter == "Client (peer0)" else "peer1"
        matched = [full for full, name in blocks if name.startswith(prefix)]
        return "\n\n".join(matched) if matched else ""

    @staticmethod
    def to_bytes(text: str, fmt: str, ebcdic_cp: str = "cp037", peer_filter: str = "All Streams") -> bytes:
        if fmt == "C Array":
            filtered = ConversionEngine.filter_c_array_stream(text, peer_filter)
            if not filtered.strip():
                return b""
            hex_tokens = re.findall(r"0x([0-9a-fA-F]{2})", filtered)
            if not hex_tokens:
                raise ValueError("No hex bytes (e.g., 0x48) found in C Array input.")
            return bytes(int(h, 16) for h in hex_tokens)

        elif fmt == "Hex Dump":
            out = bytearray()
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                line = re.sub(r"^[0-9a-fA-F]{4,8}:?\s+", "", line)
                hex_part = re.split(r"\s{2,}|\t|\|", line)[0]
                tokens = re.findall(r"\b[0-9a-fA-F]{2}\b", hex_part)
                out.extend(int(t, 16) for t in tokens)
            if not out:
                raise ValueError("No valid hex dump bytes found.")
            return bytes(out)

        elif fmt == "YAML":
            b64_matches = re.findall(r"(?:data|payload|base64):\s*([A-Za-z0-9+/=]+)", text)
            if b64_matches:
                return b"".join(base64.b64decode(m) for m in b64_matches)
            hex_matches = re.findall(r"(?:hex|bytes):\s*([0-9a-fA-F\s]+)", text)
            if hex_matches:
                cleaned = re.sub(r"\s+", "", "".join(hex_matches))
                return bytes.fromhex(cleaned)
            str_match = re.search(r"(?:text|ascii|utf8):\s*\|?\s*\n?([\s\S]+)", text)
            if str_match:
                return str_match.group(1).encode("utf-8")
            return text.encode("utf-8")

        elif fmt == "ASCII":
            return text.encode("ascii", errors="replace")
        elif fmt == "UTF-8":
            return text.encode("utf-8")
        elif fmt == "EBCDIC":
            return text.encode(ebcdic_cp, errors="replace")
        elif fmt == "Raw":
            return text.encode("latin-1", errors="replace")

        raise ValueError(f"Unsupported input format: {fmt}")

    @staticmethod
    def from_bytes(data: bytes, fmt: str, ebcdic_cp: str = "cp037", ascii_dots: bool = False) -> str:
        if fmt == "C Array":
            if not data:
                return "char stream_data[] = {};"
            lines = ["char stream_data[] = {"]
            for i in range(0, len(data), 8):
                chunk = ", ".join(f"0x{b:02x}" for b in data[i:i + 8])
                comma = "," if i + 8 < len(data) else ""
                lines.append(f"    {chunk}{comma}")
            lines.append("};")
            return "\n".join(lines)

        elif fmt == "Hex Dump":
            if not data:
                return ""
            lines = []
            for offset in range(0, len(data), 16):
                chunk = data[offset:offset + 16]
                hex_left = " ".join(f"{b:02x}" for b in chunk[:8])
                hex_right = " ".join(f"{b:02x}" for b in chunk[8:])
                hex_col = f"{hex_left:<23}  {hex_right:<23}"
                ascii_col = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                lines.append(f"{offset:04x}   {hex_col}   {ascii_col}")
            return "\n".join(lines)

        elif fmt == "YAML":
            b64_str = base64.b64encode(data).decode("ascii")
            hex_str = data.hex()
            preview = data.decode("utf-8", errors="replace").replace("\n", "\\n").replace("\r", "\\r")
            if len(preview) > 120:
                preview = preview[:117] + "..."
            return (
                "---\n"
                f"byte_length: {len(data)}\n"
                f"sha256: {hashlib.sha256(data).hexdigest()}\n"
                f"preview: \"{preview}\"\n"
                f"hex: {hex_str}\n"
                f"data: {b64_str}\n"
            )

        elif fmt == "ASCII":
            if ascii_dots:
                return "".join(chr(b) if (32 <= b <= 126 or b in (9, 10, 13)) else "." for b in data)
            return data.decode("ascii", errors="replace")
        elif fmt == "UTF-8":
            return data.decode("utf-8", errors="replace")
        elif fmt == "EBCDIC":
            return data.decode(ebcdic_cp, errors="replace")
        elif fmt == "Raw":
            return data.decode("latin-1")

        raise ValueError(f"Unsupported output format: {fmt}")

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        length = len(data)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    @staticmethod
    def try_gunzip(data: bytes) -> bytes:
        if data.startswith(b"\x1f\x8b"):
            return gzip.decompress(data)
        sep = data.find(b"\r\n\r\n")
        if sep != -1:
            headers, body = data[:sep], data[sep + 4:]
            if body.startswith(b"\x1f\x8b"):
                return headers + b"\r\n\r\n" + gzip.decompress(body)
        try:
            return zlib.decompress(data)
        except zlib.error:
            pass
        raise ValueError("No Gzip (1f 8b) or Zlib stream detected in payload.")

    @staticmethod
    def transform_bytes(data: bytes, action: str, xor_key: str = "0x00") -> bytes:
        if action == "b64_decode":
            return base64.b64decode(re.sub(rb"\s+", b"", data))
        elif action == "b64_encode":
            return base64.b64encode(data)
        elif action == "url_decode":
            return urllib.parse.unquote_to_bytes(data.decode("latin-1"))
        elif action == "url_encode":
            return urllib.parse.quote_from_bytes(data).encode("ascii")
        elif action == "xor":
            key_str = xor_key.strip()
            key_bytes = bytes.fromhex(key_str[2:]) if key_str.startswith(("0x", "0X")) else key_str.encode("utf-8")
            if not key_bytes:
                raise ValueError("Enter a valid XOR key (e.g., 0x55 or secret).")
            return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
        raise ValueError(f"Unknown transform: {action}")

    @staticmethod
    def extract_pcap_payloads(raw_pcap: bytes) -> bytes:
        """Pure-Python Ethernet/IPv4/TCP & UDP payload extractor for classic .pcap files."""
        if len(raw_pcap) < 24:
            raise ValueError("File too small to be a valid PCAP.")
        magic = struct.unpack("<I", raw_pcap[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            endian = "<"
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            endian = ">"
        else:
            raise ValueError("Unsupported PCAP magic header (standard .pcap required).")

        offset = 24
        reassembled = bytearray()
        while offset + 16 <= len(raw_pcap):
            _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack(f"{endian}IIII", raw_pcap[offset:offset + 16])
            offset += 16
            pkt = raw_pcap[offset:offset + incl_len]
            offset += incl_len
            if len(pkt) < 34:
                continue
            eth_type = struct.unpack("!H", pkt[12:14])[0]
            if eth_type != 0x0800:  # IPv4
                continue
            ip_start = 14
            ihl = (pkt[ip_start] & 0x0F) * 4
            proto = pkt[ip_start + 9]
            l4_start = ip_start + ihl
            if proto == 6 and len(pkt) >= l4_start + 20:  # TCP
                tcp_hdr_len = ((pkt[l4_start + 12] >> 4) & 0x0F) * 4
                reassembled.extend(pkt[l4_start + tcp_hdr_len:])
            elif proto == 17 and len(pkt) >= l4_start + 8:  # UDP
                reassembled.extend(pkt[l4_start + 8:])
        return bytes(reassembled)
