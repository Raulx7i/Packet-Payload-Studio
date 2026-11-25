import base64
import hashlib
import math
import re
import struct
import urllib.parse
import zlib

FORMATS = ["C Array", "Hex Dump", "YAML", "ASCII", "UTF-8", "EBCDIC", "Raw"]
MAX_DECOMPRESS_BYTES = 10 * 1024 * 1024  # 10 MB safety cap against decompression bombs


class ConversionEngine:
    """Hub-and-spoke packet engine: Any Format -> canonical bytes -> Any Format."""

    @staticmethod
    def auto_detect(text: str) -> str:
        sample = text.strip()
        if not sample:
            return "ASCII"
        if re.search(r"0x[0-9a-fA-F]{2}", sample) and ("{" in sample or "," in sample):
            return "C Array"
        if re.match(r"^[0-9a-fA-F]{4,8}:?\s+([0-9a-fA-F]{2}\s+){2,}", sample):
            return "Hex Dump"
        if re.fullmatch(r"[0-9a-fA-F\s]+", sample) and len(re.sub(r"\s+", "", sample)) >= 4 and len(re.sub(r"\s+", "", sample)) % 2 == 0:
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
                # Strip leading offset (e.g., "0000   " or "00000000: ")
                line = re.sub(r"^[0-9a-fA-F]{4,8}:?\s+", "", line)
                # Split on 3+ spaces or pipe to preserve 2-space mid-line byte grouping
                hex_part = re.split(r"\s{3,}|\|", line)[0].strip()
                # Support continuous unseparated hex strings (e.g., 48656c6c6f)
                if re.fullmatch(r"[0-9a-fA-F]+", hex_part) and len(hex_part) % 2 == 0:
                    out.extend(bytes.fromhex(hex_part))
                else:
                    tokens = re.findall(r"\b[0-9a-fA-F]{2}\b", hex_part)
                    out.extend(int(t, 16) for t in tokens)
            if not out:
                raise ValueError("No valid hex dump bytes found.")
            return bytes(out)

        elif fmt == "YAML":
            # Support Wireshark multi-line !!binary | blocks as well as single-line Base64
            b64_blocks = re.findall(
                r"(?:data|payload|base64):[ \t]*(?:!!binary[ \t]*)?\|?[ \t]*\r?\n((?:[ \t]+[A-Za-z0-9+/=]+[ \t]*\r?\n?)+)",
                text,
            )
            if b64_blocks:
                return b"".join(base64.b64decode(re.sub(r"\s+", "", blk)) for blk in b64_blocks)
            b64_inline = re.findall(r"(?:data|payload|base64):\s*(?:!!binary\s*)?([A-Za-z0-9+/=]+)", text)
            if b64_inline:
                return b"".join(base64.b64decode(m) for m in b64_inline)
            hex_matches = re.findall(r"(?:hex|bytes):\s*([0-9a-fA-F\s]+)", text)
            if hex_matches:
                cleaned = re.sub(r"\s+", "", "".join(hex_matches))
                return bytes.fromhex(cleaned)
            str_match = re.search(r"(?:text|ascii|utf8):\s*\|?\s*\n?([\s\S]+)", text)
            if str_match:
                return str_match.group(1).encode("utf-8")
            raise ValueError("No YAML data, !!binary, hex, or text fields found.")

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
    def _decode_http_chunked(body: bytes) -> bytes:
        """Unchunk HTTP Transfer-Encoding: chunked body (tolerates truncated final chunks)."""
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

    @staticmethod
    def _bounded_decompress(payload: bytes, wbits: int, max_bytes: int = MAX_DECOMPRESS_BYTES) -> bytes:
        """Decompress Gzip/Zlib up to max_bytes, preserving partial output on truncated streams."""
        dobj = zlib.decompressobj(wbits)
        out = bytearray()
        mv = memoryview(payload)
        step = 16384
        for i in range(0, len(mv), step):
            remaining = max_bytes - len(out)
            if remaining <= 0:
                raise ValueError(f"Decompression aborted: output exceeded {max_bytes // (1024 * 1024)} MB safety limit.")
            try:
                chunk = dobj.decompress(mv[i:i + step], remaining)
            except zlib.error as exc:
                if out:
                    return bytes(out)
                raise ValueError(f"Corrupt Gzip/Zlib stream: {exc}") from exc
            out.extend(chunk)
            if dobj.unconsumed_tail and len(out) >= max_bytes:
                raise ValueError(f"Decompression aborted: output exceeded {max_bytes // (1024 * 1024)} MB safety limit.")
            if dobj.eof:
                break
        try:
            rem = max_bytes - len(out)
            if rem > 0:
                out.extend(dobj.flush(rem))
        except zlib.error:
            pass
        return bytes(out)

    @staticmethod
    def try_gunzip(data: bytes, max_bytes: int = MAX_DECOMPRESS_BYTES) -> bytes:
        if data.startswith(b"\x1f\x8b"):
            return ConversionEngine._bounded_decompress(data, 16 + zlib.MAX_WBITS, max_bytes)
        sep = data.find(b"\r\n\r\n")
        if sep != -1:
            headers, body = data[:sep], data[sep + 4:]
            if re.search(rb"(?i)^transfer-encoding:\s*chunked\b", headers, re.M):
                body = ConversionEngine._decode_http_chunked(body)
            if body.startswith(b"\x1f\x8b"):
                decompressed = ConversionEngine._bounded_decompress(body, 16 + zlib.MAX_WBITS, max_bytes)
                return headers + b"\r\n\r\n" + decompressed
            try:
                decompressed = ConversionEngine._bounded_decompress(body, zlib.MAX_WBITS, max_bytes)
                if decompressed:
                    return headers + b"\r\n\r\n" + decompressed
            except ValueError:
                pass
        try:
            res = ConversionEngine._bounded_decompress(data, zlib.MAX_WBITS, max_bytes)
            if res:
                return res
        except ValueError as exc:
            if "exceeded" in str(exc):
                raise
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
        """Extract Ethernet/VLAN IPv4 & IPv6 TCP/UDP payloads from classic .pcap files (strips L2 padding)."""
        if len(raw_pcap) < 24:
            raise ValueError("File too small to be a valid PCAP.")
        magic = struct.unpack("<I", raw_pcap[:4])[0]
        if magic == 0x0A0D0D0A:
            raise ValueError("PCAPNG format detected. Export as classic .pcap in Wireshark (File -> Save As -> tcpdump .pcap).")
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            endian = "<"
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            endian = ">"
        else:
            raise ValueError("Unsupported PCAP magic header (standard .pcap required).")

        _ver_maj, _ver_min, _thiszone, _sigfigs, _snaplen, network = struct.unpack(f"{endian}HHIIII", raw_pcap[4:24])
        if network != 1:
            raise ValueError(f"Unsupported PCAP link-layer type {network} (only Ethernet DLT_EN10MB=1 is supported).")

        offset = 24
        extracted = bytearray()
        while offset + 16 <= len(raw_pcap):
            _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack(f"{endian}IIII", raw_pcap[offset:offset + 16])
            offset += 16
            pkt = raw_pcap[offset:offset + incl_len]
            offset += incl_len
            if len(pkt) < 14:
                continue

            eth_type = struct.unpack("!H", pkt[12:14])[0]
            ip_start = 14
            # Handle single or QinQ 802.1Q VLAN tags
            while eth_type in (0x8100, 0x88A8) and len(pkt) >= ip_start + 4:
                eth_type = struct.unpack("!H", pkt[ip_start + 2:ip_start + 4])[0]
                ip_start += 4

            if eth_type == 0x0800 and len(pkt) >= ip_start + 20:  # IPv4
                ihl = (pkt[ip_start] & 0x0F) * 4
                total_len = struct.unpack("!H", pkt[ip_start + 2:ip_start + 4])[0]
                frag_offset = struct.unpack("!H", pkt[ip_start + 6:ip_start + 8])[0] & 0x1FFF
                if frag_offset != 0:
                    continue
                ip_end = min(len(pkt), ip_start + total_len) if total_len >= ihl else len(pkt)
                proto = pkt[ip_start + 9]
                l4_start = ip_start + ihl
            elif eth_type == 0x86DD and len(pkt) >= ip_start + 40:  # IPv6
                payload_len = struct.unpack("!H", pkt[ip_start + 4:ip_start + 6])[0]
                ip_end = min(len(pkt), ip_start + 40 + payload_len)
                proto = pkt[ip_start + 6]
                l4_start = ip_start + 40
            else:
                continue

            if proto == 6 and ip_end >= l4_start + 20:  # TCP
                tcp_hdr_len = ((pkt[l4_start + 12] >> 4) & 0x0F) * 4
                if ip_end > l4_start + tcp_hdr_len:
                    extracted.extend(pkt[l4_start + tcp_hdr_len:ip_end])
            elif proto == 17 and ip_end >= l4_start + 8:  # UDP
                if ip_end > l4_start + 8:
                    extracted.extend(pkt[l4_start + 8:ip_end])

        if not extracted:
            raise ValueError("No IPv4/IPv6 TCP or UDP payloads found in this PCAP.")
        return bytes(extracted)
