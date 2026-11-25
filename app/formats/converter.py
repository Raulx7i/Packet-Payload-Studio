from __future__ import annotations

import base64
import hashlib
import re

FORMATS = ["C Array", "Hex Dump", "YAML", "ASCII", "UTF-8", "EBCDIC", "Raw"]


class ConversionEngine:
    """Hub-and-spoke packet engine: Any Format -> canonical bytes -> Any Format."""

    @staticmethod
    def auto_detect(text: str) -> str:
        sample = text.strip()
        if not sample:
            return "ASCII"
        if re.search(r"\b0x[0-9a-fA-F]{2}\b", sample) and ("{" in sample or "," in sample):
            return "C Array"
        if re.match(r"^[0-9a-fA-F]{4,8}:\s+([0-9a-fA-F]{2,4}\s+)+", sample):
            return "Hex Dump"
        if re.match(r"^[0-9a-fA-F]{4,8}\s{2,}([0-9a-fA-F]{2}\s+)+", sample):
            return "Hex Dump"
        compact = re.sub(r"\s+", "", sample)
        if re.fullmatch(r"[0-9a-fA-F]+", compact) and len(compact) >= 4 and len(compact) % 2 == 0:
            return "Hex Dump"
        if sample.startswith("---") or re.search(r"^\s*(?:packets|data|payload|stream|hex):", sample, re.M):
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
    def _parse_c_array(text: str, peer_filter: str) -> bytes:
        filtered = ConversionEngine.filter_c_array_stream(text, peer_filter)
        if not filtered.strip():
            return b""
        # Strip C block comments and line comments so /* 0x42 */ doesn't pollute bytes
        no_comments = re.sub(r"/\*[\s\S]*?\*/|//.*", " ", filtered)
        # Extract body inside braces if present
        brace_bodies = re.findall(r"\{([\s\S]*?)\}", no_comments)
        body = ",".join(brace_bodies) if brace_bodies else no_comments

        out = bytearray()
        for raw_tok in body.split(","):
            tok = raw_tok.strip()
            if not tok:
                continue
            if re.fullmatch(r"0[xX][0-9a-fA-F]+", tok):
                val = int(tok, 16)
                if val > 0xFF:
                    raise ValueError(f"C Array token {tok!r} exceeds single byte (0xFF).")
                out.append(val)
            elif re.fullmatch(r"-?\d+", tok):
                val = int(tok, 10)
                if not (-128 <= val <= 255):
                    raise ValueError(f"C Array integer {tok!r} out of byte range (-128..255).")
                out.append(val & 0xFF)
            elif re.fullmatch(r"'(?:\\.|[^\\'])'", tok):
                ch = tok[1:-1]
                esc = {"\\n": 10, "\\r": 13, "\\t": 9, "\\0": 0, "\\\\": 92, "\\'": 39}
                out.append(esc[ch] if ch in esc else ord(ch[-1]))
            else:
                raise ValueError(f"Unsupported C Array element: {tok!r}")
        if not out and "{" not in no_comments:
            raise ValueError("No valid byte literals found in C Array input.")
        return bytes(out)

    @staticmethod
    def _parse_hex_dump(text: str) -> bytes:
        if not text.strip():
            return b""
        out = bytearray()
        for line in text.splitlines():
            s = line.strip()
            if not s:
                continue
            # Match xxd style ("00000000: 4865 6c6c ...") or hexdump -C ("00000000  48 65 ...  |ASCII|")
            m_colon = re.match(r"^[0-9a-fA-F]{2,16}:\s+(.*)$", s)
            m_gap = re.match(r"^[0-9a-fA-F]{4,16}\s{2,}(.*)$", s)
            if m_colon:
                rest = m_colon.group(1)
                # Strip trailing ASCII gutter after 2+ spaces
                hex_part = re.split(r"\s{2,}", rest, maxsplit=1)[0]
            elif m_gap:
                rest = m_gap.group(1)
                # Standard hexdump -C has 2 spaces between 8-byte groups and 2-3+ spaces/pipe before ASCII
                hex_part = re.split(r"\s{3,}|\s+\|", rest, maxsplit=1)[0]
            else:
                # Bare hex line (e.g. "dead beef" or "48656c6c6f") — do NOT strip leading hex word!
                hex_part = re.split(r"\s{3,}|\s+\|", s, maxsplit=1)[0]

            compact = re.sub(r"\s+", "", hex_part)
            if not compact or not re.fullmatch(r"[0-9a-fA-F]+", compact) or len(compact) % 2 != 0:
                raise ValueError(f"Invalid hex dump line: {line!r}")
            out.extend(bytes.fromhex(compact))
        if not out:
            raise ValueError("No valid hex dump bytes found.")
        return bytes(out)

    @staticmethod
    def to_bytes(text: str, fmt: str, ebcdic_cp: str = "cp037", peer_filter: str = "All Streams") -> bytes:
        if fmt == "C Array":
            return ConversionEngine._parse_c_array(text, peer_filter)
        elif fmt == "Hex Dump":
            return ConversionEngine._parse_hex_dump(text)
        elif fmt == "YAML":
            b64_blocks = re.findall(
                r"(?:^|\n)[ \t]*(?:data|payload|base64):[ \t]*(?:!!binary[ \t]*)?\|?[ \t]*\r?\n((?:[ \t]+[A-Za-z0-9+/=]+[ \t]*\r?\n?)+)",
                text,
            )
            if b64_blocks:
                return b"".join(base64.b64decode(re.sub(r"\s+", "", blk)) for blk in b64_blocks)
            b64_inline = re.findall(r"(?:^|\n)[ \t]*(?:data|payload|base64):[ \t]*(?:!!binary[ \t]*)?([A-Za-z0-9+/=]+)", text)
            if b64_inline:
                return b"".join(base64.b64decode(m) for m in b64_inline)
            hex_matches = re.findall(r"(?:^|\n)[ \t]*(?:hex|bytes):[ \t]*([0-9a-fA-F \t]+)", text)
            if hex_matches:
                cleaned = re.sub(r"\s+", "", "".join(hex_matches))
                return bytes.fromhex(cleaned)
            str_match = re.search(r"(?:^|\n)[ \t]*(?:text|ascii|utf8):[ \t]*\|?[ \t]*\r?\n?([\s\S]+)", text)
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
            preview = (
                data.decode("utf-8", errors="replace")
                .replace("\\", "\\\\")
                .replace('"', '\\"')
                .replace("\n", "\\n")
                .replace("\r", "\\r")
            )
            if len(preview) > 120:
                preview = preview[:117] + "..."
            return (
                "---\n"
                f"byte_length: {len(data)}\n"
                f"sha256: {hashlib.sha256(data).hexdigest()}\n"
                f'preview: "{preview}"\n'
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
