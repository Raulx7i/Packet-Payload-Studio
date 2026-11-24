import base64
import gzip
import hashlib
import math
import re
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk

FORMATS = ["C Array", "Hex Dump", "YAML", "ASCII", "UTF-8", "EBCDIC", "Raw"]


class ConversionEngine:
    """Hub-and-spoke converter: Any Format -> canonical bytes -> Any Format."""

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
    def to_bytes(text: str, fmt: str, ebcdic_cp: str = "cp037") -> bytes:
        if fmt == "C Array":
            hex_tokens = re.findall(r"0x([0-9a-fA-F]{2})", text)
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
                return "".join(
                    chr(b) if (32 <= b <= 126 or b in (9, 10, 13)) else "."
                    for b in data
                )
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
            headers = data[:sep]
            body = data[sep + 4:]
            if body.startswith(b"\x1f\x8b"):
                return headers + b"\r\n\r\n" + gzip.decompress(body)
        raise ValueError("No Gzip magic bytes (1f 8b) detected in payload.")


class PacketConverterApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("Wireshark Stream & Payload Converter")
        self.geometry("1280x780")
        self.minsize(1020, 620)

        self.current_bytes = b""
        self.in_fmt = "C Array"
        self.out_fmt = "ASCII"

        self._build_ui()
        self._load_sample()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # --- Top Global Action Bar ---
        top_bar = ctk.CTkFrame(self, height=48, corner_radius=10)
        top_bar.grid(row=0, column=0, columnspan=2, sticky="ew", padx=14, pady=(12, 6))

        ctk.CTkLabel(
            top_bar, text="Wireshark Stream Converter",
            font=ctk.CTkFont(size=15, weight="bold")
        ).pack(side="left", padx=14, pady=8)

        # Global utilities on right side of top bar
        ctk.CTkButton(
            top_bar, text="Clear All", width=85, fg_color="#45475a", hover_color="#585b70",
            command=self.clear_all
        ).pack(side="right", padx=(6, 12), pady=8)

        ctk.CTkButton(
            top_bar, text="Gunzip Body", width=105, fg_color="#313244", hover_color="#45475a",
            command=self.decompress_gzip
        ).pack(side="right", padx=6, pady=8)

        ctk.CTkButton(
            top_bar, text="⇄ Swap Panes", width=115, command=self.swap_panes
        ).pack(side="right", padx=6, pady=8)

        # EBCDIC Codepage Pill
        self.ebcdic_var = ctk.StringVar(value="cp037")
        cp_menu = ctk.CTkOptionMenu(
            top_bar, values=["cp037", "cp500", "cp1047"], variable=self.ebcdic_var,
            width=90, command=lambda _: self.convert()
        )
        cp_menu.pack(side="right", padx=(4, 10), pady=8)
        ctk.CTkLabel(top_bar, text="EBCDIC Codepage:", font=ctk.CTkFont(size=12)).pack(side="right", padx=(10, 4))

        # --- Left Panel: Input with Format Selection Tabs ---
        left_card = ctk.CTkFrame(self, corner_radius=12)
        left_card.grid(row=1, column=0, sticky="nsew", padx=(14, 7), pady=6)
        left_card.grid_rowconfigure(2, weight=1)
        left_card.grid_columnconfigure(0, weight=1)

        left_header = ctk.CTkFrame(left_card, fg_color="transparent")
        left_header.grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 4))

        ctk.CTkLabel(
            left_header, text="INPUT FORMAT",
            font=ctk.CTkFont(size=12, weight="bold"), text_color="#89b4fa"
        ).pack(side="left")

        ctk.CTkButton(
            left_header, text="Load File...", width=85, height=28,
            fg_color="#313244", hover_color="#45475a", command=self.load_file
        ).pack(side="right", padx=(4, 0))

        ctk.CTkButton(
            left_header, text="Paste", width=65, height=28,
            fg_color="#313244", hover_color="#45475a", command=self.paste_clipboard
        ).pack(side="right", padx=4)

        ctk.CTkButton(
            left_header, text="Auto-Detect", width=95, height=28,
            command=self.auto_detect_input
        ).pack(side="right", padx=4)

        # Input Format Selection Tabs (Segmented Button)
        self.in_tabs = ctk.CTkSegmentedButton(
            left_card, values=FORMATS, command=self.on_input_tab_change,
            font=ctk.CTkFont(size=12, weight="bold"), height=32
        )
        self.in_tabs.set("C Array")
        self.in_tabs.grid(row=1, column=0, sticky="ew", padx=12, pady=(4, 8))

        self.in_textbox = ctk.CTkTextbox(
            left_card, font=ctk.CTkFont(family="Menlo", size=13),
            wrap="none", corner_radius=8
        )
        self.in_textbox.grid(row=2, column=0, sticky="nsew", padx=12, pady=(0, 12))
        self.in_textbox.bind("<KeyRelease>", lambda _: self.convert())

        # --- Right Panel: Output with Format Selection Tabs ---
        right_card = ctk.CTkFrame(self, corner_radius=12)
        right_card.grid(row=1, column=1, sticky="nsew", padx=(7, 14), pady=6)
        right_card.grid_rowconfigure(2, weight=1)
        right_card.grid_columnconfigure(0, weight=1)

        right_header = ctk.CTkFrame(right_card, fg_color="transparent")
        right_header.grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 4))

        ctk.CTkLabel(
            right_header, text="OUTPUT FORMAT",
            font=ctk.CTkFont(size=12, weight="bold"), text_color="#a6e3a1"
        ).pack(side="left")

        ctk.CTkButton(
            right_header, text="Save Output...", width=95, height=28,
            fg_color="#313244", hover_color="#45475a", command=self.save_output
        ).pack(side="right", padx=(4, 0))

        ctk.CTkButton(
            right_header, text="Copy Output", width=95, height=28,
            command=self.copy_output
        ).pack(side="right", padx=4)

        self.ascii_dots_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            right_header, text="Dots for non-ASCII", variable=self.ascii_dots_var,
            font=ctk.CTkFont(size=11), checkbox_width=18, checkbox_height=18,
            command=self.convert
        ).pack(side="right", padx=8)

        # Output Format Selection Tabs (Segmented Button)
        self.out_tabs = ctk.CTkSegmentedButton(
            right_card, values=FORMATS, command=self.on_output_tab_change,
            font=ctk.CTkFont(size=12, weight="bold"), height=32,
            selected_color="#2e7d32", selected_hover_color="#388e3c"
        )
        self.out_tabs.set("ASCII")
        self.out_tabs.grid(row=1, column=0, sticky="ew", padx=12, pady=(4, 8))

        self.out_textbox = ctk.CTkTextbox(
            right_card, font=ctk.CTkFont(family="Menlo", size=13),
            wrap="none", corner_radius=8, text_color="#a6e3a1"
        )
        self.out_textbox.grid(row=2, column=0, sticky="nsew", padx=12, pady=(0, 12))

        # --- Bottom Status & Entropy Inspector Bar ---
        status_bar = ctk.CTkFrame(self, height=34, corner_radius=8)
        status_bar.grid(row=2, column=0, columnspan=2, sticky="ew", padx=14, pady=(4, 12))

        self.status_label = ctk.CTkLabel(
            status_bar, text="Ready",
            font=ctk.CTkFont(family="Menlo", size=11), text_color="#a6adc8"
        )
        self.status_label.pack(side="left", padx=12, pady=5)

    def _load_sample(self):
        sample = (
            "char peer0_0[] = { /* Packet 6 */\n"
            "0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54,\n"
            "0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a,\n"
            "0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x68, 0x74,\n"
            "0x74, 0x70, 0x66, 0x6f, 0x72, 0x65, 0x76, 0x65,\n"
            "0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a, 0x0d, 0x0a };"
        )
        self.in_textbox.insert("1.0", sample)
        self.convert()

    def on_input_tab_change(self, value: str):
        self.in_fmt = value
        self.convert()

    def on_output_tab_change(self, value: str):
        self.out_fmt = value
        self.convert()

    def convert(self):
        raw_in = self.in_textbox.get("1.0", "end-1c")
        if not raw_in.strip():
            self.current_bytes = b""
            self.out_textbox.delete("1.0", "end")
            self.status_label.configure(text="Bytes: 0  |  Entropy: 0.00  |  SHA-256: -")
            return

        try:
            data = ConversionEngine.to_bytes(raw_in, self.in_fmt, self.ebcdic_var.get())
            self.current_bytes = data
            rendered = ConversionEngine.from_bytes(
                data, self.out_fmt, self.ebcdic_var.get(), self.ascii_dots_var.get()
            )
            self.out_textbox.configure(text_color="#a6e3a1")
            self.out_textbox.delete("1.0", "end")
            self.out_textbox.insert("1.0", rendered)

            entropy = ConversionEngine.shannon_entropy(data)
            ent_hint = " (Likely Encrypted/Compressed)" if entropy > 7.2 else " (Plaintext/Structured)"
            sha_short = hashlib.sha256(data).hexdigest()[:16]
            self.status_label.configure(
                text=f"Bytes: {len(data):,}  |  Entropy: {entropy:.2f}/8.00{ent_hint}  |  SHA-256: {sha_short}..."
            )
        except Exception as exc:
            self.out_textbox.configure(text_color="#f38ba8")
            self.out_textbox.delete("1.0", "end")
            self.out_textbox.insert("1.0", f"[Conversion Error]\n{exc}")
            self.status_label.configure(text=f"Error: {exc}")

    def auto_detect_input(self):
        raw_in = self.in_textbox.get("1.0", "end-1c")
        detected = ConversionEngine.auto_detect(raw_in)
        self.in_fmt = detected
        self.in_tabs.set(detected)
        self.convert()

    def swap_panes(self):
        out_val = self.out_textbox.get("1.0", "end-1c")
        old_in, old_out = self.in_fmt, self.out_fmt

        self.in_fmt = old_out
        self.out_fmt = old_in
        self.in_tabs.set(old_out)
        self.out_tabs.set(old_in)

        self.in_textbox.delete("1.0", "end")
        self.in_textbox.insert("1.0", out_val)
        self.convert()

    def decompress_gzip(self):
        if not self.current_bytes:
            return
        try:
            unzipped = ConversionEngine.try_gunzip(self.current_bytes)
            self.current_bytes = unzipped
            rendered = ConversionEngine.from_bytes(
                unzipped, self.out_fmt, self.ebcdic_var.get(), self.ascii_dots_var.get()
            )
            self.out_textbox.delete("1.0", "end")
            self.out_textbox.insert("1.0", rendered)
            self.status_label.configure(text=f"Gunzipped successfully -> {len(unzipped):,} bytes")
        except Exception as exc:
            messagebox.showinfo("Gunzip", str(exc))

    def paste_clipboard(self):
        try:
            clip = self.clipboard_get()
            self.in_textbox.delete("1.0", "end")
            self.in_textbox.insert("1.0", clip)
            self.auto_detect_input()
        except tk.TclError:
            messagebox.showwarning("Clipboard", "Clipboard is empty or contains non-text data.")

    def copy_output(self):
        out_val = self.out_textbox.get("1.0", "end-1c")
        self.clipboard_clear()
        self.clipboard_append(out_val)
        self.status_label.configure(text="Copied output to clipboard.")

    def load_file(self):
        path = filedialog.askopenfilename(title="Open Stream or Binary File")
        if not path:
            return
        with open(path, "rb") as f:
            raw_bytes = f.read()
        try:
            text_val = raw_bytes.decode("utf-8")
            self.in_textbox.delete("1.0", "end")
            self.in_textbox.insert("1.0", text_val)
            self.auto_detect_input()
        except UnicodeDecodeError:
            self.in_fmt = "Raw"
            self.in_tabs.set("Raw")
            self.in_textbox.delete("1.0", "end")
            self.in_textbox.insert("1.0", raw_bytes.decode("latin-1"))
            self.convert()

    def save_output(self):
        if self.out_fmt == "Raw":
            path = filedialog.asksaveasfilename(title="Save Raw Binary", defaultextension=".bin")
            if path:
                with open(path, "wb") as f:
                    f.write(self.current_bytes)
                self.status_label.configure(text=f"Saved {len(self.current_bytes):,} raw bytes to {path}")
        else:
            path = filedialog.asksaveasfilename(title="Save Converted Output", defaultextension=".txt")
            if path:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self.out_textbox.get("1.0", "end-1c"))
                self.status_label.configure(text=f"Saved text output to {path}")

    def clear_all(self):
        self.in_textbox.delete("1.0", "end")
        self.out_textbox.delete("1.0", "end")
        self.current_bytes = b""
        self.status_label.configure(text="Cleared.")


if __name__ == "__main__":
    app = PacketConverterApp()
    app.mainloop()
