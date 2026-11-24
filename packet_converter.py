import base64
import gzip
import hashlib
import math
import re
import tkinter as tk
from tkinter import filedialog, messagebox

FORMATS = ["C Array", "Hex Dump", "YAML", "ASCII", "UTF-8", "EBCDIC", "Raw"]

# Nord Frost Palette (Low-Glare Arctic Slate & Ice Blue)
NORD = {
    "bg_window": "#2E3440",      # Polar Night 0 (Base translucent backdrop)
    "bg_card": "#3B4252",        # Polar Night 1 (Elevated frosted panels)
    "bg_elevated": "#434C5E",    # Polar Night 2 (Inactive pills / controls)
    "bg_editor": "#242933",      # Deep Slate (Crisp editor surface)
    "border": "#4C566A",         # Polar Night 3 (Subtle hairline borders)
    "fg_main": "#ECEFF4",        # Snow Storm 2 (Primary readable text)
    "fg_muted": "#D8DEE9",       # Snow Storm 0 (Labels & status)
    "frost_cyan": "#88C0D0",     # Frost 1 (Input active accent)
    "frost_blue": "#81A1C1",     # Frost 2 (Secondary buttons)
    "aurora_green": "#A3BE8C",   # Aurora Green (Output text & active accent)
    "aurora_red": "#BF616A",     # Aurora Red (Error highlight)
    "text_dark": "#2E3440",      # Dark text for active bright pills
}


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


class PacketConverterApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Wireshark Stream & Payload Converter")
        self.root.geometry("1320x800")
        self.root.minsize(1060, 620)
        self.root.configure(bg=NORD["bg_window"])

        # Semi-transparent frosted glass window opacity (adjustable via slider)
        self.alpha_var = tk.DoubleVar(value=0.93)
        self._apply_frosted_glass()

        self.current_bytes = b""
        self.in_fmt_var = tk.StringVar(value="C Array")
        self.out_fmt_var = tk.StringVar(value="ASCII")
        self.ebcdic_var = tk.StringVar(value="cp037")
        self.ascii_dots = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="Ready")

        self._build_ui()
        self._load_sample()

    def _apply_frosted_glass(self):
        try:
            self.root.wm_attributes("-alpha", self.alpha_var.get())
        except tk.TclError:
            pass

    def _on_opacity_slide(self, val: str):
        try:
            self.root.wm_attributes("-alpha", float(val))
        except tk.TclError:
            pass

    def _make_pill(self, parent, text, cmd, bg=NORD["bg_elevated"], fg=NORD["fg_main"], padx=10, pady=4):
        lbl = tk.Label(
            parent,
            text=text,
            bg=bg,
            fg=fg,
            font=("Helvetica", 11, "bold"),
            padx=padx,
            pady=pady,
            cursor="pointinghand",
        )
        lbl.bind("<Button-1>", lambda _e: cmd())
        return lbl

    def _build_ui(self):
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1, uniform="col")
        self.root.grid_columnconfigure(1, weight=1, uniform="col")

        # ================= TOP FROSTED HEADER BAR =================
        top_bar = tk.Frame(
            self.root, bg=NORD["bg_card"], padx=14, pady=10,
            highlightbackground=NORD["border"], highlightthickness=1
        )
        top_bar.grid(row=0, column=0, columnspan=2, sticky="ew", padx=14, pady=(12, 6))

        tk.Label(
            top_bar, text="Wireshark Stream & Payload Converter",
            bg=NORD["bg_card"], fg=NORD["fg_main"], font=("Helvetica", 15, "bold")
        ).pack(side=tk.LEFT)

        # Right-side global actions
        self._make_pill(
            top_bar, "Clear All", self.clear_all,
            bg=NORD["bg_elevated"], fg=NORD["fg_muted"]
        ).pack(side=tk.RIGHT, padx=(6, 0))

        self._make_pill(
            top_bar, "Gunzip Body", self.decompress_gzip,
            bg=NORD["bg_elevated"], fg=NORD["frost_cyan"]
        ).pack(side=tk.RIGHT, padx=6)

        self._make_pill(
            top_bar, "Swap Panes", self.swap_panes,
            bg=NORD["frost_blue"], fg=NORD["text_dark"]
        ).pack(side=tk.RIGHT, padx=6)

        # EBCDIC Codepage Dropdown
        cp_menu = tk.OptionMenu(top_bar, self.ebcdic_var, "cp037", "cp500", "cp1047", command=lambda _: self.convert())
        cp_menu.configure(
            bg=NORD["bg_elevated"], fg=NORD["fg_main"],
            activebackground=NORD["border"], activeforeground=NORD["fg_main"],
            highlightthickness=0, bd=0, font=("Menlo", 11)
        )
        cp_menu.pack(side=tk.RIGHT, padx=(4, 14))
        tk.Label(
            top_bar, text="EBCDIC:", bg=NORD["bg_card"], fg=NORD["fg_muted"], font=("Helvetica", 11)
        ).pack(side=tk.RIGHT)

        # Glass Opacity Slider
        opacity_scale = tk.Scale(
            top_bar, from_=0.75, to=1.0, resolution=0.01, orient=tk.HORIZONTAL,
            variable=self.alpha_var, command=self._on_opacity_slide,
            showvalue=False, length=85, sliderlength=14,
            bg=NORD["bg_card"], troughcolor=NORD["bg_editor"],
            highlightthickness=0, bd=0
        )
        opacity_scale.pack(side=tk.RIGHT, padx=(4, 14))
        tk.Label(
            top_bar, text="Glass:", bg=NORD["bg_card"], fg=NORD["fg_muted"], font=("Helvetica", 11)
        ).pack(side=tk.RIGHT)

        # ================= LEFT CARD (INPUT STREAM) =================
        left_card = tk.Frame(
            self.root, bg=NORD["bg_card"], padx=12, pady=10,
            highlightbackground=NORD["border"], highlightthickness=1
        )
        left_card.grid(row=1, column=0, sticky="nsew", padx=(14, 7), pady=4)
        left_card.grid_rowconfigure(2, weight=1)
        left_card.grid_columnconfigure(0, weight=1)

        # Row 0: Input Dropdown + File/Clipboard Actions
        left_top = tk.Frame(left_card, bg=NORD["bg_card"])
        left_top.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        tk.Label(
            left_top, text="INPUT:", bg=NORD["bg_card"], fg=NORD["frost_cyan"],
            font=("Helvetica", 12, "bold")
        ).pack(side=tk.LEFT, padx=(0, 6))

        in_menu = tk.OptionMenu(left_top, self.in_fmt_var, *FORMATS, command=lambda _: self.on_format_change())
        in_menu.configure(
            bg=NORD["bg_elevated"], fg=NORD["fg_main"],
            activebackground=NORD["border"], activeforeground=NORD["fg_main"],
            highlightthickness=0, bd=0, font=("Helvetica", 11, "bold"), width=9
        )
        in_menu.pack(side=tk.LEFT)

        self._make_pill(left_top, "Load File...", self.load_file, padx=8, pady=3).pack(side=tk.RIGHT, padx=(4, 0))
        self._make_pill(left_top, "Paste", self.paste_clipboard, padx=8, pady=3).pack(side=tk.RIGHT, padx=4)
        self._make_pill(
            left_top, "Auto-Detect", self.auto_detect_input,
            bg=NORD["frost_cyan"], fg=NORD["text_dark"], padx=8, pady=3
        ).pack(side=tk.RIGHT, padx=4)

        # Row 1: Equal-Width Format Selection Tabs (All 7 visible without clipping)
        in_tabs = tk.Frame(left_card, bg=NORD["bg_editor"], padx=3, pady=3)
        in_tabs.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        self.in_pill_btns = {}
        for idx, fmt in enumerate(FORMATS):
            in_tabs.grid_columnconfigure(idx, weight=1, uniform="intab")
            lbl = tk.Label(
                in_tabs, text=fmt, font=("Menlo", 10, "bold"),
                pady=5, cursor="pointinghand"
            )
            lbl.grid(row=0, column=idx, sticky="ew", padx=1)
            lbl.bind("<Button-1>", lambda _e, f=fmt: self.set_in_format(f))
            self.in_pill_btns[fmt] = lbl

        # Row 2: Input Editor
        in_editor_wrap = tk.Frame(
            left_card, bg=NORD["bg_editor"],
            highlightbackground=NORD["border"], highlightthickness=1
        )
        in_editor_wrap.grid(row=2, column=0, sticky="nsew")
        in_editor_wrap.grid_rowconfigure(0, weight=1)
        in_editor_wrap.grid_columnconfigure(0, weight=1)

        self.in_text = tk.Text(
            in_editor_wrap,
            wrap=tk.NONE,
            bg=NORD["bg_editor"],
            fg=NORD["fg_main"],
            insertbackground=NORD["frost_cyan"],
            selectbackground=NORD["border"],
            selectforeground=NORD["fg_main"],
            font=("Menlo", 13),
            padx=12,
            pady=10,
            undo=True,
            highlightthickness=0,
            bd=0
        )
        in_sy = tk.Scrollbar(in_editor_wrap, orient=tk.VERTICAL, command=self.in_text.yview)
        in_sx = tk.Scrollbar(in_editor_wrap, orient=tk.HORIZONTAL, command=self.in_text.xview)
        self.in_text.configure(yscrollcommand=in_sy.set, xscrollcommand=in_sx.set)

        self.in_text.grid(row=0, column=0, sticky="nsew")
        in_sy.grid(row=0, column=1, sticky="ns")
        in_sx.grid(row=1, column=0, sticky="ew")
        self.in_text.bind("<KeyRelease>", lambda _: self.convert())

        # ================= RIGHT CARD (CONVERTED OUTPUT) =================
        right_card = tk.Frame(
            self.root, bg=NORD["bg_card"], padx=12, pady=10,
            highlightbackground=NORD["border"], highlightthickness=1
        )
        right_card.grid(row=1, column=1, sticky="nsew", padx=(7, 14), pady=4)
        right_card.grid_rowconfigure(2, weight=1)
        right_card.grid_columnconfigure(0, weight=1)

        # Row 0: Output Dropdown + Actions
        right_top = tk.Frame(right_card, bg=NORD["bg_card"])
        right_top.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        tk.Label(
            right_top, text="OUTPUT:", bg=NORD["bg_card"], fg=NORD["aurora_green"],
            font=("Helvetica", 12, "bold")
        ).pack(side=tk.LEFT, padx=(0, 6))

        out_menu = tk.OptionMenu(right_top, self.out_fmt_var, *FORMATS, command=lambda _: self.on_format_change())
        out_menu.configure(
            bg=NORD["bg_elevated"], fg=NORD["fg_main"],
            activebackground=NORD["border"], activeforeground=NORD["fg_main"],
            highlightthickness=0, bd=0, font=("Helvetica", 11, "bold"), width=9
        )
        out_menu.pack(side=tk.LEFT)

        self._make_pill(right_top, "Save...", self.save_output, padx=8, pady=3).pack(side=tk.RIGHT, padx=(4, 0))
        self._make_pill(
            right_top, "Copy Output", self.copy_output,
            bg=NORD["aurora_green"], fg=NORD["text_dark"], padx=8, pady=3
        ).pack(side=tk.RIGHT, padx=4)

        tk.Checkbutton(
            right_top, text="Non-ASCII dots", variable=self.ascii_dots,
            bg=NORD["bg_card"], fg=NORD["fg_muted"], selectcolor=NORD["bg_editor"],
            activebackground=NORD["bg_card"], activeforeground=NORD["fg_main"],
            font=("Helvetica", 11), command=self.convert
        ).pack(side=tk.RIGHT, padx=6)

        # Row 1: Equal-Width Output Format Tabs
        out_tabs = tk.Frame(right_card, bg=NORD["bg_editor"], padx=3, pady=3)
        out_tabs.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        self.out_pill_btns = {}
        for idx, fmt in enumerate(FORMATS):
            out_tabs.grid_columnconfigure(idx, weight=1, uniform="outtab")
            lbl = tk.Label(
                out_tabs, text=fmt, font=("Menlo", 10, "bold"),
                pady=5, cursor="pointinghand"
            )
            lbl.grid(row=0, column=idx, sticky="ew", padx=1)
            lbl.bind("<Button-1>", lambda _e, f=fmt: self.set_out_format(f))
            self.out_pill_btns[fmt] = lbl

        # Row 2: Output Editor
        out_editor_wrap = tk.Frame(
            right_card, bg=NORD["bg_editor"],
            highlightbackground=NORD["border"], highlightthickness=1
        )
        out_editor_wrap.grid(row=2, column=0, sticky="nsew")
        out_editor_wrap.grid_rowconfigure(0, weight=1)
        out_editor_wrap.grid_columnconfigure(0, weight=1)

        self.out_text = tk.Text(
            out_editor_wrap,
            wrap=tk.NONE,
            bg=NORD["bg_editor"],
            fg=NORD["aurora_green"],
            insertbackground=NORD["aurora_green"],
            selectbackground=NORD["border"],
            selectforeground=NORD["fg_main"],
            font=("Menlo", 13),
            padx=12,
            pady=10,
            highlightthickness=0,
            bd=0
        )
        out_sy = tk.Scrollbar(out_editor_wrap, orient=tk.VERTICAL, command=self.out_text.yview)
        out_sx = tk.Scrollbar(out_editor_wrap, orient=tk.HORIZONTAL, command=self.out_text.xview)
        self.out_text.configure(yscrollcommand=out_sy.set, xscrollcommand=out_sx.set)

        self.out_text.grid(row=0, column=0, sticky="nsew")
        out_sy.grid(row=0, column=1, sticky="ns")
        out_sx.grid(row=1, column=0, sticky="ew")

        # ================= BOTTOM STATUS BAR =================
        status_bar = tk.Frame(
            self.root, bg=NORD["bg_card"], padx=14, pady=8,
            highlightbackground=NORD["border"], highlightthickness=1
        )
        status_bar.grid(row=2, column=0, columnspan=2, sticky="ew", padx=14, pady=(4, 12))

        tk.Label(
            status_bar, textvariable=self.status_var, bg=NORD["bg_card"], fg=NORD["fg_muted"],
            font=("Menlo", 11)
        ).pack(side=tk.LEFT)

        self._highlight_active_pills()

    def _highlight_active_pills(self):
        cur_in = self.in_fmt_var.get()
        cur_out = self.out_fmt_var.get()
        for fmt, lbl in self.in_pill_btns.items():
            if fmt == cur_in:
                lbl.configure(bg=NORD["frost_cyan"], fg=NORD["text_dark"])
            else:
                lbl.configure(bg=NORD["bg_elevated"], fg=NORD["fg_muted"])
        for fmt, lbl in self.out_pill_btns.items():
            if fmt == cur_out:
                lbl.configure(bg=NORD["aurora_green"], fg=NORD["text_dark"])
            else:
                lbl.configure(bg=NORD["bg_elevated"], fg=NORD["fg_muted"])

    def set_in_format(self, fmt: str):
        self.in_fmt_var.set(fmt)
        self.on_format_change()

    def set_out_format(self, fmt: str):
        self.out_fmt_var.set(fmt)
        self.on_format_change()

    def on_format_change(self):
        self._highlight_active_pills()
        self.convert()

    def _load_sample(self):
        sample = (
            "char peer0_0[] = { /* Packet 6 */\n"
            "0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54,\n"
            "0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a,\n"
            "0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x68, 0x74,\n"
            "0x74, 0x70, 0x66, 0x6f, 0x72, 0x65, 0x76, 0x65,\n"
            "0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a, 0x0d, 0x0a };"
        )
        self.in_text.delete("1.0", tk.END)
        self.in_text.insert("1.0", sample)
        self.convert()

    def convert(self):
        raw_in = self.in_text.get("1.0", "end-1c")
        if not raw_in.strip():
            self.current_bytes = b""
            self.out_text.delete("1.0", tk.END)
            self.status_var.set("Bytes: 0  |  Entropy: 0.00  |  SHA-256: -")
            return

        try:
            data = ConversionEngine.to_bytes(raw_in, self.in_fmt_var.get(), self.ebcdic_var.get())
            self.current_bytes = data
            rendered = ConversionEngine.from_bytes(
                data, self.out_fmt_var.get(), self.ebcdic_var.get(), self.ascii_dots.get()
            )
            self.out_text.configure(fg=NORD["aurora_green"])
            self.out_text.delete("1.0", tk.END)
            self.out_text.insert("1.0", rendered)

            entropy = ConversionEngine.shannon_entropy(data)
            ent_hint = " (Likely Encrypted/Compressed)" if entropy > 7.2 else " (Plaintext/Structured)"
            sha_short = hashlib.sha256(data).hexdigest()[:16]
            self.status_var.set(
                f"Bytes: {len(data):,}  |  Entropy: {entropy:.2f}/8.00{ent_hint}  |  SHA-256: {sha_short}..."
            )
        except Exception as exc:
            self.out_text.configure(fg=NORD["aurora_red"])
            self.out_text.delete("1.0", tk.END)
            self.out_text.insert("1.0", f"[Conversion Error]\n{exc}")
            self.status_var.set(f"Error: {exc}")

    def auto_detect_input(self):
        raw_in = self.in_text.get("1.0", "end-1c")
        detected = ConversionEngine.auto_detect(raw_in)
        self.in_fmt_var.set(detected)
        self.on_format_change()

    def swap_panes(self):
        out_val = self.out_text.get("1.0", "end-1c")
        old_in = self.in_fmt_var.get()
        old_out = self.out_fmt_var.get()
        self.in_fmt_var.set(old_out)
        self.out_fmt_var.set(old_in)
        self._highlight_active_pills()
        self.in_text.delete("1.0", tk.END)
        self.in_text.insert("1.0", out_val)
        self.convert()

    def decompress_gzip(self):
        if not self.current_bytes:
            return
        try:
            unzipped = ConversionEngine.try_gunzip(self.current_bytes)
            self.current_bytes = unzipped
            rendered = ConversionEngine.from_bytes(
                unzipped, self.out_fmt_var.get(), self.ebcdic_var.get(), self.ascii_dots.get()
            )
            self.out_text.delete("1.0", tk.END)
            self.out_text.insert("1.0", rendered)
            self.status_var.set(f"Gunzipped successfully -> {len(unzipped):,} bytes")
        except Exception as exc:
            messagebox.showinfo("Gunzip", str(exc))

    def paste_clipboard(self):
        try:
            clip = self.root.clipboard_get()
            self.in_text.delete("1.0", tk.END)
            self.in_text.insert("1.0", clip)
            self.auto_detect_input()
        except tk.TclError:
            messagebox.showwarning("Clipboard", "Clipboard is empty or contains non-text data.")

    def copy_output(self):
        out_val = self.out_text.get("1.0", "end-1c")
        self.root.clipboard_clear()
        self.root.clipboard_append(out_val)
        self.status_var.set("Copied output to clipboard.")

    def load_file(self):
        path = filedialog.askopenfilename(title="Open Stream or Binary File")
        if not path:
            return
        with open(path, "rb") as f:
            raw_bytes = f.read()
        try:
            text_val = raw_bytes.decode("utf-8")
            self.in_text.delete("1.0", "end")
            self.in_text.insert("1.0", text_val)
            self.auto_detect_input()
        except UnicodeDecodeError:
            self.in_fmt_var.set("Raw")
            self._highlight_active_pills()
            self.in_text.delete("1.0", "end")
            self.in_text.insert("1.0", raw_bytes.decode("latin-1"))
            self.convert()

    def save_output(self):
        if self.out_fmt_var.get() == "Raw":
            path = filedialog.asksaveasfilename(title="Save Raw Binary", defaultextension=".bin")
            if path:
                with open(path, "wb") as f:
                    f.write(self.current_bytes)
                self.status_var.set(f"Saved {len(self.current_bytes):,} raw bytes to {path}")
        else:
            path = filedialog.asksaveasfilename(title="Save Converted Output", defaultextension=".txt")
            if path:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self.out_text.get("1.0", "end-1c"))
                self.status_var.set(f"Saved text output to {path}")

    def clear_all(self):
        self.in_text.delete("1.0", tk.END)
        self.out_text.delete("1.0", tk.END)
        self.current_bytes = b""
        self.status_var.set("Cleared.")


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketConverterApp(root)
    root.mainloop()
