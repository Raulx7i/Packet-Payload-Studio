import base64
import gzip
import hashlib
import math
import re
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

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


class PacketConverterApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Wireshark Stream & Payload Converter")
        self.root.geometry("1240x760")
        self.root.minsize(960, 560)

        self.current_bytes = b""
        self.in_fmt = "C Array"
        self.out_fmt = "ASCII"

        self._setup_theme()
        self._build_ui()
        self._load_sample()

        # Force macOS window render & foreground focus
        self.root.update_idletasks()
        self.root.lift()
        self.root.attributes("-topmost", True)
        self.root.after(150, lambda: self.root.attributes("-topmost", False))

    def _setup_theme(self):
        style = ttk.Style(self.root)
        # "default" or "classic" renders reliably on both Tk 8.5 and Tk 8.6 on macOS
        available = style.theme_names()
        style.theme_use("clam" if "clam" in available else "default")

        style.configure("TNotebook", background="#252536", borderwidth=0)
        style.configure("TNotebook.Tab", padding=[10, 5], font=("Menlo", 11, "bold"))
        style.map(
            "TNotebook.Tab",
            background=[("selected", "#89b4fa"), ("!selected", "#313244")],
            foreground=[("selected", "#11111b"), ("!selected", "#cdd6f4")],
        )

    def _build_ui(self):
        self.root.configure(bg="#1e1e2e")

        # --- Top Global Toolbar ---
        top_bar = tk.Frame(self.root, bg="#252536", padx=12, pady=8)
        top_bar.pack(side=tk.TOP, fill=tk.X, padx=12, pady=(12, 6))

        tk.Label(
            top_bar, text="Wireshark Stream & Payload Converter",
            bg="#252536", fg="#cdd6f4", font=("Helvetica", 14, "bold")
        ).pack(side=tk.LEFT)

        tk.Button(top_bar, text="Clear All", command=self.clear_all, padx=10).pack(side=tk.RIGHT, padx=(6, 0))
        tk.Button(top_bar, text="Gunzip Body", command=self.decompress_gzip, padx=10).pack(side=tk.RIGHT, padx=6)
        tk.Button(top_bar, text="Swap Panes", command=self.swap_panes, padx=10).pack(side=tk.RIGHT, padx=6)

        self.ebcdic_var = tk.StringVar(value="cp037")
        cp_menu = tk.OptionMenu(top_bar, self.ebcdic_var, "cp037", "cp500", "cp1047", command=lambda _: self.convert())
        cp_menu.pack(side=tk.RIGHT, padx=(4, 12))
        tk.Label(
            top_bar, text="EBCDIC CP:", bg="#252536", fg="#cdd6f4", font=("Helvetica", 11)
        ).pack(side=tk.RIGHT)

        # --- Bottom Status Bar (pack before expanding middle area) ---
        status_bar = tk.Frame(self.root, bg="#11111b", padx=12, pady=6)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=12, pady=(4, 12))

        self.status_var = tk.StringVar(value="Ready")
        tk.Label(
            status_bar, textvariable=self.status_var, bg="#11111b", fg="#a6adc8",
            font=("Menlo", 11)
        ).pack(side=tk.LEFT)

        # --- Center PanedWindow (Left Input / Right Output) ---
        paned = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, bg="#1e1e2e", sashwidth=8, bd=0)
        paned.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=12, pady=4)

        # LEFT CARD (INPUT)
        left_card = tk.Frame(paned, bg="#252536", padx=10, pady=10)
        left_hdr = tk.Frame(left_card, bg="#252536")
        left_hdr.pack(side=tk.TOP, fill=tk.X, pady=(0, 6))

        tk.Label(
            left_hdr, text="INPUT FORMAT", bg="#252536", fg="#89b4fa",
            font=("Helvetica", 12, "bold")
        ).pack(side=tk.LEFT)

        tk.Button(left_hdr, text="Load File...", command=self.load_file, padx=8).pack(side=tk.RIGHT, padx=(4, 0))
        tk.Button(left_hdr, text="Paste", command=self.paste_clipboard, padx=8).pack(side=tk.RIGHT, padx=4)
        tk.Button(left_hdr, text="Auto-Detect", command=self.auto_detect_input, padx=8).pack(side=tk.RIGHT, padx=4)

        # Native Notebook Tabs for Input Format
        self.in_notebook = ttk.Notebook(left_card)
        self.in_tab_frames = {}
        for fmt in FORMATS:
            tab = tk.Frame(self.in_notebook, bg="#252536", height=1)
            self.in_notebook.add(tab, text=fmt)
            self.in_tab_frames[fmt] = tab
        self.in_notebook.pack(side=tk.TOP, fill=tk.X, pady=(0, 6))
        self.in_notebook.bind("<<NotebookTabChanged>>", self.on_in_tab)

        in_box = tk.Frame(left_card, bg="#181825")
        in_box.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.in_text = tk.Text(
            in_box, wrap=tk.NONE, bg="#181825", fg="#cdd6f4",
            insertbackground="#89b4fa", font=("Menlo", 12), relief=tk.FLAT, padx=10, pady=10, undo=True
        )
        in_sy = tk.Scrollbar(in_box, orient=tk.VERTICAL, command=self.in_text.yview)
        in_sx = tk.Scrollbar(in_box, orient=tk.HORIZONTAL, command=self.in_text.xview)
        self.in_text.configure(yscrollcommand=in_sy.set, xscrollcommand=in_sx.set)
        in_sy.pack(side=tk.RIGHT, fill=tk.Y)
        in_sx.pack(side=tk.BOTTOM, fill=tk.X)
        self.in_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.in_text.bind("<KeyRelease>", lambda _: self.convert())

        # RIGHT CARD (OUTPUT)
        right_card = tk.Frame(paned, bg="#252536", padx=10, pady=10)
        right_hdr = tk.Frame(right_card, bg="#252536")
        right_hdr.pack(side=tk.TOP, fill=tk.X, pady=(0, 6))

        tk.Label(
            right_hdr, text="OUTPUT FORMAT", bg="#252536", fg="#a6e3a1",
            font=("Helvetica", 12, "bold")
        ).pack(side=tk.LEFT)

        tk.Button(right_hdr, text="Save Output...", command=self.save_output, padx=8).pack(side=tk.RIGHT, padx=(4, 0))
        tk.Button(right_hdr, text="Copy Output", command=self.copy_output, padx=8).pack(side=tk.RIGHT, padx=4)

        self.ascii_dots = tk.BooleanVar(value=False)
        tk.Checkbutton(
            right_hdr, text="Dots for non-ASCII", variable=self.ascii_dots,
            bg="#252536", fg="#cdd6f4", selectcolor="#181825", activebackground="#252536",
            font=("Helvetica", 11), command=self.convert
        ).pack(side=tk.RIGHT, padx=8)

        # Native Notebook Tabs for Output Format
        self.out_notebook = ttk.Notebook(right_card)
        self.out_tab_frames = {}
        for fmt in FORMATS:
            tab = tk.Frame(self.out_notebook, bg="#252536", height=1)
            self.out_notebook.add(tab, text=fmt)
            self.out_tab_frames[fmt] = tab
        self.out_notebook.select(self.out_tab_frames["ASCII"])
        self.out_notebook.pack(side=tk.TOP, fill=tk.X, pady=(0, 6))
        self.out_notebook.bind("<<NotebookTabChanged>>", self.on_out_tab)

        out_box = tk.Frame(right_card, bg="#181825")
        out_box.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.out_text = tk.Text(
            out_box, wrap=tk.NONE, bg="#181825", fg="#a6e3a1",
            insertbackground="#a6e3a1", font=("Menlo", 12), relief=tk.FLAT, padx=10, pady=10
        )
        out_sy = tk.Scrollbar(out_box, orient=tk.VERTICAL, command=self.out_text.yview)
        out_sx = tk.Scrollbar(out_box, orient=tk.HORIZONTAL, command=self.out_text.xview)
        self.out_text.configure(yscrollcommand=out_sy.set, xscrollcommand=out_sx.set)
        out_sy.pack(side=tk.RIGHT, fill=tk.Y)
        out_sx.pack(side=tk.BOTTOM, fill=tk.X)
        self.out_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        paned.add(left_card, stretch="always")
        paned.add(right_card, stretch="always")

    def _load_sample(self):
        sample = (
            "char peer0_0[] = { /* Packet 6 */\n"
            "0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54,\n"
            "0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a,\n"
            "0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x68, 0x74,\n"
            "0x74, 0x70, 0x66, 0x6f, 0x72, 0x65, 0x76, 0x65,\n"
            "0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a, 0x0d, 0x0a };"
        )
        self.in_text.insert("1.0", sample)
        self.convert()

    def on_in_tab(self, _event=None):
        idx = self.in_notebook.index(self.in_notebook.select())
        self.in_fmt = FORMATS[idx]
        self.convert()

    def on_out_tab(self, _event=None):
        idx = self.out_notebook.index(self.out_notebook.select())
        self.out_fmt = FORMATS[idx]
        self.convert()

    def convert(self):
        raw_in = self.in_text.get("1.0", "end-1c")
        if not raw_in.strip():
            self.current_bytes = b""
            self.out_text.delete("1.0", tk.END)
            self.status_var.set("Bytes: 0  |  Entropy: 0.00  |  SHA-256: -")
            return

        try:
            data = ConversionEngine.to_bytes(raw_in, self.in_fmt, self.ebcdic_var.get())
            self.current_bytes = data
            rendered = ConversionEngine.from_bytes(
                data, self.out_fmt, self.ebcdic_var.get(), self.ascii_dots.get()
            )
            self.out_text.configure(fg="#a6e3a1")
            self.out_text.delete("1.0", tk.END)
            self.out_text.insert("1.0", rendered)

            entropy = ConversionEngine.shannon_entropy(data)
            ent_hint = " (Likely Encrypted/Compressed)" if entropy > 7.2 else " (Plaintext/Structured)"
            sha_short = hashlib.sha256(data).hexdigest()[:16]
            self.status_var.set(
                f"Bytes: {len(data):,}  |  Entropy: {entropy:.2f}/8.00{ent_hint}  |  SHA-256: {sha_short}..."
            )
        except Exception as exc:
            self.out_text.configure(fg="#f38ba8")
            self.out_text.delete("1.0", tk.END)
            self.out_text.insert("1.0", f"[Conversion Error]\n{exc}")
            self.status_var.set(f"Error: {exc}")

    def auto_detect_input(self):
        raw_in = self.in_text.get("1.0", "end-1c")
        detected = ConversionEngine.auto_detect(raw_in)
        self.in_fmt = detected
        self.in_notebook.select(self.in_tab_frames[detected])
        self.convert()

    def swap_panes(self):
        out_val = self.out_text.get("1.0", "end-1c")
        old_in, old_out = self.in_fmt, self.out_fmt
        self.in_fmt, self.out_fmt = old_out, old_in
        self.in_notebook.select(self.in_tab_frames[old_out])
        self.out_notebook.select(self.out_tab_frames[old_in])
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
                unzipped, self.out_fmt, self.ebcdic_var.get(), self.ascii_dots.get()
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
            self.in_fmt = "Raw"
            self.in_notebook.select(self.in_tab_frames["Raw"])
            self.in_text.delete("1.0", "end")
            self.in_text.insert("1.0", raw_bytes.decode("latin-1"))
            self.convert()

    def save_output(self):
        if self.out_fmt == "Raw":
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
