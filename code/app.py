import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox

from code.engine import ConversionEngine, FORMATS
from code.theme import (
    FONT_MONO,
    FONT_MONO_SMALL,
    FONT_STATUS,
    FONT_TITLE,
    FONT_UI,
    FONT_UI_BOLD,
    NORD,
)


class PacketConverterApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Packet Payload Studio")
        self.root.geometry("1380x850")
        self.root.minsize(1120, 660)
        self.root.configure(bg=NORD["bg_window"])

        self.alpha_var = tk.DoubleVar(value=0.93)
        self._apply_frosted_glass()

        self.current_bytes = b""
        self.in_fmt_var = tk.StringVar(value="C Array")
        self.out_fmt_var = tk.StringVar(value="ASCII")
        self.peer_var = tk.StringVar(value="All Streams")
        self.ebcdic_var = tk.StringVar(value="cp037")
        self.xor_var = tk.StringVar(value="0x55")
        self.search_var = tk.StringVar(value="")
        self.ascii_dots = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="Ready")

        self._build_ui()
        self._bind_shortcuts()
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

    def _bind_shortcuts(self):
        self.root.bind("<Command-f>", lambda _e: self.search_entry.focus_set())
        self.root.bind("<Control-f>", lambda _e: self.search_entry.focus_set())

    def _make_pill(self, parent, text, cmd, bg=NORD["bg_elevated"], fg=NORD["fg_main"], padx=9, pady=4):
        lbl = tk.Label(
            parent, text=text, bg=bg, fg=fg,
            font=FONT_UI_BOLD, padx=padx, pady=pady, cursor="pointinghand"
        )
        lbl.bind("<Button-1>", lambda _e: cmd())
        return lbl

    def _build_ui(self):
        self.root.grid_rowconfigure(2, weight=1)
        self.root.grid_columnconfigure(0, weight=1, uniform="col")
        self.root.grid_columnconfigure(1, weight=1, uniform="col")

        # ================= ROW 0: TOP FROSTED HEADER =================
        top_bar = tk.Frame(
            self.root, bg=NORD["bg_card"], padx=14, pady=9,
            highlightbackground=NORD["border"], highlightthickness=1
        )
        top_bar.grid(row=0, column=0, columnspan=2, sticky="ew", padx=14, pady=(12, 4))

        tk.Label(
            top_bar, text="Packet Payload Studio",
            bg=NORD["bg_card"], fg=NORD["fg_main"], font=FONT_TITLE
        ).pack(side=tk.LEFT)

        self._make_pill(top_bar, "Clear All", self.clear_all, fg=NORD["fg_muted"]).pack(side=tk.RIGHT, padx=(6, 0))
        self._make_pill(top_bar, "Gunzip / Zlib", self.decompress_gzip, fg=NORD["frost_cyan"]).pack(side=tk.RIGHT, padx=6)
        self._make_pill(top_bar, "Swap Panes", self.swap_panes, bg=NORD["frost_blue"], fg=NORD["text_dark"]).pack(side=tk.RIGHT, padx=6)

        # EBCDIC Codepage
        cp_menu = tk.OptionMenu(top_bar, self.ebcdic_var, "cp037", "cp500", "cp1047", command=lambda _: self.convert())
        cp_menu.configure(
            bg=NORD["bg_elevated"], fg=NORD["fg_main"],
            activebackground=NORD["border"], activeforeground=NORD["fg_main"],
            highlightthickness=0, bd=0, font=FONT_STATUS
        )
        cp_menu.pack(side=tk.RIGHT, padx=(4, 12))
        tk.Label(top_bar, text="EBCDIC:", bg=NORD["bg_card"], fg=NORD["fg_muted"], font=FONT_UI).pack(side=tk.RIGHT)

        # Glass Opacity Slider
        opacity_scale = tk.Scale(
            top_bar, from_=0.75, to=1.0, resolution=0.01, orient=tk.HORIZONTAL,
            variable=self.alpha_var, command=self._on_opacity_slide,
            showvalue=False, length=80, sliderlength=14,
            bg=NORD["bg_card"], troughcolor=NORD["bg_editor"], highlightthickness=0, bd=0
        )
        opacity_scale.pack(side=tk.RIGHT, padx=(4, 12))
        tk.Label(top_bar, text="Glass:", bg=NORD["bg_card"], fg=NORD["fg_muted"], font=FONT_UI).pack(side=tk.RIGHT)

        # ================= ROW 1: CYBERCHEF TRANSFORM & SEARCH BAR =================
        tool_bar = tk.Frame(
            self.root, bg=NORD["bg_card"], padx=14, pady=6,
            highlightbackground=NORD["border"], highlightthickness=1
        )
        tool_bar.grid(row=1, column=0, columnspan=2, sticky="ew", padx=14, pady=4)

        tk.Label(tool_bar, text="TRANSFORMS:", bg=NORD["bg_card"], fg=NORD["aurora_yellow"], font=FONT_UI_BOLD).pack(side=tk.LEFT, padx=(0, 8))
        self._make_pill(tool_bar, "B64 Decode", lambda: self.apply_transform("b64_decode"), padx=7, pady=2).pack(side=tk.LEFT, padx=3)
        self._make_pill(tool_bar, "B64 Encode", lambda: self.apply_transform("b64_encode"), padx=7, pady=2).pack(side=tk.LEFT, padx=3)
        self._make_pill(tool_bar, "URL Decode", lambda: self.apply_transform("url_decode"), padx=7, pady=2).pack(side=tk.LEFT, padx=3)
        self._make_pill(tool_bar, "URL Encode", lambda: self.apply_transform("url_encode"), padx=7, pady=2).pack(side=tk.LEFT, padx=3)

        tk.Label(tool_bar, text="XOR Key:", bg=NORD["bg_card"], fg=NORD["fg_muted"], font=FONT_UI).pack(side=tk.LEFT, padx=(12, 4))
        xor_entry = tk.Entry(
            tool_bar, textvariable=self.xor_var, width=8,
            bg=NORD["bg_editor"], fg=NORD["fg_main"], insertbackground=NORD["frost_cyan"],
            highlightbackground=NORD["border"], highlightthickness=1, bd=0, font=FONT_STATUS
        )
        xor_entry.pack(side=tk.LEFT, padx=(0, 4))
        self._make_pill(tool_bar, "Apply XOR", lambda: self.apply_transform("xor"), bg=NORD["frost_blue"], fg=NORD["text_dark"], padx=7, pady=2).pack(side=tk.LEFT)

        # Right-side Output Search (Cmd+F)
        self._make_pill(tool_bar, "Find", self.highlight_search, padx=8, pady=2).pack(side=tk.RIGHT, padx=(4, 0))
        self.search_entry = tk.Entry(
            tool_bar, textvariable=self.search_var, width=20,
            bg=NORD["bg_editor"], fg=NORD["fg_main"], insertbackground=NORD["aurora_green"],
            highlightbackground=NORD["border"], highlightthickness=1, bd=0, font=FONT_STATUS
        )
        self.search_entry.pack(side=tk.RIGHT, padx=4)
        self.search_entry.bind("<Return>", lambda _e: self.highlight_search())
        tk.Label(tool_bar, text="Search Output:", bg=NORD["bg_card"], fg=NORD["fg_muted"], font=FONT_UI).pack(side=tk.RIGHT)

        # ================= ROW 2: LEFT & RIGHT CARDS =================
        left_card = tk.Frame(
            self.root, bg=NORD["bg_card"], padx=12, pady=10,
            highlightbackground=NORD["border"], highlightthickness=1
        )
        left_card.grid(row=2, column=0, sticky="nsew", padx=(14, 7), pady=4)
        left_card.grid_rowconfigure(2, weight=1)
        left_card.grid_columnconfigure(0, weight=1)

        left_top = tk.Frame(left_card, bg=NORD["bg_card"])
        left_top.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        tk.Label(left_top, text="INPUT:", bg=NORD["bg_card"], fg=NORD["frost_cyan"], font=("Helvetica", 12, "bold")).pack(side=tk.LEFT, padx=(0, 6))
        in_menu = tk.OptionMenu(left_top, self.in_fmt_var, *FORMATS, command=lambda _: self.on_format_change())
        in_menu.configure(bg=NORD["bg_elevated"], fg=NORD["fg_main"], activebackground=NORD["border"], highlightthickness=0, bd=0, font=FONT_UI_BOLD, width=8)
        in_menu.pack(side=tk.LEFT)

        peer_menu = tk.OptionMenu(left_top, self.peer_var, "All Streams", "Client (peer0)", "Server (peer1)", command=lambda _: self.convert())
        peer_menu.configure(bg=NORD["bg_elevated"], fg=NORD["frost_cyan"], activebackground=NORD["border"], highlightthickness=0, bd=0, font=FONT_UI, width=11)
        peer_menu.pack(side=tk.LEFT, padx=(6, 0))

        self._make_pill(left_top, "Load / PCAP...", self.load_file, padx=7, pady=3).pack(side=tk.RIGHT, padx=(4, 0))
        self._make_pill(left_top, "Paste", self.paste_clipboard, padx=7, pady=3).pack(side=tk.RIGHT, padx=4)
        self._make_pill(left_top, "Auto-Detect", self.auto_detect_input, bg=NORD["frost_cyan"], fg=NORD["text_dark"], padx=7, pady=3).pack(side=tk.RIGHT, padx=4)

        in_tabs = tk.Frame(left_card, bg=NORD["bg_editor"], padx=3, pady=3)
        in_tabs.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        self.in_pill_btns = {}
        for idx, fmt in enumerate(FORMATS):
            in_tabs.grid_columnconfigure(idx, weight=1, uniform="intab")
            lbl = tk.Label(in_tabs, text=fmt, font=FONT_MONO_SMALL, pady=5, cursor="pointinghand")
            lbl.grid(row=0, column=idx, sticky="ew", padx=1)
            lbl.bind("<Button-1>", lambda _e, f=fmt: self.set_in_format(f))
            self.in_pill_btns[fmt] = lbl

        in_wrap = tk.Frame(left_card, bg=NORD["bg_editor"], highlightbackground=NORD["border"], highlightthickness=1)
        in_wrap.grid(row=2, column=0, sticky="nsew")
        in_wrap.grid_rowconfigure(0, weight=1)
        in_wrap.grid_columnconfigure(0, weight=1)

        self.in_text = tk.Text(
            in_wrap, wrap=tk.NONE, bg=NORD["bg_editor"], fg=NORD["fg_main"],
            insertbackground=NORD["frost_cyan"], selectbackground=NORD["border"],
            font=FONT_MONO, padx=12, pady=10, undo=True, highlightthickness=0, bd=0
        )
        in_sy = tk.Scrollbar(in_wrap, orient=tk.VERTICAL, command=self.in_text.yview)
        in_sx = tk.Scrollbar(in_wrap, orient=tk.HORIZONTAL, command=self.in_text.xview)
        self.in_text.configure(yscrollcommand=in_sy.set, xscrollcommand=in_sx.set)
        self.in_text.grid(row=0, column=0, sticky="nsew")
        in_sy.grid(row=0, column=1, sticky="ns")
        in_sx.grid(row=1, column=0, sticky="ew")
        self.in_text.bind("<KeyRelease>", lambda _: self.convert())

        # RIGHT CARD
        right_card = tk.Frame(
            self.root, bg=NORD["bg_card"], padx=12, pady=10,
            highlightbackground=NORD["border"], highlightthickness=1
        )
        right_card.grid(row=2, column=1, sticky="nsew", padx=(7, 14), pady=4)
        right_card.grid_rowconfigure(2, weight=1)
        right_card.grid_columnconfigure(0, weight=1)

        right_top = tk.Frame(right_card, bg=NORD["bg_card"])
        right_top.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        tk.Label(right_top, text="OUTPUT:", bg=NORD["bg_card"], fg=NORD["aurora_green"], font=("Helvetica", 12, "bold")).pack(side=tk.LEFT, padx=(0, 6))
        out_menu = tk.OptionMenu(right_top, self.out_fmt_var, *FORMATS, command=lambda _: self.on_format_change())
        out_menu.configure(bg=NORD["bg_elevated"], fg=NORD["fg_main"], activebackground=NORD["border"], highlightthickness=0, bd=0, font=FONT_UI_BOLD, width=8)
        out_menu.pack(side=tk.LEFT)

        self._make_pill(right_top, "Save...", self.save_output, padx=7, pady=3).pack(side=tk.RIGHT, padx=(4, 0))
        self._make_pill(right_top, "Copy Output", self.copy_output, bg=NORD["aurora_green"], fg=NORD["text_dark"], padx=7, pady=3).pack(side=tk.RIGHT, padx=4)

        tk.Checkbutton(
            right_top, text="Non-ASCII dots", variable=self.ascii_dots,
            bg=NORD["bg_card"], fg=NORD["fg_muted"], selectcolor=NORD["bg_editor"],
            activebackground=NORD["bg_card"], font=FONT_UI, command=self.convert
        ).pack(side=tk.RIGHT, padx=6)

        out_tabs = tk.Frame(right_card, bg=NORD["bg_editor"], padx=3, pady=3)
        out_tabs.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        self.out_pill_btns = {}
        for idx, fmt in enumerate(FORMATS):
            out_tabs.grid_columnconfigure(idx, weight=1, uniform="outtab")
            lbl = tk.Label(out_tabs, text=fmt, font=FONT_MONO_SMALL, pady=5, cursor="pointinghand")
            lbl.grid(row=0, column=idx, sticky="ew", padx=1)
            lbl.bind("<Button-1>", lambda _e, f=fmt: self.set_out_format(f))
            self.out_pill_btns[fmt] = lbl

        out_wrap = tk.Frame(right_card, bg=NORD["bg_editor"], highlightbackground=NORD["border"], highlightthickness=1)
        out_wrap.grid(row=2, column=0, sticky="nsew")
        out_wrap.grid_rowconfigure(0, weight=1)
        out_wrap.grid_columnconfigure(0, weight=1)

        self.out_text = tk.Text(
            out_wrap, wrap=tk.NONE, bg=NORD["bg_editor"], fg=NORD["aurora_green"],
            insertbackground=NORD["aurora_green"], selectbackground=NORD["border"],
            font=FONT_MONO, padx=12, pady=10, highlightthickness=0, bd=0
        )
        self.out_text.tag_configure("search_hit", background=NORD["aurora_yellow"], foreground=NORD["text_dark"])
        out_sy = tk.Scrollbar(out_wrap, orient=tk.VERTICAL, command=self.out_text.yview)
        out_sx = tk.Scrollbar(out_wrap, orient=tk.HORIZONTAL, command=self.out_text.xview)
        self.out_text.configure(yscrollcommand=out_sy.set, xscrollcommand=out_sx.set)
        self.out_text.grid(row=0, column=0, sticky="nsew")
        out_sy.grid(row=0, column=1, sticky="ns")
        out_sx.grid(row=1, column=0, sticky="ew")

        # ================= ROW 3: STATUS BAR =================
        status_bar = tk.Frame(
            self.root, bg=NORD["bg_card"], padx=14, pady=8,
            highlightbackground=NORD["border"], highlightthickness=1
        )
        status_bar.grid(row=3, column=0, columnspan=2, sticky="ew", padx=14, pady=(4, 12))
        tk.Label(status_bar, textvariable=self.status_var, bg=NORD["bg_card"], fg=NORD["fg_muted"], font=FONT_STATUS).pack(side=tk.LEFT)

        self._highlight_active_pills()

    def _highlight_active_pills(self):
        for fmt, lbl in self.in_pill_btns.items():
            lbl.configure(bg=NORD["frost_cyan"] if fmt == self.in_fmt_var.get() else NORD["bg_elevated"], fg=NORD["text_dark"] if fmt == self.in_fmt_var.get() else NORD["fg_muted"])
        for fmt, lbl in self.out_pill_btns.items():
            lbl.configure(bg=NORD["aurora_green"] if fmt == self.out_fmt_var.get() else NORD["bg_elevated"], fg=NORD["text_dark"] if fmt == self.out_fmt_var.get() else NORD["fg_muted"])

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
        welcome_bytes = b"Welcome to Packet Payload Studio"
        lines = ["char welcome_msg[] = {"]
        for i in range(0, len(welcome_bytes), 8):
            chunk = ", ".join(f"0x{b:02x}" for b in welcome_bytes[i:i + 8])
            comma = "," if i + 8 < len(welcome_bytes) else ""
            lines.append(f"    {chunk}{comma}")
        lines.append("};")
        self.in_text.delete("1.0", tk.END)
        self.in_text.insert("1.0", "\n".join(lines))
        self.convert()

    def _render_bytes(self, data: bytes, prefix_msg: str = ""):
        self.current_bytes = data
        rendered = ConversionEngine.from_bytes(data, self.out_fmt_var.get(), self.ebcdic_var.get(), self.ascii_dots.get())
        self.out_text.configure(fg=NORD["aurora_green"])
        self.out_text.delete("1.0", tk.END)
        self.out_text.insert("1.0", rendered)
        self.highlight_search()

        entropy = ConversionEngine.shannon_entropy(data)
        ent_hint = " (Encrypted/Compressed)" if entropy > 7.2 else " (Plaintext/Structured)"
        sha_short = hashlib.sha256(data).hexdigest()[:16]
        lead = f"{prefix_msg}  |  " if prefix_msg else ""
        self.status_var.set(f"{lead}Bytes: {len(data):,}  |  Entropy: {entropy:.2f}/8.00{ent_hint}  |  SHA-256: {sha_short}...")

    def convert(self):
        raw_in = self.in_text.get("1.0", "end-1c")
        if not raw_in.strip():
            self.current_bytes = b""
            self.out_text.delete("1.0", tk.END)
            self.status_var.set("Bytes: 0  |  Entropy: 0.00  |  SHA-256: -")
            return
        try:
            data = ConversionEngine.to_bytes(raw_in, self.in_fmt_var.get(), self.ebcdic_var.get(), self.peer_var.get())
            self._render_bytes(data)
        except Exception as exc:
            self.out_text.configure(fg=NORD["aurora_red"])
            self.out_text.delete("1.0", tk.END)
            self.out_text.insert("1.0", f"[Conversion Error]\n{exc}")
            self.status_var.set(f"Error: {exc}")

    def apply_transform(self, action: str):
        if not self.current_bytes:
            return
        try:
            transformed = ConversionEngine.transform_bytes(self.current_bytes, action, self.xor_var.get())
            self._render_bytes(transformed, prefix_msg=f"Applied {action}")
        except Exception as exc:
            messagebox.showinfo("Transform", str(exc))

    def highlight_search(self):
        self.out_text.tag_remove("search_hit", "1.0", tk.END)
        query = self.search_var.get()
        if not query:
            return
        start = "1.0"
        count = 0
        while True:
            pos = self.out_text.search(query, start, stopindex=tk.END, nocase=True)
            if not pos:
                break
            end = f"{pos}+{len(query)}c"
            self.out_text.tag_add("search_hit", pos, end)
            if count == 0:
                self.out_text.see(pos)
            count += 1
            start = end

    def auto_detect_input(self):
        detected = ConversionEngine.auto_detect(self.in_text.get("1.0", "end-1c"))
        self.in_fmt_var.set(detected)
        self.on_format_change()

    def swap_panes(self):
        out_val = self.out_text.get("1.0", "end-1c")
        old_in, old_out = self.in_fmt_var.get(), self.out_fmt_var.get()
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
            self._render_bytes(unzipped, prefix_msg="Decompressed")
        except Exception as exc:
            messagebox.showinfo("Gunzip / Zlib", str(exc))

    def paste_clipboard(self):
        try:
            clip = self.root.clipboard_get()
            self.in_text.delete("1.0", tk.END)
            self.in_text.insert("1.0", clip)
            self.auto_detect_input()
        except tk.TclError:
            messagebox.showwarning("Clipboard", "Clipboard is empty or contains non-text data.")

    def copy_output(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.out_text.get("1.0", "end-1c"))
        self.status_var.set("Copied output to clipboard.")

    def load_file(self):
        path = filedialog.askopenfilename(title="Open Stream, Binary, or .pcap File")
        if not path:
            return
        with open(path, "rb") as f:
            raw_bytes = f.read()
        if path.lower().endswith(".pcap"):
            try:
                extracted = ConversionEngine.extract_pcap_payloads(raw_bytes)
                self.in_fmt_var.set("Raw")
                self._highlight_active_pills()
                self.in_text.delete("1.0", tk.END)
                self.in_text.insert("1.0", extracted.decode("latin-1"))
                self._render_bytes(extracted, prefix_msg="PCAP TCP/UDP Extracted")
                return
            except Exception as exc:
                messagebox.showerror("PCAP Error", str(exc))
                return
        try:
            text_val = raw_bytes.decode("utf-8")
            self.in_text.delete("1.0", tk.END)
            self.in_text.insert("1.0", text_val)
            self.auto_detect_input()
        except UnicodeDecodeError:
            self.in_fmt_var.set("Raw")
            self._highlight_active_pills()
            self.in_text.delete("1.0", tk.END)
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
