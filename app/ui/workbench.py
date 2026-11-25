import hashlib
import json
import os
import tkinter as tk
from tkinter import filedialog, messagebox

from app.core.pipeline import OPERATIONS, TransformationPipeline
from app.pcap.reassembler import FlowStream, parse_capture_flows
from app.protocols.inspector import analyze_payload
from code.engine import ConversionEngine, FORMATS
from code.theme import (
    FONT_FAMILY_MONO,
    FONT_MONO,
    FONT_MONO_SMALL,
    FONT_STATUS,
    FONT_TITLE,
    FONT_UI,
    FONT_UI_BOLD,
    THEMES,
)

PREFS_PATH = os.path.expanduser("~/.packet_payload_studio.json")


class PacketWorkbenchApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Packet Payload Studio — Network Analysis & Transformation Workbench")
        self.root.geometry("1520x900")
        self.root.minsize(1240, 720)

        prefs = self._load_prefs()
        self.theme_name_var = tk.StringVar(value=prefs.get("theme", "Nord Frost (Dark)"))
        if self.theme_name_var.get() not in THEMES:
            self.theme_name_var.set("Nord Frost (Dark)")
        self.colors = THEMES[self.theme_name_var.get()].copy()

        self.alpha_var = tk.DoubleVar(value=float(prefs.get("alpha", 0.96)))
        self.font_size_var = tk.IntVar(value=int(prefs.get("font_size", 12)))
        self.wrap_var = tk.BooleanVar(value=bool(prefs.get("word_wrap", False)))

        self.pipeline = TransformationPipeline()
        self.flows: dict[str, FlowStream] = {}
        self.raw_input_bytes = b""
        self.output_bytes = b""
        self.settings_win = None
        self._pill_registry = []

        self.in_fmt_var = tk.StringVar(value="C Array")
        self.out_fmt_var = tk.StringVar(value="ASCII")
        self.peer_var = tk.StringVar(value="All Streams")
        self.flow_var = tk.StringVar(value="No PCAP Loaded")
        self.op_search_var = tk.StringVar(value="")
        self.op_param_var = tk.StringVar(value="")
        self.search_var = tk.StringVar(value="")
        self.ascii_dots = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="Ready")

        self._build_menubar()
        self._build_ui()
        self.apply_alpha(self.alpha_var.get())
        self.apply_theme(self.theme_name_var.get(), save=False)

        self.root.bind("<Command-f>", lambda _e: self.search_entry.focus_set())
        self.root.bind("<Control-f>", lambda _e: self.search_entry.focus_set())
        self.root.bind("<Command-comma>", lambda _e: self.open_settings_dialog())
        self.root.bind("<Control-comma>", lambda _e: self.open_settings_dialog())
        self._load_sample()

    def _load_prefs(self) -> dict:
        try:
            if os.path.exists(PREFS_PATH):
                with open(PREFS_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_prefs(self):
        try:
            with open(PREFS_PATH, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "theme": self.theme_name_var.get(),
                        "alpha": round(float(self.alpha_var.get()), 2),
                        "font_size": int(self.font_size_var.get()),
                        "word_wrap": bool(self.wrap_var.get()),
                    },
                    f,
                    indent=2,
                )
        except Exception:
            pass

    def apply_alpha(self, val=None):
        alpha = max(0.55, min(1.0, float(val if val is not None else self.alpha_var.get())))
        self.alpha_var.set(round(alpha, 2))
        try:
            self.root.wm_attributes("-alpha", alpha)
        except tk.TclError:
            pass
        self._save_prefs()

    def _build_menubar(self):
        self.menubar = tk.Menu(self.root)

        file_menu = tk.Menu(self.menubar, tearoff=0)
        file_menu.add_command(label="Open PCAP / PCAPNG / File...", command=self.load_file)
        file_menu.add_command(label="Save Output...", command=self.save_output)
        file_menu.add_separator()
        file_menu.add_command(label="Load Recipe JSON...", command=self.load_recipe)
        file_menu.add_command(label="Save Recipe JSON...", command=self.save_recipe)
        file_menu.add_separator()
        file_menu.add_command(label="Clear All", command=self.clear_all)
        self.menubar.add_cascade(label="File", menu=file_menu)

        settings_menu = tk.Menu(self.menubar, tearoff=0)
        settings_menu.add_command(label="Transparency & Theme Settings...", command=self.open_settings_dialog)
        settings_menu.add_separator()
        theme_sub = tk.Menu(settings_menu, tearoff=0)
        for tname in THEMES:
            theme_sub.add_radiobutton(
                label=tname,
                variable=self.theme_name_var,
                value=tname,
                command=lambda tn=tname: self.apply_theme(tn),
            )
        settings_menu.add_cascade(label="Color Theme", menu=theme_sub)

        alpha_sub = tk.Menu(settings_menu, tearoff=0)
        for pct in (100, 95, 90, 85, 75):
            alpha_sub.add_command(label=f"{pct}% Opacity", command=lambda p=pct / 100.0: self.apply_alpha(p))
        settings_menu.add_cascade(label="Quick Transparency", menu=alpha_sub)
        settings_menu.add_checkbutton(label="Wrap Long Lines", variable=self.wrap_var, command=self._apply_editor_prefs)
        self.menubar.add_cascade(label="Settings", menu=settings_menu)

        presets_menu = tk.Menu(self.menubar, tearoff=0)
        presets_menu.add_command(
            label="Base64 -> GZIP -> JSON Beautify",
            command=lambda: self._load_preset(["Base64 Decode", "GZIP Decompress", "JSON Beautify"]),
        )
        presets_menu.add_command(
            label="Auto Decompress -> JSON Beautify",
            command=lambda: self._load_preset(["Auto Decompress (Gzip/Zlib/BZ2/XZ)", "JSON Beautify"]),
        )
        presets_menu.add_command(
            label="Double URL Decode -> HTML Entity Decode",
            command=lambda: self._load_preset(["Double URL Decode", "HTML Entity Decode"]),
        )
        presets_menu.add_command(
            label="Full Cryptographic Hash & Checksum Report",
            command=lambda: self._load_preset(["Hash & Checksum Report (Param = HMAC Key)"]),
        )
        self.menubar.add_cascade(label="Recipes", menu=presets_menu)

        self.root.config(menu=self.menubar)

    def _load_preset(self, step_names: list[str]):
        self.pipeline.steps.clear()
        for name in step_names:
            self.pipeline.add_step(name)
        self.run_all()

    def _pill(self, parent, text, cmd, role="neutral", padx=8, pady=3):
        lbl = tk.Label(parent, text=text, font=FONT_UI_BOLD, padx=padx, pady=pady, cursor="pointinghand")
        lbl.bind("<Button-1>", lambda _e: cmd())
        self._pill_registry.append((lbl, role))
        return lbl

    def _build_ui(self):
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=5, uniform="pane")
        self.root.grid_columnconfigure(1, weight=4, uniform="pane")
        self.root.grid_columnconfigure(2, weight=5, uniform="pane")

        # TOP BAR
        self.top_bar = tk.Frame(self.root, padx=14, pady=8, highlightthickness=1)
        self.top_bar.grid(row=0, column=0, columnspan=3, sticky="ew", padx=12, pady=(10, 4))
        self.title_lbl = tk.Label(self.top_bar, text="Packet Payload Studio", font=FONT_TITLE)
        self.title_lbl.pack(side=tk.LEFT)
        self.subtitle_lbl = tk.Label(self.top_bar, text="  |  Network Analysis & Transformation Workbench", font=FONT_UI)
        self.subtitle_lbl.pack(side=tk.LEFT)

        self._pill(self.top_bar, "Clear All", self.clear_all, role="muted").pack(side=tk.RIGHT, padx=(6, 0))
        self._pill(self.top_bar, "Swap Panes", self.swap_panes, role="blue").pack(side=tk.RIGHT, padx=6)
        self._pill(self.top_bar, "Settings", self.open_settings_dialog, role="cyan").pack(side=tk.RIGHT, padx=4)
        self._pill(self.top_bar, "Save Recipe", self.save_recipe, role="neutral").pack(side=tk.RIGHT, padx=4)
        self._pill(self.top_bar, "Load Recipe", self.load_recipe, role="neutral").pack(side=tk.RIGHT, padx=4)

        # ================= PANEL 1: INPUT & PCAP FLOW EXPLORER =================
        self.p1 = tk.Frame(self.root, padx=10, pady=8, highlightthickness=1)
        self.p1.grid(row=1, column=0, sticky="nsew", padx=(12, 5), pady=4)
        self.p1.grid_rowconfigure(3, weight=1)
        self.p1.grid_columnconfigure(0, weight=1)

        self.p1_hdr = tk.Frame(self.p1)
        self.p1_hdr.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        self.p1_title = tk.Label(self.p1_hdr, text="1. INPUT & FLOWS", font=FONT_UI_BOLD)
        self.p1_title.pack(side=tk.LEFT)
        self._pill(self.p1_hdr, "Open PCAP / File...", self.load_file, role="neutral").pack(side=tk.RIGHT, padx=(4, 0))
        self._pill(self.p1_hdr, "Auto", self.auto_detect_input, role="cyan").pack(side=tk.RIGHT, padx=4)

        self.p1_ctl = tk.Frame(self.p1)
        self.p1_ctl.grid(row=1, column=0, sticky="ew", pady=(0, 6))
        self.in_menu = tk.OptionMenu(self.p1_ctl, self.in_fmt_var, *FORMATS, command=lambda _: self.run_all())
        self.in_menu.configure(highlightthickness=0, bd=0, font=FONT_UI_BOLD, width=8)
        self.in_menu.pack(side=tk.LEFT)

        self.peer_menu = tk.OptionMenu(self.p1_ctl, self.peer_var, "All Streams", "Client (peer0)", "Server (peer1)", command=lambda _: self.run_all())
        self.peer_menu.configure(highlightthickness=0, bd=0, font=FONT_UI, width=11)
        self.peer_menu.pack(side=tk.LEFT, padx=4)

        self.flow_menu = tk.OptionMenu(self.p1_ctl, self.flow_var, "No PCAP Loaded")
        self.flow_menu.configure(highlightthickness=0, bd=0, font=FONT_MONO_SMALL)
        self.flow_menu.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.intel_box = tk.Label(
            self.p1, text="Protocol: Detecting...", justify=tk.LEFT, anchor="w",
            font=FONT_MONO_SMALL, padx=8, pady=6, highlightthickness=1
        )
        self.intel_box.grid(row=2, column=0, sticky="ew", pady=(0, 6))

        self.in_wrap = tk.Frame(self.p1, highlightthickness=1)
        self.in_wrap.grid(row=3, column=0, sticky="nsew")
        self.in_wrap.grid_rowconfigure(0, weight=1)
        self.in_wrap.grid_columnconfigure(0, weight=1)
        self.in_text = tk.Text(self.in_wrap, wrap=tk.NONE, font=FONT_MONO, padx=10, pady=8, undo=True, bd=0, highlightthickness=0)
        sy1 = tk.Scrollbar(self.in_wrap, orient=tk.VERTICAL, command=self.in_text.yview)
        sx1 = tk.Scrollbar(self.in_wrap, orient=tk.HORIZONTAL, command=self.in_text.xview)
        self.in_text.configure(yscrollcommand=sy1.set, xscrollcommand=sx1.set)
        self.in_text.grid(row=0, column=0, sticky="nsew")
        sy1.grid(row=0, column=1, sticky="ns")
        sx1.grid(row=1, column=0, sticky="ew")
        self.in_text.bind("<KeyRelease>", lambda _: self.run_all())

        # ================= PANEL 2: CYBERCHEF RECIPE PIPELINE =================
        self.p2 = tk.Frame(self.root, padx=10, pady=8, highlightthickness=1)
        self.p2.grid(row=1, column=1, sticky="nsew", padx=5, pady=4)
        self.p2.grid_rowconfigure(2, weight=1)
        self.p2.grid_rowconfigure(5, weight=1)
        self.p2.grid_columnconfigure(0, weight=1)

        self.p2_hdr = tk.Frame(self.p2)
        self.p2_hdr.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        self.p2_title = tk.Label(self.p2_hdr, text="2. TRANSFORMATION PIPELINE", font=FONT_UI_BOLD)
        self.p2_title.pack(side=tk.LEFT)
        self._pill(self.p2_hdr, "Clear Recipe", self.clear_recipe, role="muted").pack(side=tk.RIGHT)

        self.search_bar = tk.Frame(self.p2)
        self.search_bar.grid(row=1, column=0, sticky="ew", pady=(0, 4))
        self.filter_lbl = tk.Label(self.search_bar, text="Filter Ops:", font=FONT_UI)
        self.filter_lbl.pack(side=tk.LEFT)
        self.op_search = tk.Entry(self.search_bar, textvariable=self.op_search_var, font=FONT_STATUS, bd=0, highlightthickness=1)
        self.op_search.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        self.op_search.bind("<KeyRelease>", lambda _: self._refresh_op_catalog())

        self.op_listbox = tk.Listbox(self.p2, font=FONT_STATUS, bd=0, highlightthickness=1, height=9)
        self.op_listbox.grid(row=2, column=0, sticky="nsew", pady=(0, 6))
        self.op_listbox.bind("<Double-Button-1>", lambda _e: self.add_selected_op())

        self.param_row = tk.Frame(self.p2)
        self.param_row.grid(row=3, column=0, sticky="ew", pady=(0, 8))
        self.param_lbl = tk.Label(self.param_row, text="Param:", font=FONT_UI)
        self.param_lbl.pack(side=tk.LEFT)
        self.param_entry = tk.Entry(self.param_row, textvariable=self.op_param_var, width=14, font=FONT_STATUS, bd=0, highlightthickness=1)
        self.param_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        self._pill(self.param_row, "+ Add Step", self.add_selected_op, role="green").pack(side=tk.RIGHT)

        self.rec_hdr = tk.Frame(self.p2)
        self.rec_hdr.grid(row=4, column=0, sticky="ew", pady=(0, 4))
        self.rec_title = tk.Label(self.rec_hdr, text="ACTIVE RECIPE STEPS:", font=FONT_UI_BOLD)
        self.rec_title.pack(side=tk.LEFT)
        self._pill(self.rec_hdr, "Remove", self.remove_step, role="red", padx=6, pady=2).pack(side=tk.RIGHT, padx=(3, 0))
        self._pill(self.rec_hdr, "Toggle", self.toggle_step, role="neutral", padx=6, pady=2).pack(side=tk.RIGHT, padx=3)
        self._pill(self.rec_hdr, "Down", lambda: self.move_step(1), role="neutral", padx=6, pady=2).pack(side=tk.RIGHT, padx=3)
        self._pill(self.rec_hdr, "Up", lambda: self.move_step(-1), role="neutral", padx=6, pady=2).pack(side=tk.RIGHT, padx=3)

        self.recipe_listbox = tk.Listbox(self.p2, font=FONT_STATUS, bd=0, highlightthickness=1, height=8)
        self.recipe_listbox.grid(row=5, column=0, sticky="nsew")

        # ================= PANEL 3: INSPECTOR & OUTPUT =================
        self.p3 = tk.Frame(self.root, padx=10, pady=8, highlightthickness=1)
        self.p3.grid(row=1, column=2, sticky="nsew", padx=(5, 12), pady=4)
        self.p3.grid_rowconfigure(2, weight=1)
        self.p3.grid_columnconfigure(0, weight=1)

        self.p3_hdr = tk.Frame(self.p3)
        self.p3_hdr.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        self.p3_title = tk.Label(self.p3_hdr, text="3. INSPECTOR OUTPUT", font=FONT_UI_BOLD)
        self.p3_title.pack(side=tk.LEFT)
        self._pill(self.p3_hdr, "Save...", self.save_output, role="neutral").pack(side=tk.RIGHT, padx=(4, 0))
        self._pill(self.p3_hdr, "Copy", self.copy_output, role="green").pack(side=tk.RIGHT, padx=4)

        self.p3_ctl = tk.Frame(self.p3)
        self.p3_ctl.grid(row=1, column=0, sticky="ew", pady=(0, 6))
        self.out_menu = tk.OptionMenu(self.p3_ctl, self.out_fmt_var, *FORMATS, command=lambda _: self.run_all())
        self.out_menu.configure(highlightthickness=0, bd=0, font=FONT_UI_BOLD, width=8)
        self.out_menu.pack(side=tk.LEFT)

        self.dots_chk = tk.Checkbutton(self.p3_ctl, text="Dots", variable=self.ascii_dots, font=FONT_UI, command=self.run_all)
        self.dots_chk.pack(side=tk.LEFT, padx=6)

        self._pill(self.p3_ctl, "Find", self.highlight_search, role="neutral", padx=6, pady=2).pack(side=tk.RIGHT)
        self.search_entry = tk.Entry(self.p3_ctl, textvariable=self.search_var, width=14, font=FONT_STATUS, bd=0, highlightthickness=1)
        self.search_entry.pack(side=tk.RIGHT, padx=4)
        self.search_entry.bind("<Return>", lambda _e: self.highlight_search())

        self.out_wrap = tk.Frame(self.p3, highlightthickness=1)
        self.out_wrap.grid(row=2, column=0, sticky="nsew")
        self.out_wrap.grid_rowconfigure(0, weight=1)
        self.out_wrap.grid_columnconfigure(0, weight=1)
        self.out_text = tk.Text(self.out_wrap, wrap=tk.NONE, font=FONT_MONO, padx=10, pady=8, bd=0, highlightthickness=0)
        sy3 = tk.Scrollbar(self.out_wrap, orient=tk.VERTICAL, command=self.out_text.yview)
        sx3 = tk.Scrollbar(self.out_wrap, orient=tk.HORIZONTAL, command=self.out_text.xview)
        self.out_text.configure(yscrollcommand=sy3.set, xscrollcommand=sx3.set)
        self.out_text.grid(row=0, column=0, sticky="nsew")
        sy3.grid(row=0, column=1, sticky="ns")
        sx3.grid(row=1, column=0, sticky="ew")

        # STATUS BAR
        self.status_bar = tk.Frame(self.root, padx=14, pady=6, highlightthickness=1)
        self.status_bar.grid(row=2, column=0, columnspan=3, sticky="ew", padx=12, pady=(4, 10))
        self.status_lbl = tk.Label(self.status_bar, textvariable=self.status_var, font=FONT_STATUS)
        self.status_lbl.pack(side=tk.LEFT)

        self._refresh_op_catalog()

    def apply_theme(self, theme_name: str | None = None, save: bool = True):
        if theme_name and theme_name in THEMES:
            self.theme_name_var.set(theme_name)
        c = THEMES[self.theme_name_var.get()].copy()
        self.colors = c

        self.root.configure(bg=c["bg_window"])

        # Cards & Headers
        for card in (self.top_bar, self.p1, self.p2, self.p3, self.status_bar):
            card.configure(bg=c["bg_card"], highlightbackground=c["border"])
        for sub in (self.p1_hdr, self.p1_ctl, self.p2_hdr, self.search_bar, self.param_row, self.rec_hdr, self.p3_hdr, self.p3_ctl):
            sub.configure(bg=c["bg_card"])

        self.title_lbl.configure(bg=c["bg_card"], fg=c["fg_main"])
        self.subtitle_lbl.configure(bg=c["bg_card"], fg=c["frost_cyan"])
        self.p1_title.configure(bg=c["bg_card"], fg=c["frost_cyan"])
        self.p2_title.configure(bg=c["bg_card"], fg=c["aurora_yellow"])
        self.rec_title.configure(bg=c["bg_card"], fg=c["frost_cyan"])
        self.p3_title.configure(bg=c["bg_card"], fg=c["aurora_green"])
        self.filter_lbl.configure(bg=c["bg_card"], fg=c["fg_muted"])
        self.param_lbl.configure(bg=c["bg_card"], fg=c["fg_muted"])
        self.status_lbl.configure(bg=c["bg_card"], fg=c["fg_muted"])
        self.dots_chk.configure(bg=c["bg_card"], fg=c["fg_main"], selectcolor=c["bg_editor"], activebackground=c["bg_card"], activeforeground=c["fg_main"])

        # Pill buttons
        role_styles = {
            "neutral": (c["bg_elevated"], c["fg_main"]),
            "muted": (c["bg_elevated"], c["fg_muted"]),
            "cyan": (c["frost_cyan"], c["text_dark"]),
            "blue": (c["frost_blue"], c["text_dark"]),
            "green": (c["aurora_green"], c["text_dark"]),
            "red": (c["bg_elevated"], c["aurora_red"]),
        }
        for lbl, role in self._pill_registry:
            bg, fg = role_styles.get(role, (c["bg_elevated"], c["fg_main"]))
            lbl.configure(bg=bg, fg=fg)

        # OptionMenus
        for om, fg_key in ((self.in_menu, "fg_main"), (self.peer_menu, "frost_cyan"), (self.flow_menu, "aurora_yellow"), (self.out_menu, "fg_main")):
            om.configure(bg=c["bg_elevated"], fg=c[fg_key], activebackground=c["select_bg"], activeforeground=c["select_fg"])
            om["menu"].configure(bg=c["bg_elevated"], fg=c["fg_main"], activebackground=c["select_bg"], activeforeground=c["select_fg"])

        # Intel box, Editors, Entries, Listboxes
        self.intel_box.configure(bg=c["bg_editor"], fg=c["fg_main"], highlightbackground=c["border"])
        for wrap in (self.in_wrap, self.out_wrap):
            wrap.configure(bg=c["bg_editor"], highlightbackground=c["border"])

        self.in_text.configure(bg=c["bg_editor"], fg=c["fg_main"], insertbackground=c["frost_cyan"], selectbackground=c["select_bg"], selectforeground=c["select_fg"])
        self.out_text.configure(bg=c["bg_editor"], fg=c["aurora_green"], insertbackground=c["aurora_green"], selectbackground=c["select_bg"], selectforeground=c["select_fg"])
        self.out_text.tag_configure("search_hit", background=c["aurora_yellow"], foreground=c["text_dark"])

        for ent in (self.op_search, self.param_entry, self.search_entry):
            ent.configure(bg=c["bg_editor"], fg=c["fg_main"], insertbackground=c["frost_cyan"], highlightbackground=c["border"])

        self.op_listbox.configure(bg=c["bg_editor"], fg=c["fg_main"], selectbackground=c["select_bg"], selectforeground=c["select_fg"], highlightbackground=c["border"])
        self.recipe_listbox.configure(bg=c["bg_editor"], fg=c["aurora_yellow"], selectbackground=c["select_bg"], selectforeground=c["select_fg"], highlightbackground=c["border"])

        if self.settings_win and self.settings_win.winfo_exists():
            self._paint_settings_dialog()

        if save:
            self._save_prefs()

    def _apply_editor_prefs(self):
        sz = max(9, min(20, int(self.font_size_var.get())))
        wrap_mode = tk.WORD if self.wrap_var.get() else tk.NONE
        mono = (FONT_FAMILY_MONO, sz)
        self.in_text.configure(font=mono, wrap=wrap_mode)
        self.out_text.configure(font=mono, wrap=wrap_mode)
        self._save_prefs()

    def open_settings_dialog(self):
        if self.settings_win and self.settings_win.winfo_exists():
            self.settings_win.lift()
            return

        win = tk.Toplevel(self.root)
        win.title("Workspace Settings — Live 3-Panel Preview")
        win.geometry("420x360+40+60")
        win.resizable(False, False)
        win.transient(self.root)
        self.settings_win = win

        self.set_body = tk.Frame(win, padx=18, pady=14)
        self.set_body.pack(fill=tk.BOTH, expand=True)

        self.set_hdr = tk.Label(self.set_body, text="Appearance & Live Preview", font=FONT_TITLE)
        self.set_hdr.pack(anchor="w")
        self.set_sub = tk.Label(self.set_body, text="Adjust transparency or theme while viewing the 3-panel workspace behind.", font=FONT_UI, wraplength=380, justify=tk.LEFT)
        self.set_sub.pack(anchor="w", pady=(2, 12))

        # Transparency Slider
        self.alpha_lbl = tk.Label(self.set_body, text=f"Window Transparency: {int(self.alpha_var.get() * 100)}%", font=FONT_UI_BOLD)
        self.alpha_lbl.pack(anchor="w")

        def on_slide(val):
            v = float(val)
            self.alpha_lbl.configure(text=f"Window Transparency: {int(v * 100)}%")
            self.apply_alpha(v)

        self.alpha_slider = tk.Scale(
            self.set_body, from_=0.60, to=1.00, resolution=0.01,
            orient=tk.HORIZONTAL, variable=self.alpha_var, showvalue=False,
            command=on_slide, highlightthickness=0, bd=0
        )
        self.alpha_slider.pack(fill=tk.X, pady=(4, 14))

        # Theme Selector
        self.theme_lbl = tk.Label(self.set_body, text="Color Theme:", font=FONT_UI_BOLD)
        self.theme_lbl.pack(anchor="w", pady=(0, 4))
        self.theme_radios = []
        for tname in THEMES:
            rb = tk.Radiobutton(
                self.set_body, text=tname, variable=self.theme_name_var, value=tname,
                font=FONT_UI, command=lambda tn=tname: self.apply_theme(tn)
            )
            rb.pack(anchor="w", pady=2)
            self.theme_radios.append(rb)

        # Font Size Slider
        self.font_lbl = tk.Label(self.set_body, text=f"Editor Font Size: {self.font_size_var.get()} pt", font=FONT_UI_BOLD)
        self.font_lbl.pack(anchor="w", pady=(12, 0))

        def on_font(val):
            sz = int(float(val))
            self.font_lbl.configure(text=f"Editor Font Size: {sz} pt")
            self._apply_editor_prefs()

        self.font_slider = tk.Scale(
            self.set_body, from_=10, to=18, resolution=1,
            orient=tk.HORIZONTAL, variable=self.font_size_var, showvalue=False,
            command=on_font, highlightthickness=0, bd=0
        )
        self.font_slider.pack(fill=tk.X, pady=(4, 12))

        close_btn = tk.Button(self.set_body, text="Done", font=FONT_UI_BOLD, padx=14, pady=4, command=win.destroy)
        close_btn.pack(anchor="e")
        self.set_close_btn = close_btn

        self._paint_settings_dialog()

    def _paint_settings_dialog(self):
        c = self.colors
        self.settings_win.configure(bg=c["bg_card"])
        self.set_body.configure(bg=c["bg_card"])
        self.set_hdr.configure(bg=c["bg_card"], fg=c["fg_main"])
        self.set_sub.configure(bg=c["bg_card"], fg=c["fg_muted"])
        self.alpha_lbl.configure(bg=c["bg_card"], fg=c["frost_cyan"])
        self.theme_lbl.configure(bg=c["bg_card"], fg=c["frost_cyan"])
        self.font_lbl.configure(bg=c["bg_card"], fg=c["frost_cyan"])
        self.alpha_slider.configure(bg=c["bg_card"], troughcolor=c["bg_elevated"], activebackground=c["frost_cyan"])
        self.font_slider.configure(bg=c["bg_card"], troughcolor=c["bg_elevated"], activebackground=c["frost_cyan"])
        for rb in self.theme_radios:
            rb.configure(bg=c["bg_card"], fg=c["fg_main"], selectcolor=c["bg_editor"], activebackground=c["bg_card"], activeforeground=c["fg_main"])
        self.set_close_btn.configure(bg=c["bg_elevated"], fg=c["fg_main"])

    def _refresh_op_catalog(self):
        q = self.op_search_var.get().strip().lower()
        self.op_listbox.delete(0, tk.END)
        for name, (cat, _fn) in OPERATIONS.items():
            label = f"[{cat}] {name}"
            if not q or q in label.lower():
                self.op_listbox.insert(tk.END, name)

    def _refresh_recipe_box(self, trace: list[str] | None = None):
        self.recipe_listbox.delete(0, tk.END)
        for idx, step in enumerate(self.pipeline.steps):
            if trace and idx < len(trace):
                line = trace[idx]
            else:
                state = "ON" if step.enabled else "OFF"
                line = f"{idx + 1:02d}. [{state}] {step.op_name}"
            if step.param:
                line += f"  (param={step.param})"
            self.recipe_listbox.insert(tk.END, line)

    def add_selected_op(self):
        sel = self.op_listbox.curselection()
        if not sel:
            return
        op_name = self.op_listbox.get(sel[0])
        self.pipeline.add_step(op_name, self.op_param_var.get().strip())
        self.run_all()

    def remove_step(self):
        sel = self.recipe_listbox.curselection()
        if sel and 0 <= sel[0] < len(self.pipeline.steps):
            self.pipeline.steps.pop(sel[0])
            self.run_all()

    def toggle_step(self):
        sel = self.recipe_listbox.curselection()
        if sel and 0 <= sel[0] < len(self.pipeline.steps):
            st = self.pipeline.steps[sel[0]]
            st.enabled = not st.enabled
            self.run_all()

    def move_step(self, delta: int):
        sel = self.recipe_listbox.curselection()
        if not sel:
            return
        i = sel[0]
        j = i + delta
        if 0 <= j < len(self.pipeline.steps):
            self.pipeline.steps[i], self.pipeline.steps[j] = self.pipeline.steps[j], self.pipeline.steps[i]
            self.run_all()
            self.recipe_listbox.selection_set(j)

    def clear_recipe(self):
        self.pipeline.steps.clear()
        self.run_all()

    def save_recipe(self):
        path = filedialog.asksaveasfilename(title="Save Recipe JSON", initialdir="recipes", defaultextension=".json")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.pipeline.to_json())
            self.status_var.set(f"Saved recipe to {path}")

    def load_recipe(self):
        path = filedialog.askopenfilename(title="Load Recipe JSON", initialdir="recipes")
        if path:
            with open(path, "r", encoding="utf-8") as f:
                self.pipeline.load_json(f.read())
            self.run_all()

    def _load_sample(self):
        welcome = b"Welcome to Packet Payload Studio"
        lines = ["char welcome_msg[] = {"]
        for i in range(0, len(welcome), 8):
            chunk = ", ".join(f"0x{b:02x}" for b in welcome[i:i + 8])
            lines.append(f"    {chunk}{',' if i + 8 < len(welcome) else ''}")
        lines.append("};")
        self.in_text.delete("1.0", tk.END)
        self.in_text.insert("1.0", "\n".join(lines))
        self.run_all()

    def run_all(self):
        raw_in = self.in_text.get("1.0", "end-1c")
        if not raw_in.strip():
            self.raw_input_bytes = b""
            self.output_bytes = b""
            self.out_text.delete("1.0", tk.END)
            self._refresh_recipe_box()
            return
        try:
            self.raw_input_bytes = ConversionEngine.to_bytes(raw_in, self.in_fmt_var.get(), "cp037", self.peer_var.get())
            intel = analyze_payload(self.raw_input_bytes)
            note_txt = f" | {intel['notes'][0]}" if intel["notes"] else ""
            sugg_txt = f" | Suggested: {', '.join(intel['suggestions'])}" if intel["suggestions"] else ""
            self.intel_box.configure(text=f"Detected: {intel['protocol']} ({intel['confidence']}%) | Entropy: {intel['entropy']:.2f}{note_txt}{sugg_txt}")

            self.output_bytes, trace = self.pipeline.execute(self.raw_input_bytes)
            self._refresh_recipe_box(trace)

            rendered = ConversionEngine.from_bytes(self.output_bytes, self.out_fmt_var.get(), "cp037", self.ascii_dots.get())
            self.out_text.configure(fg=self.colors["aurora_green"])
            self.out_text.delete("1.0", tk.END)
            self.out_text.insert("1.0", rendered)
            self.highlight_search()

            sha_short = hashlib.sha256(self.output_bytes).hexdigest()[:16]
            self.status_var.set(f"In: {len(self.raw_input_bytes):,} B  ->  Out: {len(self.output_bytes):,} B  |  Steps: {len(self.pipeline.steps)}  |  SHA-256: {sha_short}...")
        except Exception as exc:
            self.out_text.configure(fg=self.colors["aurora_red"])
            self.out_text.delete("1.0", tk.END)
            self.out_text.insert("1.0", f"[Pipeline / Parse Error]\n{exc}")
            self.status_var.set(f"Error: {exc}")

    def _select_flow(self, flow_key: str):
        self.flow_var.set(flow_key)
        flow = self.flows.get(flow_key)
        if not flow:
            return
        payload = flow.reconstructed_bytes()
        self.in_fmt_var.set("Raw")
        self.in_text.delete("1.0", tk.END)
        self.in_text.insert("1.0", payload.decode("latin-1"))
        self.run_all()
        self.status_var.set(f"Loaded {flow_key} ({flow.packet_count} pkts, {flow.retransmissions} retransmits skipped, {len(payload):,} B)")

    def load_file(self):
        path = filedialog.askopenfilename(title="Open PCAP, PCAPNG, Stream, or Binary File")
        if not path:
            return
        with open(path, "rb") as f:
            raw = f.read()
        if path.lower().endswith((".pcap", ".pcapng", ".cap")):
            try:
                self.flows = parse_capture_flows(raw)
                menu = self.flow_menu["menu"]
                menu.delete(0, "end")
                for k in self.flows:
                    menu.add_command(label=k, command=lambda fk=k: self._select_flow(fk))
                first_flow = next(iter(self.flows))
                self._select_flow(first_flow)
                return
            except Exception as exc:
                messagebox.showerror("Capture Parse Error", str(exc))
                return
        try:
            self.in_text.delete("1.0", tk.END)
            self.in_text.insert("1.0", raw.decode("utf-8"))
            self.auto_detect_input()
        except UnicodeDecodeError:
            self.in_fmt_var.set("Raw")
            self.in_text.delete("1.0", tk.END)
            self.in_text.insert("1.0", raw.decode("latin-1"))
            self.run_all()

    def highlight_search(self):
        self.out_text.tag_remove("search_hit", "1.0", tk.END)
        q = self.search_var.get()
        if not q:
            return
        start = "1.0"
        while True:
            pos = self.out_text.search(q, start, stopindex=tk.END, nocase=True)
            if not pos:
                break
            end = f"{pos}+{len(q)}c"
            self.out_text.tag_add("search_hit", pos, end)
            start = end

    def auto_detect_input(self):
        self.in_fmt_var.set(ConversionEngine.auto_detect(self.in_text.get("1.0", "end-1c")))
        self.run_all()

    def swap_panes(self):
        out_val = self.out_text.get("1.0", "end-1c")
        self.in_fmt_var.set(self.out_fmt_var.get())
        self.in_text.delete("1.0", tk.END)
        self.in_text.insert("1.0", out_val)
        self.run_all()

    def copy_output(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.out_text.get("1.0", "end-1c"))
        self.status_var.set("Copied output to clipboard.")

    def save_output(self):
        if self.out_fmt_var.get() == "Raw":
            path = filedialog.asksaveasfilename(title="Save Raw Binary", defaultextension=".bin")
            if path:
                with open(path, "wb") as f:
                    f.write(self.output_bytes)
        else:
            path = filedialog.asksaveasfilename(title="Save Text Output", defaultextension=".txt")
            if path:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self.out_text.get("1.0", "end-1c"))

    def clear_all(self):
        self.in_text.delete("1.0", tk.END)
        self.out_text.delete("1.0", tk.END)
        self.pipeline.steps.clear()
        self._refresh_recipe_box()
        self.status_var.set("Cleared.")
