import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox

from app.core.pipeline import OPERATIONS, TransformationPipeline
from app.pcap.reassembler import FlowStream, parse_capture_flows
from app.protocols.inspector import analyze_payload
from code.engine import ConversionEngine, FORMATS
from code.theme import FONT_MONO, FONT_MONO_SMALL, FONT_STATUS, FONT_TITLE, FONT_UI, FONT_UI_BOLD, NORD


class PacketWorkbenchApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Packet Payload Studio — Network Analysis & Transformation Workbench")
        self.root.geometry("1520x900")
        self.root.minsize(1240, 720)
        self.root.configure(bg=NORD["bg_window"])

        self.alpha_var = tk.DoubleVar(value=0.94)
        try:
            self.root.wm_attributes("-alpha", self.alpha_var.get())
        except tk.TclError:
            pass

        self.pipeline = TransformationPipeline()
        self.flows: dict[str, FlowStream] = {}
        self.raw_input_bytes = b""
        self.output_bytes = b""

        self.in_fmt_var = tk.StringVar(value="C Array")
        self.out_fmt_var = tk.StringVar(value="ASCII")
        self.peer_var = tk.StringVar(value="All Streams")
        self.flow_var = tk.StringVar(value="No PCAP Loaded")
        self.op_search_var = tk.StringVar(value="")
        self.op_param_var = tk.StringVar(value="")
        self.search_var = tk.StringVar(value="")
        self.ascii_dots = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="Ready")

        self._build_ui()
        self.root.bind("<Command-f>", lambda _e: self.search_entry.focus_set())
        self.root.bind("<Control-f>", lambda _e: self.search_entry.focus_set())
        self._load_sample()

    def _pill(self, parent, text, cmd, bg=NORD["bg_elevated"], fg=NORD["fg_main"], padx=8, pady=3):
        lbl = tk.Label(parent, text=text, bg=bg, fg=fg, font=FONT_UI_BOLD, padx=padx, pady=pady, cursor="pointinghand")
        lbl.bind("<Button-1>", lambda _e: cmd())
        return lbl

    def _build_ui(self):
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=5, uniform="pane")
        self.root.grid_columnconfigure(1, weight=4, uniform="pane")
        self.root.grid_columnconfigure(2, weight=5, uniform="pane")

        # TOP BAR
        top = tk.Frame(self.root, bg=NORD["bg_card"], padx=14, pady=8, highlightbackground=NORD["border"], highlightthickness=1)
        top.grid(row=0, column=0, columnspan=3, sticky="ew", padx=12, pady=(10, 4))
        tk.Label(top, text="Packet Payload Studio", bg=NORD["bg_card"], fg=NORD["fg_main"], font=FONT_TITLE).pack(side=tk.LEFT)
        tk.Label(top, text="  |  Network Analysis & Transformation Workbench", bg=NORD["bg_card"], fg=NORD["frost_cyan"], font=FONT_UI).pack(side=tk.LEFT)

        self._pill(top, "Clear All", self.clear_all, fg=NORD["fg_muted"]).pack(side=tk.RIGHT, padx=(6, 0))
        self._pill(top, "Swap Panes", self.swap_panes, bg=NORD["frost_blue"], fg=NORD["text_dark"]).pack(side=tk.RIGHT, padx=6)
        self._pill(top, "Save Recipe", self.save_recipe).pack(side=tk.RIGHT, padx=4)
        self._pill(top, "Load Recipe", self.load_recipe).pack(side=tk.RIGHT, padx=4)

        # ================= PANEL 1: INPUT & PCAP FLOW EXPLORER =================
        p1 = tk.Frame(self.root, bg=NORD["bg_card"], padx=10, pady=8, highlightbackground=NORD["border"], highlightthickness=1)
        p1.grid(row=1, column=0, sticky="nsew", padx=(12, 5), pady=4)
        p1.grid_rowconfigure(3, weight=1)
        p1.grid_columnconfigure(0, weight=1)

        p1_hdr = tk.Frame(p1, bg=NORD["bg_card"])
        p1_hdr.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        tk.Label(p1_hdr, text="1. INPUT & FLOWS", bg=NORD["bg_card"], fg=NORD["frost_cyan"], font=FONT_UI_BOLD).pack(side=tk.LEFT)
        self._pill(p1_hdr, "Open PCAP / File...", self.load_file).pack(side=tk.RIGHT, padx=(4, 0))
        self._pill(p1_hdr, "Auto", self.auto_detect_input, bg=NORD["frost_cyan"], fg=NORD["text_dark"]).pack(side=tk.RIGHT, padx=4)

        p1_ctl = tk.Frame(p1, bg=NORD["bg_card"])
        p1_ctl.grid(row=1, column=0, sticky="ew", pady=(0, 6))
        in_menu = tk.OptionMenu(p1_ctl, self.in_fmt_var, *FORMATS, command=lambda _: self.run_all())
        in_menu.configure(bg=NORD["bg_elevated"], fg=NORD["fg_main"], highlightthickness=0, bd=0, font=FONT_UI_BOLD, width=8)
        in_menu.pack(side=tk.LEFT)

        peer_menu = tk.OptionMenu(p1_ctl, self.peer_var, "All Streams", "Client (peer0)", "Server (peer1)", command=lambda _: self.run_all())
        peer_menu.configure(bg=NORD["bg_elevated"], fg=NORD["frost_cyan"], highlightthickness=0, bd=0, font=FONT_UI, width=11)
        peer_menu.pack(side=tk.LEFT, padx=4)

        self.flow_menu = tk.OptionMenu(p1_ctl, self.flow_var, "No PCAP Loaded")
        self.flow_menu.configure(bg=NORD["bg_elevated"], fg=NORD["aurora_yellow"], highlightthickness=0, bd=0, font=FONT_MONO_SMALL)
        self.flow_menu.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.intel_box = tk.Label(
            p1, text="Protocol: Detecting...", justify=tk.LEFT, anchor="w",
            bg=NORD["bg_editor"], fg=NORD["fg_muted"], font=FONT_MONO_SMALL, padx=8, pady=6,
            highlightbackground=NORD["border"], highlightthickness=1
        )
        self.intel_box.grid(row=2, column=0, sticky="ew", pady=(0, 6))

        in_wrap = tk.Frame(p1, bg=NORD["bg_editor"], highlightbackground=NORD["border"], highlightthickness=1)
        in_wrap.grid(row=3, column=0, sticky="nsew")
        in_wrap.grid_rowconfigure(0, weight=1)
        in_wrap.grid_columnconfigure(0, weight=1)
        self.in_text = tk.Text(in_wrap, wrap=tk.NONE, bg=NORD["bg_editor"], fg=NORD["fg_main"], insertbackground=NORD["frost_cyan"], font=FONT_MONO, padx=10, pady=8, undo=True, bd=0, highlightthickness=0)
        sy1 = tk.Scrollbar(in_wrap, orient=tk.VERTICAL, command=self.in_text.yview)
        sx1 = tk.Scrollbar(in_wrap, orient=tk.HORIZONTAL, command=self.in_text.xview)
        self.in_text.configure(yscrollcommand=sy1.set, xscrollcommand=sx1.set)
        self.in_text.grid(row=0, column=0, sticky="nsew")
        sy1.grid(row=0, column=1, sticky="ns")
        sx1.grid(row=1, column=0, sticky="ew")
        self.in_text.bind("<KeyRelease>", lambda _: self.run_all())

        # ================= PANEL 2: CYBERCHEF RECIPE PIPELINE =================
        p2 = tk.Frame(self.root, bg=NORD["bg_card"], padx=10, pady=8, highlightbackground=NORD["border"], highlightthickness=1)
        p2.grid(row=1, column=1, sticky="nsew", padx=5, pady=4)
        p2.grid_rowconfigure(2, weight=1)
        p2.grid_rowconfigure(5, weight=1)
        p2.grid_columnconfigure(0, weight=1)

        p2_hdr = tk.Frame(p2, bg=NORD["bg_card"])
        p2_hdr.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        tk.Label(p2_hdr, text="2. TRANSFORMATION PIPELINE", bg=NORD["bg_card"], fg=NORD["aurora_yellow"], font=FONT_UI_BOLD).pack(side=tk.LEFT)
        self._pill(p2_hdr, "Clear Recipe", self.clear_recipe, fg=NORD["fg_muted"]).pack(side=tk.RIGHT)

        search_bar = tk.Frame(p2, bg=NORD["bg_card"])
        search_bar.grid(row=1, column=0, sticky="ew", pady=(0, 4))
        tk.Label(search_bar, text="Filter Ops:", bg=NORD["bg_card"], fg=NORD["fg_muted"], font=FONT_UI).pack(side=tk.LEFT)
        op_search = tk.Entry(search_bar, textvariable=self.op_search_var, bg=NORD["bg_editor"], fg=NORD["fg_main"], insertbackground=NORD["frost_cyan"], font=FONT_STATUS, bd=0, highlightbackground=NORD["border"], highlightthickness=1)
        op_search.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        op_search.bind("<KeyRelease>", lambda _: self._refresh_op_catalog())

        self.op_listbox = tk.Listbox(p2, bg=NORD["bg_editor"], fg=NORD["fg_main"], selectbackground=NORD["frost_blue"], selectforeground=NORD["text_dark"], font=FONT_STATUS, bd=0, highlightthickness=1, highlightbackground=NORD["border"], height=9)
        self.op_listbox.grid(row=2, column=0, sticky="nsew", pady=(0, 6))
        self.op_listbox.bind("<Double-Button-1>", lambda _e: self.add_selected_op())

        param_row = tk.Frame(p2, bg=NORD["bg_card"])
        param_row.grid(row=3, column=0, sticky="ew", pady=(0, 8))
        tk.Label(param_row, text="Param:", bg=NORD["bg_card"], fg=NORD["fg_muted"], font=FONT_UI).pack(side=tk.LEFT)
        tk.Entry(param_row, textvariable=self.op_param_var, width=14, bg=NORD["bg_editor"], fg=NORD["fg_main"], insertbackground=NORD["aurora_yellow"], font=FONT_STATUS, bd=0, highlightbackground=NORD["border"], highlightthickness=1).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        self._pill(param_row, "+ Add Step", self.add_selected_op, bg=NORD["aurora_green"], fg=NORD["text_dark"]).pack(side=tk.RIGHT)

        rec_hdr = tk.Frame(p2, bg=NORD["bg_card"])
        rec_hdr.grid(row=4, column=0, sticky="ew", pady=(0, 4))
        tk.Label(rec_hdr, text="ACTIVE RECIPE STEPS:", bg=NORD["bg_card"], fg=NORD["frost_cyan"], font=FONT_UI_BOLD).pack(side=tk.LEFT)
        self._pill(rec_hdr, "Remove", self.remove_step, fg=NORD["aurora_red"], padx=6, pady=2).pack(side=tk.RIGHT, padx=(3, 0))
        self._pill(rec_hdr, "Toggle", self.toggle_step, padx=6, pady=2).pack(side=tk.RIGHT, padx=3)
        self._pill(rec_hdr, "Down", lambda: self.move_step(1), padx=6, pady=2).pack(side=tk.RIGHT, padx=3)
        self._pill(rec_hdr, "Up", lambda: self.move_step(-1), padx=6, pady=2).pack(side=tk.RIGHT, padx=3)

        self.recipe_listbox = tk.Listbox(p2, bg=NORD["bg_editor"], fg=NORD["aurora_yellow"], selectbackground=NORD["border"], font=FONT_STATUS, bd=0, highlightthickness=1, highlightbackground=NORD["border"], height=8)
        self.recipe_listbox.grid(row=5, column=0, sticky="nsew")

        # ================= PANEL 3: INSPECTOR & OUTPUT =================
        p3 = tk.Frame(self.root, bg=NORD["bg_card"], padx=10, pady=8, highlightbackground=NORD["border"], highlightthickness=1)
        p3.grid(row=1, column=2, sticky="nsew", padx=(5, 12), pady=4)
        p3.grid_rowconfigure(2, weight=1)
        p3.grid_columnconfigure(0, weight=1)

        p3_hdr = tk.Frame(p3, bg=NORD["bg_card"])
        p3_hdr.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        tk.Label(p3_hdr, text="3. INSPECTOR OUTPUT", bg=NORD["bg_card"], fg=NORD["aurora_green"], font=FONT_UI_BOLD).pack(side=tk.LEFT)
        self._pill(p3_hdr, "Save...", self.save_output).pack(side=tk.RIGHT, padx=(4, 0))
        self._pill(p3_hdr, "Copy", self.copy_output, bg=NORD["aurora_green"], fg=NORD["text_dark"]).pack(side=tk.RIGHT, padx=4)

        p3_ctl = tk.Frame(p3, bg=NORD["bg_card"])
        p3_ctl.grid(row=1, column=0, sticky="ew", pady=(0, 6))
        out_menu = tk.OptionMenu(p3_ctl, self.out_fmt_var, *FORMATS, command=lambda _: self.run_all())
        out_menu.configure(bg=NORD["bg_elevated"], fg=NORD["fg_main"], highlightthickness=0, bd=0, font=FONT_UI_BOLD, width=8)
        out_menu.pack(side=tk.LEFT)

        tk.Checkbutton(p3_ctl, text="Dots", variable=self.ascii_dots, bg=NORD["bg_card"], fg=NORD["fg_muted"], selectcolor=NORD["bg_editor"], font=FONT_UI, command=self.run_all).pack(side=tk.LEFT, padx=6)

        self._pill(p3_ctl, "Find", self.highlight_search, padx=6, pady=2).pack(side=tk.RIGHT)
        self.search_entry = tk.Entry(p3_ctl, textvariable=self.search_var, width=14, bg=NORD["bg_editor"], fg=NORD["fg_main"], insertbackground=NORD["aurora_green"], font=FONT_STATUS, bd=0, highlightbackground=NORD["border"], highlightthickness=1)
        self.search_entry.pack(side=tk.RIGHT, padx=4)
        self.search_entry.bind("<Return>", lambda _e: self.highlight_search())

        out_wrap = tk.Frame(p3, bg=NORD["bg_editor"], highlightbackground=NORD["border"], highlightthickness=1)
        out_wrap.grid(row=2, column=0, sticky="nsew")
        out_wrap.grid_rowconfigure(0, weight=1)
        out_wrap.grid_columnconfigure(0, weight=1)
        self.out_text = tk.Text(out_wrap, wrap=tk.NONE, bg=NORD["bg_editor"], fg=NORD["aurora_green"], insertbackground=NORD["aurora_green"], font=FONT_MONO, padx=10, pady=8, bd=0, highlightthickness=0)
        self.out_text.tag_configure("search_hit", background=NORD["aurora_yellow"], foreground=NORD["text_dark"])
        sy3 = tk.Scrollbar(out_wrap, orient=tk.VERTICAL, command=self.out_text.yview)
        sx3 = tk.Scrollbar(out_wrap, orient=tk.HORIZONTAL, command=self.out_text.xview)
        self.out_text.configure(yscrollcommand=sy3.set, xscrollcommand=sx3.set)
        self.out_text.grid(row=0, column=0, sticky="nsew")
        sy3.grid(row=0, column=1, sticky="ns")
        sx3.grid(row=1, column=0, sticky="ew")

        # STATUS BAR
        status = tk.Frame(self.root, bg=NORD["bg_card"], padx=14, pady=6, highlightbackground=NORD["border"], highlightthickness=1)
        status.grid(row=2, column=0, columnspan=3, sticky="ew", padx=12, pady=(4, 10))
        tk.Label(status, textvariable=self.status_var, bg=NORD["bg_card"], fg=NORD["fg_muted"], font=FONT_STATUS).pack(side=tk.LEFT)

        self._refresh_op_catalog()

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
            self.out_text.configure(fg=NORD["aurora_green"])
            self.out_text.delete("1.0", tk.END)
            self.out_text.insert("1.0", rendered)
            self.highlight_search()

            sha_short = hashlib.sha256(self.output_bytes).hexdigest()[:16]
            self.status_var.set(f"In: {len(self.raw_input_bytes):,} B  ->  Out: {len(self.output_bytes):,} B  |  Steps: {len(self.pipeline.steps)}  |  SHA-256: {sha_short}...")
        except Exception as exc:
            self.out_text.configure(fg=NORD["aurora_red"])
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
