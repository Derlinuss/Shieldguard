import os
import sys
import json
import time
import threading
import math
from datetime import datetime

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
except ImportError:
    tk = None

from antivirus import AntiVirus, LOG_FILE, REPORT_DIR
from algorithm import get_file_hash

# ─── Color palette ───
C_BG = "#0D1117"
C_SURFACE = "#161B22"
C_CARD = "#1C2333"
C_HEADER = "#1A1F2E"
C_PRIMARY = "#2B5FD7"
C_PRIMARY_HOVER = "#3B6FE7"
C_ACCENT = "#0E7C7C"
C_DANGER = "#C53030"
C_WARNING = "#B7791F"
C_INFO = "#2563EB"
C_TEXT = "#E6EDF3"
C_TEXT_DIM = "#8B949E"
C_TEXT_MUTED = "#484F58"
C_SUCCESS = "#276749"
C_BORDER = "#30363D"
C_CRITICAL = "#DC2626"
C_HIGH = "#C53030"
C_MEDIUM = "#D97706"
C_LOW = "#2563EB"
FONT = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_HEADING = ("Segoe UI", 13, "bold")
FONT_TITLE = ("Segoe UI", 18, "bold")
FONT_MONO = ("Consolas", 10)
FONT_SMALL = ("Segoe UI", 9)
FONT_TINY = ("Segoe UI", 8)
ICON_SHIELD = "🛡"
ICON_SCAN = "🔍"
ICON_QUAR = "🔒"
ICON_SHIELDED = "✅"
ICON_SETTINGS = "⚙"
ICON_DANGER = "⚠"


class RoundedButton(tk.Canvas):
    def __init__(self, parent, text, command, bg=C_PRIMARY, fg=C_TEXT, width=140, height=36, font=FONT_BOLD, **kw):
        super().__init__(parent, width=width, height=height, bg=C_BG, highlightthickness=0, **kw)
        self.command = command
        self.bg = bg
        self.fg = fg
        self.text = text
        self.font = font
        self.width = width
        self.height = height
        self.disabled = False
        self._draw_idle()
        self.bind("<Button-1>", self._on_click)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)

    def _draw_idle(self):
        self.delete("all")
        r = 6
        self.create_rounded_rect(1, 1, self.width - 1, self.height - 1, r, fill=C_SURFACE, outline=self.bg, width=2)
        self.create_text(self.width // 2, self.height // 2, text=self.text, fill=self.fg, font=self.font)

    def create_rounded_rect(self, x1, y1, x2, y2, r, **kw):
        points = [x1+r, y1, x2-r, y1, x2, y1, x2, y1+r, x2, y2-r, x2, y2, x2-r, y2, x1+r, y2, x1, y2, x1, y2-r, x1, y1+r, x1, y1]
        return self.create_polygon(points, smooth=True, **kw)

    def _on_click(self, e):
        if not self.disabled and self.command:
            self.command()

    def _on_enter(self, e):
        if not self.disabled:
            self.delete("all")
            r = 6
            self.create_rounded_rect(1, 1, self.width - 1, self.height - 1, r, fill=self.bg, outline=self.bg, width=2)
            self.create_text(self.width // 2, self.height // 2, text=self.text, fill=self.fg, font=self.font)

    def _on_leave(self, e):
        self._draw_idle()

    def set_disabled(self, state):
        self.disabled = state
        if state:
            self.delete("all")
            r = 6
            self.create_rounded_rect(1, 1, self.width - 1, self.height - 1, r, fill=C_SURFACE, outline=C_TEXT_MUTED, width=1)
            self.create_text(self.width // 2, self.height // 2, text=self.text, fill=C_TEXT_MUTED, font=self.font)
        else:
            self._draw_idle()


class StatCard(tk.Frame):
    def __init__(self, parent, label, value, color=C_PRIMARY, **kw):
        super().__init__(parent, bg=C_CARD, highlightbackground=color, highlightthickness=1, **kw)
        self.label = label
        self.value = value
        self.color = color
        self._build()

    def _build(self):
        inner = tk.Frame(self, bg=C_CARD)
        inner.pack(fill="both", expand=True, padx=14, pady=10)
        tk.Label(inner, text=self.label, bg=C_CARD, fg=C_TEXT_DIM, font=FONT_SMALL).pack(anchor="w")
        self.val_lbl = tk.Label(inner, text=str(self.value), bg=C_CARD, fg=self.color, font=("Segoe UI", 26, "bold"))
        self.val_lbl.pack(anchor="w", pady=(2, 0))

    def update_value(self, val):
        self.val_lbl.configure(text=str(val))


class ThreatBadge(tk.Frame):
    def __init__(self, parent, severity, text, **kw):
        super().__init__(parent, **kw)
        colors = {"critical": C_CRITICAL, "high": C_HIGH, "medium": C_MEDIUM, "low": C_LOW}
        bg = colors.get(severity, C_TEXT_DIM)
        lbl = tk.Label(self, text=text, bg=bg, fg="white", font=("Segoe UI", 7, "bold"), padx=6, pady=1)
        lbl.pack()


class ModernGUI:
    def __init__(self):
        self.av = AntiVirus()
        self.realtime_active = False
        self.scanning = False

        self.root = tk.Tk()
        self.root.title("ShieldGuard Antivirus")
        self.root.geometry("1100x720")
        self.root.minsize(900, 600)
        self.root.configure(bg=C_BG)

        self._setup_styles()
        self._build_layout()
        self._bind_events()
        self._animate_shield()

    def _setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("Treeview", background=C_SURFACE, foreground=C_TEXT, fieldbackground=C_SURFACE,
                             borderwidth=0, font=FONT_SMALL, rowheight=32)
        self.style.configure("Treeview.Heading", background=C_HEADER, foreground=C_TEXT, font=FONT_BOLD,
                             borderwidth=0, relief="flat")
        self.style.map("Treeview.Heading", background=[("active", C_PRIMARY)])
        self.style.map("Treeview", background=[("selected", C_PRIMARY)], foreground=[("selected", "white")])
        self.style.configure("Vertical.TScrollbar", background=C_BORDER, troughcolor=C_SURFACE, borderwidth=0)
        self.style.configure("Horizontal.TScrollbar", background=C_BORDER, troughcolor=C_SURFACE, borderwidth=0)
        self.style.configure("TNotebook", background=C_BG, borderwidth=0)
        self.style.configure("TNotebook.Tab", background=C_SURFACE, foreground=C_TEXT_DIM, font=FONT_SMALL, padding=[14, 6])
        self.style.map("TNotebook.Tab", background=[("selected", C_CARD)], foreground=[("selected", C_TEXT)])
        self.style.configure("TLabel", background=C_BG, foreground=C_TEXT, font=FONT)
        self.style.configure("TLabelframe", background=C_BG, foreground=C_TEXT, font=FONT_BOLD)
        self.style.configure("TLabelframe.Label", background=C_BG, foreground=C_TEXT, font=FONT_BOLD)
        self.style.configure("TEntry", fieldbackground=C_SURFACE, foreground=C_TEXT, borderwidth=0, font=FONT)
        self.style.map("TEntry", fieldbackground=[("focus", C_CARD)])

    def _build_layout(self):
        self._build_header()
        self._build_stats_row()
        self._build_notebook()
        self._build_statusbar()

    def _build_header(self):
        header = tk.Frame(self.root, bg=C_HEADER, height=56)
        header.pack(fill="x")
        header.pack_propagate(False)

        # Shield icon
        self.shield_canvas = tk.Canvas(header, width=40, height=40, bg=C_HEADER, highlightthickness=0)
        self.shield_canvas.place(x=14, y=8)

        tk.Label(header, text="ShieldGuard", bg=C_HEADER, fg=C_TEXT, font=FONT_TITLE).place(x=60, y=10)
        tk.Label(header, text="Antivirus", bg=C_HEADER, fg=C_TEXT_DIM, font=("Segoe UI", 10)).place(x=210, y=18)

        # Right side controls
        right = tk.Frame(header, bg=C_HEADER)
        right.pack(side="right", padx=12)
        self.activity_label = tk.Label(right, text="", bg=C_HEADER, fg=C_ACCENT, font=("Segoe UI", 9, "bold"))
        self.activity_label.pack(side="left", padx=(0, 12))
        self.rt_indicator = tk.Canvas(right, width=14, height=14, bg=C_HEADER, highlightthickness=0)
        self.rt_indicator.pack(side="left", padx=(0, 6))
        self._draw_dot(self.rt_indicator, C_TEXT_MUTED)
        tk.Label(right, text="Real-Time: Off", bg=C_HEADER, fg=C_TEXT_DIM, font=FONT_SMALL).pack(side="left")

    def _draw_dot(self, canvas, color):
        canvas.delete("all")
        x, y, r = 7, 7, 5
        canvas.create_oval(x - r, y - r, x + r, y + r, fill=color, outline="", tags="dot")
        canvas.create_oval(x - r - 1, y - r - 1, x + r + 1, y + r + 1, outline=color, width=1)

    def _build_stats_row(self):
        container = tk.Frame(self.root, bg=C_BG)
        container.pack(fill="x", padx=20, pady=(14, 4))

        self.stat_cards = {}
        cards = [
            ("Files Scanned", "0", C_PRIMARY, "scanned"),
            ("Threats Found", "0", C_DANGER, "infected"),
            ("Quarantined", "0", C_WARNING, "quarantined"),
            ("Errors", "0", C_TEXT_DIM, "errors"),
        ]
        for label, val, color, key in cards:
            c = StatCard(container, label, val, color, width=240, height=80)
            c.pack(side="left", padx=(0, 10))
            self.stat_cards[key] = c

    def _build_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=(8, 4))

        self._build_dashboard_tab()
        self._build_scan_tab()
        self._build_quarantine_tab()
        self._build_realtime_tab()
        self._build_lookup_tab()
        self._build_log_tab()

    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg=C_HEADER, height=28)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self.status_icon = tk.Canvas(bar, width=12, height=12, bg=C_HEADER, highlightthickness=0)
        self.status_icon.pack(side="left", padx=(10, 4))
        self._draw_dot(self.status_icon, C_SUCCESS)

        self.status_label = tk.Label(bar, text="Ready", bg=C_HEADER, fg=C_TEXT_DIM, font=FONT_SMALL)
        self.status_label.pack(side="left")

        self.scan_time_label = tk.Label(bar, text="", bg=C_HEADER, fg=C_TEXT_MUTED, font=FONT_TINY)
        self.scan_time_label.pack(side="right", padx=10)

    # ─── DASHBOARD TAB ───

    def _build_dashboard_tab(self):
        tab = tk.Frame(self.notebook, bg=C_BG)
        self.notebook.add(tab, text="  Dashboard  ")

        # Quick action cards
        tk.Label(tab, text="Quick Actions", bg=C_BG, fg=C_TEXT, font=FONT_HEADING).pack(anchor="w", pady=(8, 10))

        actions = tk.Frame(tab, bg=C_BG)
        actions.pack(fill="x")

        qcards = [
            ("Quick Scan", C_PRIMARY, "\U0001F50D", "Scan Downloads folder for threats", self._quick_scan),
            ("Full Scan", C_DANGER, "\U0001F4FD", "Scan entire system", self._full_scan),
            ("Scan & Quarantine", C_WARNING, "\U0001F6E1", "Scan and auto-quarantine", self._scan_and_quarantine),
            ("Update Defs", C_INFO, "\U0001F504", "Update virus database", self._update_defs),
        ]
        for i, (title, color, icon, desc, cmd) in enumerate(qcards):
            self._quick_card(actions, title, color, icon, desc, cmd).pack(side="left", padx=(0, 10))

        # Recent threats
        tk.Label(tab, text="Recent Threats", bg=C_BG, fg=C_TEXT, font=FONT_HEADING).pack(anchor="w", pady=(16, 6))
        self.recent_frame = tk.Frame(tab, bg=C_CARD, highlightbackground=C_BORDER, highlightthickness=1)
        self.recent_frame.pack(fill="both", expand=True)
        self.no_threats_lbl = tk.Label(self.recent_frame, text="No threats detected yet", bg=C_CARD, fg=C_TEXT_DIM, font=FONT)
        self.no_threats_lbl.pack(expand=True)

    def _quick_card(self, parent, title, color, icon, desc, cmd):
        f = tk.Frame(parent, bg=C_CARD, highlightbackground=color, highlightthickness=1, cursor="hand2", width=220, height=130)
        f.pack_propagate(False)
        f.bind("<Button-1>", lambda e: cmd())
        f.bind("<Enter>", lambda e: f.configure(bg=C_SURFACE))
        f.bind("<Leave>", lambda e: f.configure(bg=C_CARD))

        inner = tk.Frame(f, bg=f.cget("bg"))
        inner.pack(fill="both", expand=True, padx=14, pady=12)
        for widget in [inner]:
            for child in widget.winfo_children():
                pass
            widget.bind("<Button-1>", lambda e: cmd())
            for child in widget.winfo_children():
                child.bind("<Button-1>", lambda e: cmd())

        tk.Label(inner, text=icon, bg=f.cget("bg"), fg=color, font=("Segoe UI", 22)).pack(anchor="w")
        tk.Label(inner, text=title, bg=f.cget("bg"), fg=C_TEXT, font=FONT_BOLD).pack(anchor="w", pady=(4, 0))
        tk.Label(inner, text=desc, bg=f.cget("bg"), fg=C_TEXT_DIM, font=FONT_TINY).pack(anchor="w")
        return f

    # ─── SCAN TAB ───

    def _build_scan_tab(self):
        tab = tk.Frame(self.notebook, bg=C_BG)
        self.notebook.add(tab, text="  Scanner  ")

        # Control bar
        ctrl = tk.Frame(tab, bg=C_BG)
        ctrl.pack(fill="x", pady=(6, 8))

        RoundedButton(ctrl, "  Quick Scan", self._quick_scan, bg=C_PRIMARY, width=160).pack(side="left", padx=(0, 8))
        RoundedButton(ctrl, "  Full Scan", self._full_scan, bg=C_DANGER, width=150).pack(side="left", padx=(0, 8))
        RoundedButton(ctrl, "  Scan & Quarantine", self._scan_and_quarantine, bg=C_WARNING, width=200).pack(side="left", padx=(0, 8))
        self.stop_btn = RoundedButton(ctrl, "  Stop", None, bg=C_TEXT_MUTED, width=120)
        self.stop_btn.pack(side="left")

        # Progress
        pf = tk.Frame(tab, bg=C_BG)
        pf.pack(fill="x", pady=(0, 6))
        self.progress = ttk.Progressbar(pf, mode="indeterminate", length=500, style="TProgressbar")
        self.progress.pack(side="left", padx=(0, 10))
        self.style.configure("TProgressbar", background=C_PRIMARY, troughcolor=C_CARD, borderwidth=0)
        self.prog_label = tk.Label(pf, text="", bg=C_BG, fg=C_TEXT_DIM, font=FONT_SMALL)
        self.prog_label.pack(side="left")

        # Results
        res_frame = tk.Frame(tab, bg=C_BG)
        res_frame.pack(fill="both", expand=True)

        # Tree
        tree_frame = tk.Frame(res_frame, bg=C_CARD, highlightbackground=C_BORDER, highlightthickness=1)
        tree_frame.pack(fill="both", expand=True)

        self.scan_table = ttk.Treeview(tree_frame, columns=("severity", "method", "name", "filepath"),
                                       show="headings", selectmode="browse", height=10)
        self.scan_table.heading("severity", text="Severity")
        self.scan_table.heading("method", text="Method")
        self.scan_table.heading("name", text="Threat Name")
        self.scan_table.heading("filepath", text="File")
        self.scan_table.column("severity", width=90, anchor="center")
        self.scan_table.column("method", width=90, anchor="center")
        self.scan_table.column("name", width=200)
        self.scan_table.column("filepath", width=500)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.scan_table.yview)
        self.scan_table.configure(yscrollcommand=vsb.set)
        self.scan_table.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # Tags for coloring
        self.scan_table.tag_configure("critical", foreground=C_CRITICAL)
        self.scan_table.tag_configure("high", foreground=C_HIGH)
        self.scan_table.tag_configure("medium", foreground=C_MEDIUM)
        self.scan_table.tag_configure("low", foreground=C_LOW)

        # Count
        count_frame = tk.Frame(tree_frame, bg=C_CARD)
        count_frame.pack(fill="x", side="bottom")
        self.scan_count = tk.Label(count_frame, text="0 threats found", bg=C_CARD, fg=C_TEXT_DIM, font=FONT_SMALL, anchor="w", padx=8, pady=4)
        self.scan_count.pack(side="left")

        # Detail panel
        detail_frame = tk.Frame(tab, bg=C_SURFACE, highlightbackground=C_BORDER, highlightthickness=1, height=100)
        detail_frame.pack(fill="x", pady=(6, 0))
        detail_frame.pack_propagate(False)

        tk.Label(detail_frame, text="Details", bg=C_SURFACE, fg=C_TEXT_DIM, font=FONT_SMALL).pack(anchor="w", padx=8, pady=(4, 0))
        self.scan_detail = tk.Text(detail_frame, bg=C_SURFACE, fg=C_TEXT_DIM, font=FONT_MONO, height=3, bd=0, padx=8, pady=4)
        self.scan_detail.pack(fill="both", expand=True)

        self.stop_btn.set_disabled(True)

    # ─── QUARANTINE TAB ───

    def _build_quarantine_tab(self):
        tab = tk.Frame(self.notebook, bg=C_BG)
        self.notebook.add(tab, text="  Quarantine  ")

        ctrl = tk.Frame(tab, bg=C_BG)
        ctrl.pack(fill="x", pady=(6, 8))
        RoundedButton(ctrl, "  Refresh", self._refresh_quarantine, bg=C_PRIMARY, width=130).pack(side="left", padx=(0, 8))
        self.restore_btn = RoundedButton(ctrl, "  Restore", None, bg=C_SUCCESS, width=120)
        self.restore_btn.pack(side="left", padx=(0, 8))
        self.delete_btn = RoundedButton(ctrl, "  Delete", None, bg=C_DANGER, width=120)
        self.delete_btn.pack(side="left")

        tree_frame = tk.Frame(tab, bg=C_CARD, highlightbackground=C_BORDER, highlightthickness=1)
        tree_frame.pack(fill="both", expand=True)

        self.quar_table = ttk.Treeview(tree_frame, columns=("status", "file", "original_path", "date"),
                                       show="headings", selectmode="browse", height=12)
        self.quar_table.heading("status", text="Status")
        self.quar_table.heading("file", text="File")
        self.quar_table.heading("original_path", text="Original Location")
        self.quar_table.heading("date", text="Date")
        self.quar_table.column("status", width=100, anchor="center")
        self.quar_table.column("file", width=200)
        self.quar_table.column("original_path", width="400")
        self.quar_table.column("date", width=160)
        self.quar_table.tag_configure("QUARANTINED", foreground=C_DANGER)
        self.quar_table.tag_configure("RESTORED", foreground=C_SUCCESS)

        qvsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.quar_table.yview)
        self.quar_table.configure(yscrollcommand=qvsb.set)
        self.quar_table.pack(side="left", fill="both", expand=True)
        qvsb.pack(side="right", fill="y")

        self.quar_table.bind("<<TreeviewSelect>>", self._on_quarantine_select)

        detail_frame = tk.Frame(tab, bg=C_SURFACE, highlightbackground=C_BORDER, highlightthickness=1, height=60)
        detail_frame.pack(fill="x", pady=(6, 0))
        detail_frame.pack_propagate(False)
        self.quar_detail = tk.Text(detail_frame, bg=C_SURFACE, fg=C_TEXT_DIM, font=FONT_MONO, height=2, bd=0, padx=8, pady=4)
        self.quar_detail.pack(fill="both", expand=True)
        self.quar_detail.insert("end", "Select an item to see details")

    def _on_quarantine_select(self, e):
        sel = self.quar_table.selection()
        if sel:
            vals = self.quar_table.item(sel[0], "values")
            if vals:
                self.restore_btn.command = lambda: self._restore_specific(vals[2])
                self.delete_btn.command = lambda: self._delete_specific(vals[2])
                self.restore_btn._draw_idle()
                self.delete_btn._draw_idle()
                if vals[0] == "QUARANTINED":
                    self.quar_detail.configure(state="normal", fg=C_DANGER)
                    self.quar_detail.delete("1.0", "end")
                    self.quar_detail.insert("end", f"File: {vals[1]}\nOriginal: {vals[2]}\nDate: {vals[3]}")
                else:
                    self.quar_detail.configure(state="normal", fg=C_SUCCESS)
                    self.quar_detail.delete("1.0", "end")
                    self.quar_detail.insert("end", f"Restored file\nOriginal: {vals[2]}\nDate: {vals[3]}")

    def _restore_specific(self, path):
        success, msg = self.av.quarantine.restore(path)
        if success:
            messagebox.showinfo("Restored", f"Restored to:\n{msg}", parent=self.root)
        else:
            messagebox.showerror("Error", msg, parent=self.root)
        self._refresh_quarantine()

    def _delete_specific(self, path):
        if not messagebox.askyesno("Confirm", "Delete permanently?", parent=self.root):
            return
        success, msg = self.av.quarantine.delete_permanently(path)
        if success:
            messagebox.showinfo("Deleted", msg, parent=self.root)
        else:
            messagebox.showerror("Error", msg, parent=self.root)
        self._refresh_quarantine()

    # ─── REAL-TIME TAB ───

    def _build_realtime_tab(self):
        tab = tk.Frame(self.notebook, bg=C_BG)
        self.notebook.add(tab, text="  Real-Time  ")

        # Status panel
        status_frame = tk.Frame(tab, bg=C_CARD, highlightbackground=C_BORDER, highlightthickness=1)
        status_frame.pack(fill="x", pady=(6, 10))

        inner = tk.Frame(status_frame, bg=C_CARD)
        inner.pack(padx=20, pady=16)

        self.rt_status_canvas = tk.Canvas(inner, width=20, height=20, bg=C_CARD, highlightthickness=0)
        self.rt_status_canvas.pack(side="left")
        self._draw_dot(self.rt_status_canvas, C_TEXT_MUTED)

        self.rt_status_text = tk.Label(inner, text="Protection: INACTIVE", bg=C_CARD, fg=C_TEXT_DIM, font=("Segoe UI", 16, "bold"))
        self.rt_status_text.pack(side="left", padx=(10, 0))

        tk.Label(inner, text="Monitors: Desktop, Downloads", bg=C_CARD, fg=C_TEXT_DIM, font=FONT_SMALL).pack(side="left", padx=(20, 0))

        btn_frame = tk.Frame(tab, bg=C_BG)
        btn_frame.pack(pady=6)
        self.rt_btn = RoundedButton(btn_frame, "  Start Protection", self._toggle_realtime, bg=C_SUCCESS, width=220)
        self.rt_btn.pack()

        log_frame = tk.Frame(tab, bg=C_SURFACE, highlightbackground=C_BORDER, highlightthickness=1)
        log_frame.pack(fill="both", expand=True)

        tk.Label(log_frame, text="Protection Log", bg=C_SURFACE, fg=C_TEXT_DIM, font=FONT_SMALL).pack(anchor="w", padx=8, pady=(4, 0))
        self.rt_log = tk.Text(log_frame, bg=C_SURFACE, fg=C_TEXT_DIM, font=FONT_MONO, bd=0, padx=8, pady=4)
        self.rt_log.pack(fill="both", expand=True)
        self.rt_log.insert("end", "Real-time protection not started\n")

    # ─── LOOKUP TAB ───

    def _build_lookup_tab(self):
        tab = tk.Frame(self.notebook, bg=C_BG)
        self.notebook.add(tab, text="  Online Lookup  ")

        top = tk.Frame(tab, bg=C_BG)
        top.pack(fill="x", pady=(10, 6))
        tk.Label(top, text="Check file hash against VirusTotal", bg=C_BG, fg=C_TEXT, font=FONT_HEADING).pack(anchor="w")

        row = tk.Frame(tab, bg=C_BG)
        row.pack(fill="x", pady=6)
        self.lookup_path = tk.StringVar()
        entry = tk.Entry(row, textvariable=self.lookup_path, bg=C_SURFACE, fg=C_TEXT, font=FONT, bd=0, insertbackground=C_TEXT, highlightbackground=C_BORDER, highlightthickness=1)
        entry.pack(side="left", fill="x", expand=True, padx=(0, 8), ipady=6, ipadx=8)
        RoundedButton(row, "  Browse", self._browse_lookup, bg=C_TEXT_MUTED, width=110).pack(side="left", padx=(0, 6))
        RoundedButton(row, "  Lookup", self._do_lookup, bg=C_PRIMARY, width=110).pack(side="left")

        result_frame = tk.Frame(tab, bg=C_SURFACE, highlightbackground=C_BORDER, highlightthickness=1)
        result_frame.pack(fill="both", expand=True, pady=(6, 0))

        tk.Label(result_frame, text="Result", bg=C_SURFACE, fg=C_TEXT_DIM, font=FONT_SMALL).pack(anchor="w", padx=8, pady=(4, 0))
        self.lookup_result = tk.Text(result_frame, bg=C_SURFACE, fg=C_TEXT, font=FONT_MONO, bd=0, padx=8, pady=4)
        self.lookup_result.pack(fill="both", expand=True)
        self.lookup_result.insert("end", "Enter a file path and click Lookup")

    # ─── LOG TAB ───

    def _build_log_tab(self):
        tab = tk.Frame(self.notebook, bg=C_BG)
        self.notebook.add(tab, text="  Activity Log  ")

        ctrl = tk.Frame(tab, bg=C_BG)
        ctrl.pack(fill="x", pady=(6, 6))
        RoundedButton(ctrl, "  Refresh", self._refresh_log, bg=C_PRIMARY, width=130).pack(side="left", padx=(0, 8))
        RoundedButton(ctrl, "  Clear", self._clear_log, bg=C_DANGER, width=110).pack(side="left")

        log_frame = tk.Frame(tab, bg=C_SURFACE, highlightbackground=C_BORDER, highlightthickness=1)
        log_frame.pack(fill="both", expand=True)

        self.log_text = tk.Text(log_frame, bg=C_SURFACE, fg=C_TEXT_DIM, font=FONT_MONO, bd=0, padx=8, pady=4)
        self.log_text.pack(fill="both", expand=True)

        vsb = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")

    # ─── ANIMATION ───

    def _animate_shield(self):
        self.shield_angle = 0
        self._shield_frame()

    def _shield_frame(self):
        self.shield_angle += 0.05
        canvas = self.shield_canvas
        canvas.delete("all")
        cx, cy, r = 20, 20, 14
        try:
            pts = []
            for i in range(12):
                a = self.shield_angle + (i / 12) * math.pi * 2
                rr = r + 2 * math.sin(self.shield_angle * 2 + i)
                pts.extend([cx + rr * math.cos(a), cy + rr * math.sin(a)])
            canvas.create_polygon(pts, fill=C_PRIMARY, outline=C_ACCENT, width=1, smooth=True)
        except Exception:
            canvas.create_text(cx, cy, text="\U0001F6E1", font=("Segoe UI", 18))
        self.root.after(50, self._shield_frame)

    # ─── EVENT BINDINGS ───

    def _bind_events(self):
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _set_status(self, msg, color=None):
        self.status_label.configure(text=msg)
        self.activity_label.configure(text=msg)
        if color:
            self._draw_dot(self.status_icon, color)
        else:
            self._draw_dot(self.status_icon, C_SUCCESS)
        self.root.update_idletasks()
        self.root.after(8000, lambda: self.activity_label.configure(text=""))

    def _update_stats(self):
        stats = self.av.get_stats()
        self.stat_cards["scanned"].update_value(stats.get("scanned", 0))
        self.stat_cards["infected"].update_value(stats.get("infected", 0))
        q_count = len(self.av.quarantine.list_quarantined())
        self.stat_cards["quarantined"].update_value(q_count)
        self.stat_cards["errors"].update_value(stats.get("errors", 0))

    def _add_threat_to_recent(self, result):
        if result and result.get("detected"):
            self.no_threats_lbl.pack_forget()
            for t in result.get("threats", []):
                row = tk.Frame(self.recent_frame, bg=C_CARD)
                row.pack(fill="x", padx=6, pady=2)
                colors = {"critical": C_CRITICAL, "high": C_HIGH, "medium": C_MEDIUM, "low": C_LOW}
                dot = tk.Canvas(row, width=8, height=8, bg=C_CARD, highlightthickness=0)
                dot.pack(side="left", padx=(6, 6))
                dot.create_oval(0, 0, 8, 8, fill=colors.get(t.get("severity"), C_TEXT_DIM), outline="")
                tk.Label(row, text=t.get("name", "?"), bg=C_CARD, fg=C_TEXT, font=("Segoe UI", 9, "bold")).pack(side="left")
                tk.Label(row, text=os.path.basename(result.get("filepath", "")), bg=C_CARD, fg=C_TEXT_DIM, font=FONT_TINY).pack(side="right", padx=6)
            # Keep only last 10
            children = self.recent_frame.winfo_children()
            if len(children) > 10:
                for w in children[10:]:
                    w.destroy()

    # ─── SCAN LOGIC ───

    def _scan_callback(self, result):
        self.root.after(0, self._safe_scan_callback, result)

    def _safe_scan_callback(self, result):
        if result and result.get("detected"):
            for t in result.get("threats", []):
                sev = t.get("severity", "low")
                self.scan_table.insert("", "end", values=(sev.upper(), t.get("method", "?").upper(), t.get("name", "?"), result.get("filepath", "?")[:90]), tags=(sev,))
            self.scan_count.configure(text=f"{len(self.scan_table.get_children())} threats found")
            self._update_stats()
            self._add_threat_to_recent(result)
            self._show_detail(result)

    def _show_detail(self, result):
        self.scan_detail.configure(state="normal")
        text = f"File: {result['filepath']}\nSize: {result.get('size', 0)} bytes\n"
        if result.get("heuristic"):
            h = result["heuristic"]
            text += f"Heuristic: score={h['score']}, verdict={h['verdict']}, flags={', '.join(h['flags'])}"
        self.scan_detail.delete("1.0", "end")
        self.scan_detail.insert("1.0", text)
        self.scan_detail.configure(state="disabled")

    def _quick_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.scan_table.delete(*self.scan_table.get_children())
        self.scan_detail.configure(state="normal")
        self.scan_detail.delete("1.0", "end")
        self.scan_detail.configure(state="disabled")
        self.scan_count.configure(text="0 threats found")
        self.progress.start(10)
        self.stop_btn.command = self._stop_scan
        self.stop_btn.set_disabled(False)
        self._set_status("Quick scanning Downloads...", C_INFO)

        def task():
            self.av.quick_scan(os.path.expanduser("~\\Downloads"), callback=self._scan_callback)
            self.root.after(0, self._scan_done)

        threading.Thread(target=task, daemon=True).start()

    def _full_scan(self):
        if self.scanning:
            return
        path = filedialog.askdirectory(title="Select folder to scan", initialdir="C:\\", parent=self.root)
        if not path:
            return
        self.scanning = True
        self.scan_table.delete(*self.scan_table.get_children())
        self.scan_detail.configure(state="normal")
        self.scan_detail.delete("1.0", "end")
        self.scan_detail.configure(state="disabled")
        self.scan_count.configure(text="0 threats found")
        self.progress.start(10)
        self.stop_btn.command = self._stop_scan
        self.stop_btn.set_disabled(False)
        self._set_status(f"Scanning {path}...", C_INFO)

        def task():
            self.av.full_scan(path, callback=self._scan_callback)
            self.root.after(0, self._scan_done)

        threading.Thread(target=task, daemon=True).start()

    def _scan_and_quarantine(self):
        if self.scanning:
            return
        path = filedialog.askdirectory(title="Select folder to scan & quarantine", initialdir=os.path.expanduser("~\\Downloads"), parent=self.root)
        if not path:
            return
        self.scanning = True
        self.scan_table.delete(*self.scan_table.get_children())
        self.scan_detail.configure(state="normal")
        self.scan_detail.delete("1.0", "end")
        self.scan_detail.configure(state="disabled")
        self.progress.start(10)
        self.stop_btn.command = self._stop_scan
        self.stop_btn.set_disabled(False)
        self._set_status("Scanning and quarantining...", C_WARNING)

        def task():
            for fpath, action, msg in self.av.scan_and_quarantine(path):
                if action == "quarantined":
                    self.root.after(0, lambda fp=fpath: self.scan_table.insert("", "end", values=("QUARANTINED", "MOVE", os.path.basename(fp), fp[:90]), tags=("high",)))
            self.root.after(0, self._scan_done)
        threading.Thread(target=task, daemon=True).start()

    def _stop_scan(self):
        self.av.scanner.stop()
        self._set_status("Scan stopped", C_WARNING)

    def _scan_done(self):
        self.progress.stop()
        self.scanning = False
        self.stop_btn.set_disabled(True)
        self._update_stats()
        count = len(self.scan_table.get_children())
        self._set_status(f"Scan complete — {count} threats found", C_DANGER if count > 0 else C_SUCCESS)
        self.scan_count.configure(text=f"{count} threats found")

    def _refresh_quarantine(self):
        self.quar_table.delete(*self.quar_table.get_children())
        entries = self.av.quarantine.list_quarantined()
        for e in entries:
            status = "QUARANTINED" if not e.get("restored") else "RESTORED"
            self.quar_table.insert("", "end", values=(status, os.path.basename(e["quarantined_path"]), e["original_path"], e.get("timestamp", "?")[:19]), tags=(status,))
        self._update_stats()

    def _toggle_realtime(self):
        if not self.realtime_active:
            self.av.start_realtime_protection(callback=self._rt_callback)
            self.realtime_active = True
            self.rt_status_text.configure(text="Protection: ACTIVE", fg=C_SUCCESS)
            self.rt_btn.text = "  Stop Protection"
            self.rt_btn.bg = C_DANGER
            self.rt_btn._draw_idle()
            self._draw_dot(self.rt_indicator, C_SUCCESS)
            self._rt_log("Real-time protection started")
        else:
            self.av.stop_realtime_protection()
            self.realtime_active = False
            self.rt_status_text.configure(text="Protection: INACTIVE", fg=C_TEXT_DIM)
            self.rt_btn.text = "  Start Protection"
            self.rt_btn.bg = C_SUCCESS
            self.rt_btn._draw_idle()
            self._draw_dot(self.rt_indicator, C_TEXT_MUTED)
            self._rt_log("Real-time protection stopped")

    def _rt_callback(self, action, fpath):
        self.root.after(0, lambda: self._rt_log(f"[{action.upper()}] {fpath}"))

    def _rt_log(self, msg):
        self.rt_log.configure(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        color = C_DANGER if "BLOCKED" in msg or "THREAT" in msg else C_TEXT_DIM
        self.rt_log.insert("end", f"[{ts}] {msg}\n")
        self.rt_log.see("end")
        self.rt_log.configure(state="disabled")

    def _browse_lookup(self):
        path = filedialog.askopenfilename(title="Select file for online lookup", parent=self.root)
        if path:
            self.lookup_path.set(path)

    def _do_lookup(self):
        path = self.lookup_path.get()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Error", "File not found", parent=self.root)
            return
        self.lookup_result.configure(state="normal")
        self.lookup_result.delete("1.0", "end")
        self.lookup_result.insert("end", f"Looking up: {path}\nHashing...\n")
        self._set_status("Looking up file online...", C_INFO)

        def task():
            result = self.av.lookup_online(path)
            self.root.after(0, lambda: self._show_lookup_result(result))
        threading.Thread(target=task, daemon=True).start()

    def _show_lookup_result(self, result):
        self.lookup_result.configure(state="normal")
        self.lookup_result.delete("1.0", "end")
        if result.get("detected"):
            self.lookup_result.insert("end", "\U000026A0  THREAT DETECTED\n", "threat")
            self.lookup_result.tag_config("threat", foreground=C_DANGER, font=("Consolas", 11, "bold"))
        else:
            self.lookup_result.insert("end", "\U00002713  File appears clean\n", "clean")
            self.lookup_result.tag_config("clean", foreground=C_SUCCESS, font=("Consolas", 11, "bold"))
        self.lookup_result.insert("end", f"\nSource: {result.get('source', 'N/A')}")
        self.lookup_result.insert("end", f"\nMalicious:  {result.get('malicious', 0)} engines")
        self.lookup_result.insert("end", f"\nSuspicious: {result.get('suspicious', 0)} engines")
        self.lookup_result.insert("end", f"\nUndetected: {result.get('undetected', 0)} engines")
        self.lookup_result.insert("end", f"\nHarmless:   {result.get('harmless', 0)} engines")
        if result.get("error"):
            self.lookup_result.insert("end", f"\n\nNote: {result['error']}")
        self.lookup_result.configure(state="disabled")
        self._set_status("Lookup complete")

    def _update_defs(self):
        self._set_status("Updating definitions...", C_INFO)

        def task():
            success, msg = self.av.update_virus_definitions()
            self.root.after(0, lambda: self._set_status(msg, C_SUCCESS if success else C_WARNING))
            self.root.after(0, lambda: messagebox.showinfo("Update" if success else "Failed", msg, parent=self.root))
        threading.Thread(target=task, daemon=True).start()

    def _refresh_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        if os.path.isfile(LOG_FILE):
            with open(LOG_FILE) as f:
                lines = f.readlines()
                for line in lines[-200:]:
                    self.log_text.insert("end", line)
        self.log_text.configure(state="disabled")
        self.log_text.see("end")

    def _clear_log(self):
        if messagebox.askyesno("Confirm", "Clear the activity log?", parent=self.root):
            try:
                open(LOG_FILE, "w").close()
            except IOError:
                pass
            self._refresh_log()

    def _on_close(self):
        if self.realtime_active:
            self.av.stop_realtime_protection()
        self.root.destroy()

    def run(self):
        self._refresh_log()
        self.root.mainloop()


def launch_gui():
    root = tk.Tk()
    root.withdraw()
    try:
        app = ModernGUI()
        app.run()
    except Exception as e:
        messagebox.showerror("Error", str(e), parent=root)
        raise
