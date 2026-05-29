import os
import sys
import json
import time
import threading
from datetime import datetime

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
except ImportError:
    tk = None

from antivirus import AntiVirus, LOG_FILE, REPORT_DIR
from algorithm import get_file_hash


class ThreatTable(ttk.Frame):
    def __init__(self, parent, columns, **kw):
        super().__init__(parent, **kw)
        self.tree = ttk.Treeview(self, columns=columns, show="headings", selectmode="browse", height=12)
        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        for col in columns:
            self.tree.heading(col, text=col.replace("_", " ").title())
            self.tree.column(col, width=120 if col != "filepath" else 300, anchor="w" if col != "severity" else "center")
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

    def add(self, values, tags=None):
        iid = self.tree.insert("", "end", values=values, tags=tags or [])
        return iid

    def clear(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    def get_selected(self):
        sel = self.tree.selection()
        if sel:
            return self.tree.item(sel[0], "values")
        return None


class ShieldGuardGUI:
    def __init__(self):
        self.av = AntiVirus()
        self.realtime_active = False
        self.scanning = False

        self.root = tk.Tk()
        self.root.title("ShieldGuard Antivirus")
        self.root.geometry("950x700")
        self.root.minsize(800, 600)

        style = ttk.Style()
        style.theme_use("aqua" if "aqua" in style.theme_names() else "clam")
        style.configure("Critical.TLabel", foreground="red", font=("Helvetica", 10, "bold"))
        style.configure("High.TLabel", foreground="#cc3300", font=("Helvetica", 10))
        style.configure("Clean.TLabel", foreground="green", font=("Helvetica", 10))
        style.configure("Title.TLabel", font=("Helvetica", 16, "bold"))
        style.configure("Heading.TLabel", font=("Helvetica", 11, "bold"))

        self._build_layout()
        self._bind_events()

    def _build_layout(self):
        header = ttk.Frame(self.root)
        header.pack(fill="x", padx=15, pady=(15, 5))
        ttk.Label(header, text="ShieldGuard Antivirus", style="Title.TLabel").pack(side="left")
        self.status_label = ttk.Label(header, text="Ready", foreground="#555")
        self.status_label.pack(side="right")

        stats_frame = ttk.LabelFrame(self.root, text="Scan Statistics", padding=8)
        stats_frame.pack(fill="x", padx=15, pady=5)

        self.stat_labels = {}
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack()
        for i, (key, color) in enumerate([("scanned", "green"), ("infected", "red"), ("whitelisted", "#cc9900"), ("errors", "#cc6600")]):
            f = ttk.Frame(stats_grid, padding=(15, 2))
            f.grid(row=0, column=i, padx=10)
            ttk.Label(f, text=key.title(), font=("Helvetica", 9)).pack()
            lbl = ttk.Label(f, text="0", foreground=color, font=("Helvetica", 14, "bold"))
            lbl.pack()
            self.stat_labels[key] = lbl

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=15, pady=8)

        self._build_scan_tab()
        self._build_quarantine_tab()
        self._build_realtime_tab()
        self._build_lookup_tab()
        self._build_log_tab()

        bottom = ttk.Frame(self.root)
        bottom.pack(fill="x", padx=15, pady=(0, 10))
        ttk.Button(bottom, text="Update Definitions", command=self._update_defs).pack(side="left", padx=2)
        ttk.Button(bottom, text="View Reports", command=self._view_reports).pack(side="left", padx=2)
        ttk.Button(bottom, text="Exit", command=self.root.destroy).pack(side="right", padx=2)

    def _build_scan_tab(self):
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="  Scanner  ")

        qf = ttk.LabelFrame(tab, text="Quick Actions", padding=10)
        qf.pack(fill="x", pady=(0, 10))
        row = ttk.Frame(qf)
        row.pack(fill="x")
        ttk.Button(row, text="Quick Scan (Downloads)", command=self._quick_scan, width=28).pack(side="left", padx=5)
        ttk.Button(row, text="Full Scan (/)", command=self._full_scan, width=20).pack(side="left", padx=5)
        ttk.Button(row, text="Scan & Quarantine", command=self._scan_and_quarantine, width=20).pack(side="left", padx=5)

        pf = ttk.Frame(tab)
        pf.pack(fill="x", pady=5)
        self.progress = ttk.Progressbar(pf, mode="indeterminate", length=400)
        self.progress.pack(side="left", padx=5)
        self.prog_label = ttk.Label(pf, text="")
        self.prog_label.pack(side="left", padx=5)

        rf = ttk.LabelFrame(tab, text="Scan Results", padding=5)
        rf.pack(fill="both", expand=True)
        self.scan_table = ThreatTable(rf, ["severity", "method", "name", "filepath"])
        self.scan_table.pack(fill="both", expand=True)
        self.scan_count = ttk.Label(rf, text="0 threats found")
        self.scan_count.pack(anchor="w", pady=2)

        self.scan_detail = scrolledtext.ScrolledText(tab, height=6, state="disabled", font=("Menlo", 9))
        self.scan_detail.pack(fill="x", pady=(5, 0))

    def _build_quarantine_tab(self):
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="  Quarantine  ")

        btn_row = ttk.Frame(tab)
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text="Refresh List", command=self._refresh_quarantine).pack(side="left", padx=2)
        ttk.Button(btn_row, text="Restore Selected", command=self._restore_selected).pack(side="left", padx=2)
        ttk.Button(btn_row, text="Delete Permanently", command=self._delete_quarantined).pack(side="left", padx=2)

        self.quar_table = ThreatTable(tab, ["status", "file", "original_path", "date"])
        self.quar_table.pack(fill="both", expand=True, pady=5)

        self.quar_detail = scrolledtext.ScrolledText(tab, height=6, state="disabled", font=("Menlo", 9))
        self.quar_detail.pack(fill="x")

    def _build_realtime_tab(self):
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="  Real-Time  ")

        info = ttk.LabelFrame(tab, text="Protection Status", padding=15)
        info.pack(fill="x", pady=10)

        self.rt_status = ttk.Label(info, text="INACTIVE", foreground="red", font=("Helvetica", 14, "bold"))
        self.rt_status.pack()

        ttk.Label(info, text="Monitors: Desktop, Downloads").pack(pady=2)

        btn_f = ttk.Frame(tab)
        btn_f.pack(pady=15)
        self.rt_btn = ttk.Button(btn_f, text="Start Protection", command=self._toggle_realtime, width=25)
        self.rt_btn.pack()

        self.rt_log = scrolledtext.ScrolledText(tab, height=15, state="disabled", font=("Menlo", 9))
        self.rt_log.pack(fill="both", expand=True)

    def _build_lookup_tab(self):
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="  Online Lookup  ")

        ttk.Label(tab, text="Check a file against VirusTotal:", style="Heading.TLabel").pack(anchor="w")

        row = ttk.Frame(tab)
        row.pack(fill="x", pady=8)
        self.lookup_path = tk.StringVar()
        ttk.Entry(row, textvariable=self.lookup_path, width=60).pack(side="left", padx=5)
        ttk.Button(row, text="Browse", command=self._browse_lookup).pack(side="left", padx=2)
        ttk.Button(row, text="Lookup", command=self._do_lookup).pack(side="left", padx=2)

        self.lookup_result = scrolledtext.ScrolledText(tab, height=18, state="disabled", font=("Menlo", 9))
        self.lookup_result.pack(fill="both", expand=True)

    def _build_log_tab(self):
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="  Activity Log  ")

        btn_row = ttk.Frame(tab)
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text="Refresh Log", command=self._refresh_log).pack(side="left", padx=2)
        ttk.Button(btn_row, text="Clear Log", command=self._clear_log).pack(side="left", padx=2)

        self.log_text = scrolledtext.ScrolledText(tab, state="disabled", font=("Menlo", 9))
        self.log_text.pack(fill="both", expand=True, pady=5)

    def _bind_events(self):
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _set_status(self, msg):
        self.status_label.configure(text=msg)
        self.root.update_idletasks()

    def _update_stats(self):
        stats = self.av.get_stats()
        for key, lbl in self.stat_labels.items():
            lbl.configure(text=str(stats.get(key, 0)))

    def _scan_callback(self, result):
        self.root.after(0, self._safe_scan_callback, result)

    def _safe_scan_callback(self, result):
        if result and result.get("detected"):
            for t in result.get("threats", []):
                sev = t.get("severity", "low")
                self.scan_table.add((
                    sev.upper(),
                    t.get("method", "?").upper(),
                    t.get("name", "?"),
                    result.get("filepath", "?")[:90],
                ), tags=(sev,))
            self.scan_count.configure(text=f"{len(self.scan_table.tree.get_children())} threats found")
            self._update_stats()
            self._show_detail(result)

    def _show_detail(self, result):
        self.scan_detail.configure(state="normal")
        text = f"File: {result['filepath']}\nSize: {result.get('size', 0)} bytes\n"
        if result.get("heuristic"):
            h = result["heuristic"]
            text += f"Heuristic: score={h['score']}, verdict={h['verdict']}, flags={', '.join(h['flags'])}\n"
        for t in result.get("threats", []):
            text += f"Threat: {t['name']} ({t['severity']}) via {t['method']}\n"
        self.scan_detail.insert("end", text + "\n")
        self.scan_detail.see("end")
        self.scan_detail.configure(state="disabled")

    def _quick_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.scan_table.clear()
        self.scan_detail.configure(state="normal")
        self.scan_detail.delete("1.0", "end")
        self.scan_detail.configure(state="disabled")
        self.scan_count.configure(text="0 threats found")
        self.progress.start(10)
        self._set_status("Quick scanning Downloads...")

        def task():
            self.av.quick_scan(os.path.expanduser("~/Downloads"), callback=self._scan_callback)
            self.root.after(0, self._scan_done)

        threading.Thread(target=task, daemon=True).start()

    def _full_scan(self):
        if self.scanning:
            return
        path = filedialog.askdirectory(title="Select folder to scan", initialdir="/")
        if not path:
            return
        self.scanning = True
        self.scan_table.clear()
        self.scan_detail.configure(state="normal")
        self.scan_detail.delete("1.0", "end")
        self.scan_detail.configure(state="disabled")
        self.scan_count.configure(text="0 threats found")
        self.progress.start(10)
        self._set_status(f"Scanning {path}...")

        def task():
            self.av.full_scan(path, callback=self._scan_callback)
            self.root.after(0, self._scan_done)

        threading.Thread(target=task, daemon=True).start()

    def _scan_and_quarantine(self):
        if self.scanning:
            return
        path = filedialog.askdirectory(title="Select folder to scan & quarantine", initialdir=os.path.expanduser("~/Downloads"))
        if not path:
            return
        self.scanning = True
        self.scan_table.clear()
        self.scan_detail.configure(state="normal")
        self.scan_detail.delete("1.0", "end")
        self.scan_detail.configure(state="disabled")
        self.progress.start(10)
        self._set_status("Scanning and quarantining...")

        def task():
            for fpath, action, msg in self.av.scan_and_quarantine(path):
                if action == "quarantined":
                    self.root.after(0, lambda fp=fpath: self.scan_table.add(("QUARANTINED", "MOVE", os.path.basename(fp), fp[:90])))
                    self.root.after(0, lambda: self._show_detail({"filepath": fpath, "threats": [{"name": "Quarantined", "severity": "high", "method": "move"}], "heuristic": None, "size": 0}))
            self.root.after(0, self._scan_done)

        threading.Thread(target=task, daemon=True).start()

    def _scan_done(self):
        self.progress.stop()
        self.scanning = False
        self._update_stats()
        self._set_status(f"Scan complete — {self.av.get_stats().get('infected', 0)} threats")
        self.scan_count.configure(text=f"{len(self.scan_table.tree.get_children())} threats found")

    def _refresh_quarantine(self):
        self.quar_table.clear()
        self.quar_detail.configure(state="normal")
        self.quar_detail.delete("1.0", "end")
        self.quar_detail.configure(state="disabled")
        entries = self.av.quarantine.list_quarantined()
        for e in entries:
            status = "QUARANTINED" if not e.get("restored") else "RESTORED"
            self.quar_table.add((status, os.path.basename(e["quarantined_path"]), e["original_path"], e.get("timestamp", "?")[:19]))

    def _restore_selected(self):
        sel = self.quar_table.get_selected()
        if not sel:
            messagebox.showwarning("No Selection", "Select an item from the quarantine list")
            return
        success, msg = self.av.quarantine.restore(sel[2])
        if success:
            messagebox.showinfo("Restored", f"Restored to:\n{msg}")
            self._refresh_quarantine()
        else:
            messagebox.showerror("Error", msg)

    def _delete_quarantined(self):
        sel = self.quar_table.get_selected()
        if not sel:
            messagebox.showwarning("No Selection", "Select an item from the quarantine list")
            return
        if not messagebox.askyesno("Confirm", "Permanently delete this file?"):
            return
        success, msg = self.av.quarantine.delete_permanently(sel[2])
        if success:
            self._refresh_quarantine()
        else:
            messagebox.showerror("Error", msg)

    def _toggle_realtime(self):
        if not self.realtime_active:
            self.av.start_realtime_protection(callback=self._rt_callback)
            self.realtime_active = True
            self.rt_status.configure(text="ACTIVE", foreground="green")
            self.rt_btn.configure(text="Stop Protection")
            self._rt_log("Real-time protection started")
        else:
            self.av.stop_realtime_protection()
            self.realtime_active = False
            self.rt_status.configure(text="INACTIVE", foreground="red")
            self.rt_btn.configure(text="Start Protection")
            self._rt_log("Real-time protection stopped")

    def _rt_callback(self, action, fpath):
        self.root.after(0, lambda: self._rt_log(f"[{action.upper()}] {fpath}"))

    def _rt_log(self, msg):
        self.rt_log.configure(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self.rt_log.insert("end", f"[{ts}] {msg}\n")
        self.rt_log.see("end")
        self.rt_log.configure(state="disabled")

    def _browse_lookup(self):
        path = filedialog.askopenfilename(title="Select file for online lookup")
        if path:
            self.lookup_path.set(path)

    def _do_lookup(self):
        path = self.lookup_path.get()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Error", "File not found")
            return
        self.lookup_result.configure(state="normal")
        self.lookup_result.delete("1.0", "end")
        self.lookup_result.insert("end", f"Looking up: {path}\nHashing...\n")
        self.lookup_result.configure(state="disabled")
        self._set_status("Looking up file online...")
        self.root.update()

        def task():
            result = self.av.lookup_online(path)
            self.root.after(0, lambda: self._show_lookup_result(result))

        threading.Thread(target=task, daemon=True).start()

    def _show_lookup_result(self, result):
        self.lookup_result.configure(state="normal")
        self.lookup_result.delete("1.0", "end")
        if result.get("detected"):
            self.lookup_result.insert("end", "\u26a0  THREAT DETECTED\n", "threat")
            self.lookup_result.tag_config("threat", foreground="red", font=("Menlo", 10, "bold"))
        else:
            self.lookup_result.insert("end", "\u2713  File appears clean\n", "clean")
            self.lookup_result.tag_config("clean", foreground="green", font=("Menlo", 10, "bold"))
        self.lookup_result.insert("end", f"Source: {result.get('source', 'N/A')}\n")
        self.lookup_result.insert("end", f"Malicious:  {result.get('malicious', 0)} engines\n")
        self.lookup_result.insert("end", f"Suspicious: {result.get('suspicious', 0)} engines\n")
        self.lookup_result.insert("end", f"Undetected: {result.get('undetected', 0)} engines\n")
        self.lookup_result.insert("end", f"Harmless:   {result.get('harmless', 0)} engines\n")
        if result.get("error"):
            self.lookup_result.insert("end", f"\nNote: {result['error']}\n")
        self.lookup_result.configure(state="disabled")
        self._set_status("Lookup complete")

    def _update_defs(self):
        self._set_status("Updating definitions...")

        def task():
            success, msg = self.av.update_virus_definitions()
            self.root.after(0, lambda: self._set_status(msg))
            self.root.after(0, lambda: messagebox.showinfo("Update" if success else "Update Failed", msg))

        threading.Thread(target=task, daemon=True).start()

    def _view_reports(self):
        if not os.path.isdir(REPORT_DIR):
            messagebox.showinfo("Reports", "No reports found")
            return
        reports = sorted([f for f in os.listdir(REPORT_DIR) if f.endswith(".json")], reverse=True)
        if not reports:
            messagebox.showinfo("Reports", "No reports found")
            return

        win = tk.Toplevel(self.root)
        win.title("Scan Reports")
        win.geometry("700x500")
        ttk.Label(win, text="Recent Reports", style="Heading.TLabel").pack(anchor="w", padx=10, pady=8)

        lb = tk.Listbox(win, font=("Menlo", 10))
        lb.pack(fill="both", expand=True, padx=10, pady=5)
        for r in reports[:30]:
            lb.insert("end", r)

        def show_report():
            sel = lb.curselection()
            if not sel:
                return
            name = lb.get(sel[0])
            with open(os.path.join(REPORT_DIR, name)) as f:
                data = json.load(f)
            text = json.dumps(data, indent=2)
            tw = tk.Toplevel(win)
            tw.title(name)
            tw.geometry("700x500")
            t = scrolledtext.ScrolledText(tw, font=("Menlo", 9))
            t.pack(fill="both", expand=True)
            t.insert("end", text)
            t.configure(state="disabled")

        ttk.Button(win, text="View Report", command=show_report).pack(pady=5)

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
        if messagebox.askyesno("Confirm", "Clear the activity log?"):
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
        app = ShieldGuardGUI()
        app.run()
    except Exception as e:
        messagebox.showerror("Error", str(e))
        raise
