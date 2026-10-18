"""LiteCarve main window"""

import gc
import json
import os
import queue
import threading
import time
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from core import VERSION, TOOL_NAME
from core.pipeline import Pipeline, Settings, STEPS
from gui.case_dialog import CaseDialog
from gui.detail_window import DetailWindow
from gui.hash_dialog import HashDialog
from gui.results_view import ResultsView

POLL_MS = 100
MAX_EVENTS_PER_TICK = 400
# Log lines are shown shortened in the pane; the full text is always in
# reports/run_log.txt. Very long lines make Tk's no-wrap Text layout slow.
MAX_LOG_LINE = 240
# Rough share of run time per step, used only for the overall progress bar.
STEP_WEIGHTS = {"hash_evidence": 3, "working_copy": 6, "carve": 4,
                "export": 1, "rehash": 6}
SHOW_RESULTS = ("show_results", "Show results")
STATUS_TEXT = {"pending": "pending", "running": "running…", "done": "done",
               "failed": "failed", "skipped": "not run"}


class LiteCarveApp:
    def __init__(self, root, ask_case_on_start=True, pipeline_factory=Pipeline):
        self.root = root
        self.pipeline_factory = pipeline_factory
        self.case = None
        self.case_dir = ""
        self.record = None            # report.json of the last run
        self.detail_windows = []
        self.queue = queue.Queue()
        self.worker = None
        self.cancel_event = None
        self.last_status = None
        self.poll_times = []          # used by the responsiveness test
        self._pending_log = []
        self._close_requested = False
        root.title(f"{TOOL_NAME} {VERSION}")
        root.geometry("1200x780")
        root.minsize(900, 600)
        style = ttk.Style(root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        self._build_menu()
        self._build_widgets()
        self._set_running(False)
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        if ask_case_on_start:
            root.after(50, self.new_case)

    # ------------------------------------------------------------ layout

    def _build_menu(self):
        bar = tk.Menu(self.root)
        file_menu = tk.Menu(bar, tearoff=False)
        file_menu.add_command(label="New case…", command=self.new_case)
        file_menu.add_command(label="Open report folder",
                              command=self.open_report_folder)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)
        help_menu = tk.Menu(bar, tearoff=False)
        help_menu.add_command(label="About", command=self.about)
        bar.add_cascade(label="File", menu=file_menu)
        bar.add_cascade(label="Help", menu=help_menu)
        self.root.config(menu=bar)
        self.file_menu = file_menu

    def _build_widgets(self):
        outer = ttk.Frame(self.root, padding=8)
        outer.pack(fill="both", expand=True)

        case_row = ttk.Frame(outer)
        case_row.pack(fill="x")
        self.case_label = ttk.Label(case_row, text="No case details entered.",
                                    font=("TkDefaultFont", 10, "bold"))
        self.case_label.pack(side="left")
        self.case_button = ttk.Button(case_row, text="Edit case details…",
                                      command=self.new_case)
        self.case_button.pack(side="right")

        sel = ttk.LabelFrame(outer, text="Evidence and output", padding=6)
        sel.pack(fill="x", pady=6)
        sel.columnconfigure(1, weight=1)
        self.image_var = tk.StringVar()
        self.output_var = tk.StringVar()
        self.embedded_var = tk.BooleanVar(value=False)
        ttk.Label(sel, text="Evidence image").grid(row=0, column=0, sticky="w")
        self.image_entry = ttk.Entry(sel, textvariable=self.image_var)
        self.image_entry.grid(row=0, column=1, sticky="ew", padx=6, pady=2)
        self.image_button = ttk.Button(sel, text="Browse…",
                                       command=self.browse_image)
        self.image_button.grid(row=0, column=2)
        ttk.Label(sel, text="Output folder").grid(row=1, column=0, sticky="w")
        self.output_entry = ttk.Entry(sel, textvariable=self.output_var)
        self.output_entry.grid(row=1, column=1, sticky="ew", padx=6, pady=2)
        self.output_button = ttk.Button(sel, text="Browse…",
                                        command=self.browse_output)
        self.output_button.grid(row=1, column=2)
        self.embedded_check = ttk.Checkbutton(
            sel, text="Export embedded objects (e.g. EXIF thumbnails)",
            variable=self.embedded_var)
        self.embedded_check.grid(row=2, column=1, sticky="w", padx=6)

        run = ttk.Frame(outer)
        run.pack(fill="x", pady=(0, 6))
        self.start_button = ttk.Button(run, text="Start", command=self.start)
        self.start_button.pack(side="left")
        self.cancel_button = ttk.Button(run, text="Cancel", command=self.cancel)
        self.cancel_button.pack(side="left", padx=6)
        self.progress = ttk.Progressbar(run, maximum=100, mode="determinate")
        self.progress.pack(side="left", fill="x", expand=True, padx=6)
        self.step_label = ttk.Label(run, text="Idle", width=62)
        self.step_label.pack(side="left")

        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill="both", expand=True)
        run_tab = ttk.Frame(self.notebook, padding=4)
        self.notebook.add(run_tab, text="Run")
        pane = ttk.PanedWindow(run_tab, orient="horizontal")
        pane.pack(fill="both", expand=True)
        stages = ttk.Frame(pane)
        self.stage_tree = ttk.Treeview(stages, columns=("status", "seconds"),
                                       show="tree headings", height=16,
                                       selectmode="none")
        self.stage_tree.heading("#0", text="Step")
        self.stage_tree.heading("status", text="Status")
        self.stage_tree.heading("seconds", text="Seconds")
        self.stage_tree.column("#0", width=330)
        self.stage_tree.column("status", width=80)
        self.stage_tree.column("seconds", width=120, anchor="e")
        for tag, colour in (("running", "#fff4c2"), ("done", "#dff3df"),
                            ("failed", "#f8d0d0"), ("skipped", "#eeeeee")):
            self.stage_tree.tag_configure(tag, background=colour)
        self.stage_tree.pack(fill="both", expand=True)
        pane.add(stages, weight=1)
        logf = ttk.Frame(pane)
        self.log_text = tk.Text(logf, wrap="none", font=("TkFixedFont", 9),
                                state="disabled", height=16)
        ys = ttk.Scrollbar(logf, orient="vertical", command=self.log_text.yview)
        xs = ttk.Scrollbar(logf, orient="horizontal", command=self.log_text.xview)
        self.log_text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        logf.rowconfigure(0, weight=1)
        logf.columnconfigure(0, weight=1)
        self.log_text.tag_configure("WARNING", foreground="#8a5a00")
        self.log_text.tag_configure("ERROR", foreground="#b00000")
        pane.add(logf, weight=3)

        self.results_view = ResultsView(self.notebook,
                                        on_open_report=self.open_html_report,
                                        on_open_item=self.open_detail)
        self.notebook.add(self.results_view, text="Results")

        self.status_bar = ttk.Label(outer, text="", foreground="#444")
        self.status_bar.pack(fill="x", pady=(4, 0))
        self._reset_stages()

    def _all_steps(self):
        return list(STEPS) + [SHOW_RESULTS]

    def _reset_stages(self):
        self.stage_tree.delete(*self.stage_tree.get_children())
        for n, (sid, label) in enumerate(self._all_steps(), start=3):
            self.stage_tree.insert("", "end", iid=sid, text=f"{n}. {label}",
                                   values=(STATUS_TEXT["pending"], ""),
                                   tags=("pending",))
        self.step_state = {sid: "pending" for sid, _ in self._all_steps()}
        self.step_fraction = 0.0
        self.progress["value"] = 0

    def _set_stage(self, sid, state, seconds=""):
        self.step_state[sid] = state
        self.stage_tree.item(sid, values=(STATUS_TEXT[state], seconds),
                             tags=(state,))

    def _set_running(self, running):
        idle = "disabled" if running else "normal"
        for w in (self.start_button, self.case_button, self.image_entry,
                  self.image_button, self.output_entry, self.output_button,
                  self.embedded_check):
            w.config(state=idle)
        self.cancel_button.config(state="normal" if running else "disabled")
        self.file_menu.entryconfig("New case…", state=idle)

    # ------------------------------------------------------------ actions

    def new_case(self):
        dlg = CaseDialog(self.root, initial=self.case)
        if dlg.result is not None:
            self.set_case(dlg.result)

    def set_case(self, case):
        self.case = case
        self.case_label.config(text=f"Case {case.case_number}   ·   Examiner "
                                    f"{case.examiner_name}"
                                    + (f" ({case.examiner_id})"
                                       if case.examiner_id else "")
                                    + (f"   ·   {case.organisation}"
                                       if case.organisation else ""))

    def browse_image(self):
        path = filedialog.askopenfilename(
            parent=self.root, title="Select evidence image",
            filetypes=[("Raw disk images", "*.dd *.img *.raw"),
                       ("All files", "*")])
        if path:
            self.image_var.set(path)

    def browse_output(self):
        path = filedialog.askdirectory(parent=self.root,
                                       title="Select output folder")
        if path:
            self.output_var.set(path)

    def validate_inputs(self):
        problems = []
        if self.case is None:
            problems.append("Enter the case details first (File > New case).")
        else:
            problems += self.case.validate()
        image, out = self.image_var.get().strip(), self.output_var.get().strip()
        if not image or not os.path.isfile(image):
            problems.append("Select an existing evidence image file.")
        if not out:
            problems.append("Select an output folder.")
        return problems

    def start(self):
        problems = self.validate_inputs()
        if problems:
            messagebox.showerror("Cannot start", "\n".join(problems),
                                 parent=self.root)
            return False
        self._reset_stages()
        self.results_view.clear()
        self._clear_log()
        self.case_dir = ""
        self.last_status = None
        self.cancel_event = threading.Event()
        # Python's cyclic garbage collector runs in whichever thread happens
        # to trigger it. Collect now, on the GUI thread, so Tk objects left
        # over from closed dialogs (e.g. StringVars, whose cleanup calls Tcl)
        # are never freed by the worker thread (DESIGN.md I-37).
        gc.collect()
        pipeline = self.pipeline_factory(
            self.case, self.image_var.get().strip(),
            self.output_var.get().strip(),
            settings=Settings(export_embedded=self.embedded_var.get()),
            on_event=self.queue.put,          # the only link worker -> GUI
            confirm_hashes=self._confirm_from_worker,
            cancel_event=self.cancel_event)
        self.worker = threading.Thread(target=pipeline.run, name="pipeline",
                                       daemon=True)
        self._set_running(True)
        self.step_label.config(text="Starting…")
        self.worker.start()
        self.root.after(POLL_MS, self._poll)
        return True

    def cancel(self):
        if self.cancel_event is not None and self.is_running():
            self.cancel_event.set()
            self.step_label.config(text="Cancelling… (stops at the next check)")

    def is_running(self):
        return self.worker is not None and self.worker.is_alive()

    # ------------------------------------------------- worker <-> GUI bridge

    def _confirm_from_worker(self, comparison):
        """Runs in the WORKER thread: ask the GUI, wait for the answer."""
        reply = {"proceed": False}
        done = threading.Event()
        self.queue.put({"type": "confirm_request", "comparison": comparison,
                        "reply": reply, "done": done})
        while not done.wait(0.2):
            if self.cancel_event.is_set():
                return False
        return reply["proceed"]

    def ask_hash_confirmation(self, comparison):
        """GUI thread. Separate method so tests can answer automatically."""
        return HashDialog(self.root, comparison).proceed

    def show_mismatch(self, comparison):
        HashDialog(self.root, comparison)

    def _poll(self):
        self.poll_times.append(time.perf_counter())
        self._pending_log = []
        handled = 0
        while handled < MAX_EVENTS_PER_TICK:
            try:
                event = self.queue.get_nowait()
            except queue.Empty:
                break
            handled += 1
            self._handle(event)
        if self._close_requested and self.last_status is not None:
            # The run has ended after a close request: close the window now,
            # as the last action of this tick (no widget is touched after).
            self.root.destroy()
            return
        self._flush_log()
        if self.is_running() or not self.queue.empty():
            self.root.after(POLL_MS, self._poll)
        elif self.last_status is None:
            # Worker ended without a "finished" event (should not happen).
            self._finish({"status": "error", "message": "worker stopped",
                          "case_dir": self.case_dir, "exit_code": 1})

    def _handle(self, e):
        kind = e["type"]
        if kind == "log":
            self._pending_log.append((e["line"], e["level"]))
        elif kind == "step_start":
            self._set_stage(e["step"], "running")
            self.step_fraction = 0.0
            self.step_label.config(text=e["label"] + "…")
            self._update_progress()
        elif kind == "step_done":
            # Processing time only; waiting for the examiner shown apart.
            secs = f"{e['seconds']:.2f}"
            if e.get("examiner_wait"):
                secs += f" (+{e['examiner_wait']:.1f} wait)"
            self._set_stage(e["step"], "done", secs)
            self.step_fraction = 0.0
            self._update_progress()
        elif kind == "step_failed":
            self._set_stage(e["step"], "failed")
        elif kind == "progress":
            if e["total"]:
                self.step_fraction = min(1.0, e["done"] / e["total"])
                self._update_progress()
        elif kind == "hash_comparison":
            if not e["comparison"]["match"]:
                self.root.after(0, self.show_mismatch, e["comparison"])
        elif kind == "confirm_request":
            # Shown from a separate callback, not inside this loop, so the
            # dialog's own event loop never re-enters _poll's loop.
            self.root.after(0, self._answer_confirm, e)
        elif kind == "finished":
            self._finish(e)

    def _answer_confirm(self, e):
        e["reply"]["proceed"] = bool(self.ask_hash_confirmation(e["comparison"]))
        e["done"].set()

    def _update_progress(self):
        total = done = 0.0
        for sid, _ in self._all_steps():
            w = STEP_WEIGHTS.get(sid, 0.5)
            total += w
            st = self.step_state[sid]
            if st == "done":
                done += w
            elif st == "running":
                done += w * self.step_fraction
        self.progress["value"] = 100.0 * done / total if total else 0

    def _finish(self, e):
        self.last_status = e["status"]
        self.case_dir = e.get("case_dir") or ""
        for sid, st in self.step_state.items():
            if st in ("pending", "running") and sid != SHOW_RESULTS[0]:
                self._set_stage(sid, "skipped" if st == "pending" else "failed")
        self._set_running(False)
        loaded = self._load_results()
        if loaded:
            self._set_stage(SHOW_RESULTS[0], "done")
            self.notebook.select(self.results_view)
        else:
            self._set_stage(SHOW_RESULTS[0], "skipped")
        if e["status"] == "completed":
            self.progress["value"] = 100
        timing = ""
        if e.get("wall_seconds") is not None:
            timing = (f" · processing {e['processing_seconds']:.1f} s, "
                      f"examiner {e['examiner_wait_seconds']:.1f} s")
        self.step_label.config(text=f"Finished: {e['status']} "
                                    f"(exit code {e.get('exit_code')}){timing}")
        self.status_bar.config(text=f"Case folder: {self.case_dir}"
                               if self.case_dir else "")
        if self._close_requested:
            return            # _poll() closes the window after this tick
        self.root.after(0, self.announce, e)

    def announce(self, e):
        """Tell the examiner how the run ended (separate so tests can skip)."""
        msg = e.get("message") or ""
        if e["status"] == "completed":
            messagebox.showinfo("Run complete", msg + "\n\nResults are shown "
                                "in the Results tab.", parent=self.root)
        elif e["status"] == "cancelled":
            messagebox.showwarning("Run cancelled", msg, parent=self.root)
        else:
            messagebox.showerror(f"Run ended: {e['status']}", msg,
                                 parent=self.root)

    def _load_results(self):
        path = os.path.join(self.case_dir, "reports", "report.json")
        if not self.case_dir or not os.path.isfile(path):
            return False
        with open(path, encoding="utf-8") as f:
            record = json.load(f)
        if not record.get("results") and record.get("status") != "completed":
            return False
        self.record = record
        self.results_view.load(record)
        return True

    def open_detail(self, result):
        """Open the detail window (metadata + hex view) for one result."""
        wc = ((self.record or {}).get("working_copy") or {}).get("path")
        win = DetailWindow(self.root, result, wc)
        self.detail_windows = [w for w in self.detail_windows
                               if w.winfo_exists()] + [win]
        return win

    # --------------------------------------------------------- log pane

    def _flush_log(self):
        """Insert this tick's log lines with one Text call and one scroll."""
        if not self._pending_log:
            return
        args = []
        for line, level in self._pending_log:
            if len(line) > MAX_LOG_LINE:
                line = line[:MAX_LOG_LINE] + " … (full line in run_log.txt)"
            args += [line + "\n",
                     (level,) if level in ("WARNING", "ERROR") else ()]
        self._pending_log = []
        self.log_text.config(state="normal")
        self.log_text.insert("end", *args)
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def log_lines(self):
        return self.log_text.get("1.0", "end").splitlines()

    def _clear_log(self):
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")

    # ------------------------------------------------------ other menu items

    def _open_own_report(self, path):
        """Hand one of LiteCarve's OWN report outputs to the desktop viewer.

        Only paths inside the current case's reports/ folder are allowed, so
        webbrowser can never be given the evidence, the working copy or a
        recovered file (decision I-34 / C-14). Returns True if opened.
        """
        if not self.case_dir:
            return False
        reports = os.path.realpath(os.path.join(self.case_dir, "reports"))
        real = os.path.realpath(path)
        if real != reports and not real.startswith(reports + os.sep):
            return False
        if not os.path.exists(real):
            return False
        webbrowser.open(Path(real).as_uri())
        return True

    def open_report_folder(self):
        target = os.path.join(self.case_dir, "reports") if self.case_dir else ""
        if not self._open_own_report(target):
            messagebox.showinfo("No report yet", "Run an examination first.",
                                parent=self.root)

    def open_html_report(self):
        self._open_own_report(os.path.join(self.case_dir, "reports",
                                           "report.html"))

    def about(self):
        messagebox.showinfo(
            f"About {TOOL_NAME}",
            f"{TOOL_NAME} {VERSION}\nLightweight, transparent signature-based "
            "file carving for NTFS and FAT32 raw images.\n\nMaster's "
            "dissertation tool (AUT, COMP997).", parent=self.root)

    def on_close(self):
        if self.is_running():
            if not messagebox.askyesno(
                    "Run in progress", "An examination is running. Cancel it "
                    "and close LiteCarve when it has stopped?", parent=self.root):
                return
            self._close_requested = True
            self.cancel()
            return            # _finish() closes the window when the run ends
        self.root.destroy()


def main():
    root = tk.Tk()
    LiteCarveApp(root)
    root.mainloop()
    return 0
