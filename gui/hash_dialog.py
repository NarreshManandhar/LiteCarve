"""Hash confirmation dialog"""

import tkinter as tk
from tkinter import ttk

GREEN, RED = "#0a6a0a", "#a00000"


class HashDialog(tk.Toplevel):
    """Modal; after it closes, ``proceed`` is True or False."""

    def __init__(self, parent, comparison, modal=True):
        super().__init__(parent)
        self.title("Working copy verification")
        self.transient(parent)
        self.resizable(False, False)
        self.proceed = False
        match = comparison["match"]
        exp, act = comparison["expected"], comparison["actual"]
        frm = ttk.Frame(self, padding=14)
        frm.grid()
        headline = ("The working copy is identical to the evidence."
                    if match else
                    "HASH MISMATCH: the working copy is NOT identical to the "
                    "evidence. Analysis has been stopped.")
        ttk.Label(frm, text=headline, foreground=GREEN if match else RED,
                  font=("TkDefaultFont", 11, "bold")).grid(
            row=0, column=0, columnspan=4, sticky="w", pady=(0, 10))
        for col, text in enumerate(("", "Original evidence", "Working copy",
                                    "Result")):
            ttk.Label(frm, text=text, font=("TkDefaultFont", 9, "bold")).grid(
                row=1, column=col, sticky="w", padx=6)
        mono = ("TkFixedFont", 9)
        self.result_labels = {}
        for row, (key, label) in enumerate((("md5", "MD5"),
                                            ("sha256", "SHA-256"),
                                            ("size", "Size (bytes)")), start=2):
            ttk.Label(frm, text=label).grid(row=row, column=0, sticky="w", padx=6)
            for col, src in ((1, exp), (2, act)):
                ttk.Label(frm, text=str(src[key]), font=mono).grid(
                    row=row, column=col, sticky="w", padx=6, pady=2)
            res = comparison[key]
            lbl = ttk.Label(frm, text=res, foreground=GREEN if res == "MATCH"
                            else RED, font=("TkDefaultFont", 9, "bold"))
            lbl.grid(row=row, column=3, sticky="w", padx=6)
            self.result_labels[key] = lbl
        btns = ttk.Frame(frm)
        btns.grid(row=6, column=0, columnspan=4, sticky="e", pady=(12, 0))
        self.proceed_button = ttk.Button(btns, text="Proceed with analysis",
                                         command=self._proceed)
        if match:
            self.proceed_button.pack(side="left", padx=4)
        self.abort_button = ttk.Button(btns, text="Abort", command=self._abort)
        self.abort_button.pack(side="left")
        (self.proceed_button if match else self.abort_button).focus_set()
        self.protocol("WM_DELETE_WINDOW", self._abort)
        if modal:
            self.grab_set()
            self.wait_window(self)

    def _proceed(self):
        self.proceed = True
        self.destroy()

    def _abort(self):
        self.proceed = False
        self.destroy()
