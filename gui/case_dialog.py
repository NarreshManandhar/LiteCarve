"""Case details dialog"""

import tkinter as tk
from tkinter import ttk

from core.case import CaseDetails

FIELDS = [
    ("examiner_name", "Examiner name *"),
    ("case_number", "Case number *"),
    ("examiner_id", "Examiner ID"),
    ("organisation", "Organisation"),
    ("evidence_description", "Evidence item description"),
]


class CaseDialog(tk.Toplevel):
    """Modal form; after it closes, ``result`` is a CaseDetails or None."""

    def __init__(self, parent, initial=None, modal=True):
        super().__init__(parent)
        self.title("Case details")
        self.transient(parent)
        self.resizable(True, False)
        self.result = None
        self.vars = {}
        frm = ttk.Frame(self, padding=12)
        frm.grid(sticky="nsew")
        self.columnconfigure(0, weight=1)
        frm.columnconfigure(1, weight=1)
        for row, (key, label) in enumerate(FIELDS):
            ttk.Label(frm, text=label).grid(row=row, column=0, sticky="w",
                                            padx=(0, 8), pady=3)
            var = tk.StringVar(value=getattr(initial, key, "") if initial else "")
            entry = ttk.Entry(frm, textvariable=var, width=48)
            entry.grid(row=row, column=1, sticky="ew", pady=3)
            self.vars[key] = var
            if row == 0:
                entry.focus_set()
        row = len(FIELDS)
        ttk.Label(frm, text="Notes").grid(row=row, column=0, sticky="nw",
                                          padx=(0, 8), pady=3)
        self.notes = tk.Text(frm, width=48, height=4, wrap="word")
        self.notes.grid(row=row, column=1, sticky="ew", pady=3)
        if initial and initial.notes:
            self.notes.insert("1.0", initial.notes)
        self.error = ttk.Label(frm, text="", foreground="#a00000")
        self.error.grid(row=row + 1, column=0, columnspan=2, sticky="w")
        ttk.Label(frm, text="* required", foreground="#555").grid(
            row=row + 2, column=0, sticky="w")
        btns = ttk.Frame(frm)
        btns.grid(row=row + 2, column=1, sticky="e", pady=(8, 0))
        self.ok_button = ttk.Button(btns, text="OK", command=self.ok)
        self.ok_button.pack(side="left", padx=4)
        ttk.Button(btns, text="Cancel", command=self.cancel).pack(side="left")
        self.bind("<Return>", lambda e: self.ok())
        self.bind("<Escape>", lambda e: self.cancel())
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        if modal:
            self.grab_set()
            self.wait_window(self)

    def case(self):
        values = {k: v.get() for k, v in self.vars.items()}
        values["notes"] = self.notes.get("1.0", "end").rstrip("\n")
        return CaseDetails(**values)

    def ok(self):
        case = self.case()
        problems = case.validate()
        if problems:
            self.error.config(text="  ".join(problems))
            return
        self.result = case
        self.destroy()

    def cancel(self):
        self.result = None
        self.destroy()
