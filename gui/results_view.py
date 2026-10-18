"""Results table with filters"""

import os
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk

from core.report import headline, offset_text

COLUMNS = [
    ("id", "ID", 60), ("name", "Name", 260), ("type", "Type", 110),
    ("separation", "Separation", 95), ("status", "Status", 100),
    ("offset", "Offset", 95), ("size", "Size", 85), ("method", "Method", 75),
    ("sha256", "SHA-256", 150),
]
FILTERS = ["All", "Deleted", "Non-deleted", "Unattributed", "TXT"]


def display_name(r, parents=None):
    if r.get("original_name"):
        return r["original_name"]
    if r.get("status") == "EMBEDDED" and parents is not None:
        parent = parents.get(r.get("parent_offset"))
        if parent is not None:
            return f"(embedded in {display_name(parent)} [{parent['id']}])"
    if r.get("export_path"):
        return os.path.basename(r["export_path"])
    return f"(offset {r.get('offset')})"


def matches(r, flt):
    if flt == "All":
        return True
    if flt == "TXT":
        return r.get("type") == "txt"
    return r.get("separation") == flt


class ResultsView(ttk.Frame):
    def __init__(self, parent, on_open_report=None, on_open_item=None):
        super().__init__(parent, padding=6)
        self.results = []
        self.on_open_item = on_open_item
        top = ttk.Frame(self)
        top.pack(fill="x")
        self.summary = ttk.Label(top, text="No results yet.", justify="left")
        self.summary.pack(side="left", anchor="w")
        self.report_button = ttk.Button(top, text="Open HTML report",
                                        command=on_open_report, state="disabled")
        self.report_button.pack(side="right")
        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(6, 4))
        ttk.Label(bar, text="Show:").pack(side="left", padx=(0, 6))
        self.filter = tk.StringVar(value="All")
        self.filter_buttons = {}
        for f in FILTERS:
            b = ttk.Radiobutton(bar, text=f, value=f, variable=self.filter,
                                command=self.refresh, style="Toolbutton")
            b.pack(side="left", padx=1)
            self.filter_buttons[f] = b
        self.count_label = ttk.Label(bar, text="")
        self.count_label.pack(side="right")
        body = ttk.Frame(self)
        body.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(body, columns=[c for c, _, _ in COLUMNS],
                                 show="headings", selectmode="browse")
        for col, head, width in COLUMNS:
            anchor = "e" if col in ("offset", "size") else "w"
            self.tree.heading(col, text=head)
            self.tree.column(col, width=width, anchor=anchor,
                             stretch=col == "name")
        ys = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        xs = ttk.Scrollbar(body, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)
        for tag, colour in (("Deleted", "#fff1f0"), ("Non-deleted", "#f0f8ff"),
                            ("Unattributed", "#f7f7f7")):
            self.tree.tag_configure(tag, background=colour)
        self.tree.bind("<Double-1>", self._double_click)
        self.tree.bind("<Return>", self._enter)

    def load(self, record):
        self.results = record.get("results") or []
        summ = record.get("summary") or {}
        rf = summ.get("recovered_files", {})
        eo = summ.get("embedded_objects", {})

        def seps(d):
            return ", ".join(f"{k} {v}" for k, v in d.items()) or "none"
        self.summary.config(text=(
            (headline(summ) if "complete" in rf else "")
            + f"   (complete: {seps(rf.get('complete_by_separation', {}))};"
              f"  partial: {seps(rf.get('partial_by_separation', {}))})"
            + f"\nCarved {rf.get('carved', 0)}, TXT via metadata "
              f"{rf.get('metadata_txt', 0)}.   Embedded objects (inside "
              f"recovered files, not counted as files): {eo.get('total', 0)}"))
        self.report_button.config(state="normal")
        self.refresh()

    def clear(self):
        self.results = []
        self.tree.delete(*self.tree.get_children())
        self.summary.config(text="No results yet.")
        self.count_label.config(text="")
        self.report_button.config(state="disabled")

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        flt = self.filter.get()
        parents = {r.get("offset"): r for r in self.results
                   if r.get("method") == "carved" and r["status"] != "EMBEDDED"}
        shown = 0
        for r in self.results:
            if not matches(r, flt):
                continue
            sub = f" / {r['subtype']}" if r.get("subtype") else ""
            sha = r.get("sha256") or ""
            self.tree.insert("", "end", iid=r["id"], tags=(r.get("separation"),),
                             values=(r["id"], display_name(r, parents),
                                     r["type"] + sub,
                                     r.get("separation") or "", r["status"],
                                     offset_text(r),
                                     f"{r.get('length') or 0:,}",
                                     "Carved" if r["method"] == "carved"
                                     else "Metadata",
                                     sha[:16] + "…" if sha else ""))
            shown += 1
        self.count_label.config(text=f"{shown} of {len(self.results)} shown")
        self._fit_columns()

    def _fit_columns(self):
        """Size the short columns to their widest cell so nothing is cut off
        (e.g. "mp3 / mpeg1-layer3", "RECOVERED")."""
        font = tkfont.nametofont("TkDefaultFont")
        heading = tkfont.nametofont("TkHeadingFont")
        for col in ("type", "separation", "status", "offset", "size", "method"):
            texts = [self.tree.set(iid, col) for iid in self.tree.get_children()]
            head = next(h for c, h, _ in COLUMNS if c == col)
            width = max([font.measure(t) for t in texts] + [heading.measure(head)])
            self.tree.column(col, width=width + 24, minwidth=width + 24)

    def visible_ids(self):
        return list(self.tree.get_children())

    def _double_click(self, event):
        iid = self.tree.identify_row(event.y)
        if iid and self.on_open_item:
            self.on_open_item(next(r for r in self.results if r["id"] == iid))

    def _enter(self, event):
        sel = self.tree.selection()
        if sel and self.on_open_item:
            self.on_open_item(next(r for r in self.results if r["id"] == sel[0]))
