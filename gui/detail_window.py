"""Detail window for one result: metadata panel + hex viewer"""

import os
import tkinter as tk
from tkinter import ttk

from core import hashing
from core.report import RESULT_FIELDS, offset_text, ts_display
from gui.hexview import HexView, FileSource

# Label for every result field; group decides where it appears.
FIELD_LAYOUT = [
    ("Identification", [("id", "ID"), ("method", "Method"), ("type", "Type"),
                        ("subtype", "Subtype"), ("status", "Status"),
                        ("parser_status", "Parser status"),
                        ("separation", "Separation label"),
                        ("attributed", "Attributed to a file-system entry")]),
    ("Location", [("offset", "Offset in image (absolute)"),
                  ("end", "End offset (exclusive)"),
                  ("length", "Length (bytes)"),
                  ("parent_offset", "Parent file offset (embedded)"),
                  ("extension", "Export extension")]),
    ("File system", [("original_name", "Original name"),
                     ("original_path", "Original path"),
                     ("meta_addr", "MFT entry / inode"),
                     ("resident", "Resident in MFT"),
                     ("fs_size", "File-system size (bytes)"),
                     ("size_consistent", "Length equals file-system size"),
                     ("fs_data_runs", "File-system data runs"),
                     ("all_zero", "Content entirely 0x00"),
                     ("timestamp_basis", "Timestamp basis")]),
    ("Timestamps", [("timestamps", "Timestamps")]),
    ("Hashes", [("md5", "MD5"), ("sha256", "SHA-256"),
                ("export_hash_match", "Export matches carved range")]),
    ("Export", [("export_path", "Export path")]),
    ("Parser checks", [("checks", "Checks")]),
    ("Notes", [("notes", "Notes")]),
    ("Format details", [("details", "Details")]),
]
LAYOUT_FIELDS = {f for _, fields in FIELD_LAYOUT for f, _ in fields}
assert LAYOUT_FIELDS == set(RESULT_FIELDS), "every report field must be shown"

FILE_MODE, IMAGE_MODE = "file", "image"


def _fmt(value):
    if value is None or value == "":
        return "—"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, int):
        return f"{value:,}"
    return str(value)


def result_title(result):
    name = result.get("original_name") or os.path.basename(
        result.get("export_path") or "") or f"offset {result.get('offset')}"
    return f"{result['id']} – {name}"


class DetailWindow(tk.Toplevel):
    def __init__(self, parent, result, working_copy):
        super().__init__(parent)
        self.result = result
        self.working_copy = working_copy
        self.title(f"LiteCarve – {result_title(result)}")
        self.geometry("1350x760")
        pane = ttk.PanedWindow(self, orient="horizontal")
        pane.pack(fill="both", expand=True, padx=6, pady=6)

        left = ttk.Frame(pane)
        self.meta = ttk.Treeview(left, columns=("value",), show="tree headings")
        self.meta.heading("#0", text="Field")
        self.meta.heading("value", text="Value")
        self.meta.column("#0", width=270, stretch=False)
        self.meta.column("value", width=330, stretch=True)
        ys = ttk.Scrollbar(left, orient="vertical", command=self.meta.yview)
        self.meta.configure(yscrollcommand=ys.set)
        self.meta.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)
        # Full text of the selected field (long hashes, paths, timestamps and
        # notes do not fit in the table column).
        ttk.Label(left, text="Selected value").grid(row=1, column=0, sticky="w",
                                                    pady=(6, 0))
        self.value_box = tk.Text(left, height=3, wrap="word",
                                 font=("TkFixedFont", 9), state="disabled")
        self.value_box.grid(row=2, column=0, columnspan=2, sticky="ew")
        self.meta.bind("<<TreeviewSelect>>", lambda e: self._show_selected())
        btns = ttk.Frame(left)
        btns.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        ttk.Button(btns, text="Copy value", command=self.copy_value).pack(
            side="left")
        self.rehash_button = ttk.Button(btns, text="Re-hash exported file",
                                        command=self.rehash)
        self.rehash_button.pack(side="left", padx=6)
        self.rehash_label = ttk.Label(btns, text="")
        self.rehash_label.pack(side="left")
        self.meta.bind("<Control-c>", lambda e: self.copy_value())
        pane.add(left, weight=2)

        right = ttk.Frame(pane)
        src = ttk.Frame(right)
        src.pack(fill="x", pady=(0, 4))
        ttk.Label(src, text="Show:").pack(side="left")
        self.mode = tk.StringVar()
        self.file_radio = ttk.Radiobutton(
            src, text="Exported file (offsets relative to the file)",
            value=FILE_MODE, variable=self.mode, command=self.switch)
        self.file_radio.pack(side="left", padx=6)
        self.image_radio = ttk.Radiobutton(
            src, text="Working image at carved offset (absolute offsets)",
            value=IMAGE_MODE, variable=self.mode, command=self.switch)
        self.image_radio.pack(side="left")
        self.source_note = ttk.Label(right, text="", foreground="#555")
        self.source_note.pack(fill="x")
        self.hex = HexView(right)
        self.hex.pack(fill="both", expand=True)
        pane.add(right, weight=3)

        self._fill_metadata()
        self._setup_sources()

    # --------------------------------------------------------- metadata

    def _fill_metadata(self):
        r = self.result
        for group, fields in FIELD_LAYOUT:
            gid = self.meta.insert("", "end", text=group, open=True)
            for key, label in fields:
                value = r.get(key)
                if key == "offset":
                    self.meta.insert(gid, "end", iid=f"f:{key}", text=label,
                                     values=(offset_text(r) or "—",))
                elif key == "timestamps":
                    stamps = value or {}
                    for t in ("mtime", "atime", "ctime", "crtime"):
                        self.meta.insert(gid, "end", iid=f"f:ts:{t}",
                                         text={"mtime": "Modified",
                                               "atime": "Accessed",
                                               "ctime": "Metadata changed",
                                               "crtime": "Created"}[t],
                                         values=(ts_display(stamps.get(t))
                                                 or "—",))
                elif key in ("checks", "notes"):
                    for i, line in enumerate(value or ["—"]):
                        self.meta.insert(gid, "end", iid=f"f:{key}:{i}",
                                         text=f"{label} {i + 1}" if value
                                         else label, values=(line,))
                elif key == "details":
                    items = (value or {}).items()
                    for k, v in items:
                        self.meta.insert(gid, "end", iid=f"f:details:{k}",
                                         text=k, values=(_fmt(v),))
                    if not items:
                        self.meta.insert(gid, "end", iid="f:details:-",
                                         text=label, values=("—",))
                else:
                    self.meta.insert(gid, "end", iid=f"f:{key}", text=label,
                                     values=(_fmt(value),))

    def field_value(self, iid):
        return self.meta.set(iid, "value")

    def _show_selected(self):
        sel = self.meta.selection()
        text = self.meta.set(sel[0], "value") if sel and \
            self.meta.parent(sel[0]) else ""
        self.value_box.config(state="normal")
        self.value_box.delete("1.0", "end")
        self.value_box.insert("1.0", text)
        self.value_box.config(state="disabled")

    def copy_value(self):
        sel = self.meta.selection()
        if sel:
            self.clipboard_clear()
            self.clipboard_append(self.meta.set(sel[0], "value"))

    def rehash(self):
        path = self.result.get("export_path")
        if not path or not os.path.isfile(path):
            self.rehash_label.config(text="no exported file", foreground="#a00000")
            return None
        h = hashing.hash_file(path)
        ok = (h.md5, h.sha256) == (self.result.get("md5"),
                                   self.result.get("sha256"))
        self.rehash_label.config(
            text="MATCH (MD5 and SHA-256 as recorded)" if ok else
            f"MISMATCH: now SHA-256 {h.sha256[:16]}…",
            foreground="#0a6a0a" if ok else "#a00000")
        return ok

    # ---------------------------------------------------------- hex view

    def _setup_sources(self):
        r = self.result
        self.file_source = self.image_source = None
        self.file_reason = self.image_reason = ""
        path = r.get("export_path")
        if path and os.path.isfile(path):
            self.file_source = FileSource(path, "Exported file")
        elif r.get("status") == "EMBEDDED" and not path:
            self.file_reason = ("Embedded object not exported (setting off); "
                                "view it in the working image.")
        else:
            self.file_reason = "Exported file not found."
        if r.get("offset") is None:
            self.image_reason = ("Resident NTFS file: its content is stored "
                                 "inside the MFT record, so there is no data "
                                 "offset in the image." if r.get("resident")
                                 else "No image offset for this result.")
        elif not self.working_copy or not os.path.isfile(self.working_copy):
            self.image_reason = "Working copy not found."
        else:
            self.image_source = FileSource(self.working_copy, "Working image")
        self.file_radio.config(state="normal" if self.file_source else "disabled")
        self.image_radio.config(state="normal" if self.image_source
                                else "disabled")
        notes = [x for x in (self.file_reason, self.image_reason) if x]
        if self.image_source:
            notes.append("In the image view the carved range is tinted yellow "
                         "and its first byte orange."
                         if r["method"] == "carved" else
                         "In the image view the first byte of the file's "
                         "first data run is marked.")
        self.source_note.config(text="  ".join(notes), wraplength=760,
                                justify="left")
        self.mode.set(FILE_MODE if self.file_source else IMAGE_MODE)
        if self.file_source or self.image_source:
            self.switch()

    def switch(self):
        r = self.result
        if self.mode.get() == FILE_MODE and self.file_source:
            self.hex.set_source(self.file_source, 0)
        elif self.image_source:
            start = r["offset"]
            # Carved results: tint exactly the carved range. Metadata (TXT)
            # results: only the first data run's start is known for sure.
            end = start + (r.get("length") or 0) if r["method"] == "carved" \
                else start + 1
            self.hex.set_source(self.image_source, start, highlight=(start, end))
