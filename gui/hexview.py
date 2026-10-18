"""Reusable read-only hex/ASCII viewer"""

import os
import tkinter as tk
from tkinter import ttk

PAGE_SIZE = 64 * 1024
ROW = 16


# ------------------------------------------------------------------ pure code

def offset_digits(size):
    """Hex digits for the offset column: 8 minimum."""
    return max(8, len(f"{max(size - 1, 0):x}"))


def ascii_char(b):
    return chr(b) if 0x20 <= b <= 0x7E else "."


def format_row(data, offset, digits):
    """One row: offset, 16 hex bytes in two groups of 8, ASCII column."""
    hexes = [f"{b:02X}" for b in data] + ["  "] * (ROW - len(data))
    hex_part = " ".join(hexes[:8]) + "  " + " ".join(hexes[8:])
    text = "".join(ascii_char(b) for b in data)
    return f"{offset:0{digits}X}  {hex_part}  |{text}|"


def format_rows(data, base, digits):
    return "\n".join(format_row(data[i:i + ROW], base + i, digits)
                     for i in range(0, len(data), ROW))


def hex_columns(digits):
    """Character columns of byte i's hex digits and ASCII char in a row."""
    hex_start = digits + 2
    hex_cols = [hex_start + 3 * i + (1 if i >= 8 else 0) for i in range(ROW)]
    ascii_start = hex_cols[-1] + 2 + 3        # "XX" + two spaces + "|"
    return hex_cols, [ascii_start + i for i in range(ROW)]


def parse_offset(text):
    """Parse "0x1A2B", "1A2Bh", "6699" or "6_699"; ValueError if invalid."""
    t = text.strip().replace("_", "").replace(",", "")
    if not t:
        raise ValueError("empty offset")
    if t.lower().startswith("0x"):
        value = int(t[2:], 16)
    elif t.lower().endswith("h"):
        value = int(t[:-1], 16)
    else:
        value = int(t, 10)
    if value < 0:
        raise ValueError("negative offset")
    return value


class FileSource:
    """Read-only window onto a file (exported file or working image)."""

    def __init__(self, path, label):
        self.path = path
        self.label = label
        self.size = os.path.getsize(path)

    def read(self, offset, n):
        with open(self.path, "rb") as f:      # read-only, per page
            f.seek(offset)
            return f.read(n)


# ------------------------------------------------------------------- widget

class HexView(ttk.Frame):
    def __init__(self, parent, height=24):
        super().__init__(parent)
        self.source = None
        self.page_start = 0
        self.highlight = None            # (start, end) absolute, end exclusive
        self.digits = 8

        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(0, 4))
        self.prev_button = ttk.Button(bar, text="◀ Previous 64 KiB",
                                      command=self.prev_page)
        self.prev_button.pack(side="left")
        self.next_button = ttk.Button(bar, text="Next 64 KiB ▶",
                                      command=self.next_page)
        self.next_button.pack(side="left", padx=4)
        ttk.Label(bar, text="Go to offset").pack(side="left", padx=(12, 4))
        self.goto_var = tk.StringVar()
        self.goto_entry = ttk.Entry(bar, textvariable=self.goto_var, width=16)
        self.goto_entry.pack(side="left")
        self.goto_entry.bind("<Return>", lambda e: self.goto_entered())
        ttk.Button(bar, text="Go", command=self.goto_entered).pack(side="left",
                                                                   padx=4)
        self.page_label = ttk.Label(self, text="")
        self.page_label.pack(fill="x")
        self.message = ttk.Label(self, text="", foreground="#a00000")
        self.message.pack(fill="x")

        body = ttk.Frame(self)
        body.pack(fill="both", expand=True)
        self.text = tk.Text(body, font=("TkFixedFont", 10), wrap="none",
                            height=height, width=80, state="disabled",
                            cursor="arrow")
        ys = ttk.Scrollbar(body, orient="vertical", command=self.text.yview)
        xs = ttk.Scrollbar(body, orient="horizontal", command=self.text.xview)
        self.text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.text.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)
        self.text.tag_configure("range", background="#fff1a8")
        self.text.tag_configure("start", background="#ffc46b")

    # ------------------------------------------------------------ API

    def set_source(self, source, start=0, highlight=None):
        """Show ``source`` from ``start`` (rounded down to a 16-byte row)."""
        self.source = source
        self.highlight = highlight
        self.digits = offset_digits(source.size)
        self.show(start)

    def show(self, offset):
        if self.source is None:
            return
        if self.source.size == 0:
            self.page_start = 0
            self._render(b"")
            return
        offset = min(max(0, offset), self.source.size - 1)
        self.page_start = offset - offset % ROW
        data = self.source.read(self.page_start, PAGE_SIZE)
        self._render(data)

    def prev_page(self):
        if self.source is not None and self.page_start > 0:
            self.show(max(0, self.page_start - PAGE_SIZE))

    def next_page(self):
        if self.source is not None and \
                self.page_start + PAGE_SIZE < self.source.size:
            self.show(self.page_start + PAGE_SIZE)

    def goto_entered(self):
        try:
            off = parse_offset(self.goto_var.get())
        except ValueError:
            self.message.config(text="Enter an offset as decimal, 0x… or …h.")
            return False
        if self.source is None or off >= self.source.size:
            self.message.config(text=f"Offset {off:,} is beyond the end of "
                                     f"this source ({self.source.size:,} bytes).")
            return False
        self.message.config(text="")
        self.show(off)
        return True

    def first_line(self):
        return self.text.get("1.0", "1.end")

    def line_count(self):
        return int(self.text.index("end-1c").split(".")[0])

    # -------------------------------------------------------- rendering

    def _render(self, data):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", format_rows(data, self.page_start, self.digits))
        self._apply_highlight(len(data))
        self.text.config(state="disabled")
        self.text.yview_moveto(0)
        end = self.page_start + len(data)
        self.page_label.config(
            text=f"{self.source.label}: bytes {self.page_start:,}–"
                 f"{max(end - 1, self.page_start):,} of {self.source.size:,}")
        self.prev_button.config(state="normal" if self.page_start > 0
                                else "disabled")
        self.next_button.config(state="normal" if end < self.source.size
                                else "disabled")

    def _apply_highlight(self, n):
        """Tint the bytes of the carved range shown on this page."""
        if not self.highlight or n == 0:
            return
        h_start, h_end = self.highlight
        lo = max(h_start, self.page_start)
        hi = min(h_end, self.page_start + n)
        if lo >= hi:
            return
        hex_cols, ascii_cols = hex_columns(self.digits)
        first_row = (lo - self.page_start) // ROW
        last_row = (hi - 1 - self.page_start) // ROW
        for row in range(first_row, last_row + 1):
            row_off = self.page_start + row * ROW
            a = max(lo, row_off) - row_off
            b = min(hi, row_off + ROW) - row_off - 1
            line = row + 1
            self.text.tag_add("range", f"{line}.{hex_cols[a]}",
                              f"{line}.{hex_cols[b] + 2}")
            self.text.tag_add("range", f"{line}.{ascii_cols[a]}",
                              f"{line}.{ascii_cols[b] + 1}")
        if self.page_start <= h_start < self.page_start + n:
            row, col = divmod(h_start - self.page_start, ROW)
            self.text.tag_add("start", f"{row + 1}.{hex_cols[col]}",
                              f"{row + 1}.{hex_cols[col] + 2}")
