"""PDF parser: finds the %%EOF that is consistent with its startxref."""

import re

from core.parsers import ParseResult, VALID, PARTIAL, invalid

HEADER = re.compile(rb"%PDF-(\d\.\d)")
EOF_MARK = b"%%EOF"
STARTXREF = re.compile(rb"startxref\s+(\d+)\s*$")
OBJ_HEADER = re.compile(rb"\d+\s+\d+\s+obj")
LOOKBACK = 1024


def _line_end(buf, pos, limit):
    """Length of a line ending at pos: \\r\\n, \\n or \\r (0 if none)."""
    if pos < limit and buf[pos:pos + 1] == b"\r":
        return 2 if pos + 1 < limit and buf[pos + 1:pos + 2] == b"\n" else 1
    if pos < limit and buf[pos:pos + 1] == b"\n":
        return 1
    return 0


def _xref_ok(buf, start, eof_pos):
    """Does the startxref before this %%EOF point at a real xref in the file?"""
    back = bytes(buf[max(start, eof_pos - LOOKBACK):eof_pos])
    m = None
    for m in STARTXREF.finditer(back):   # keep the last match
        pass
    if m is None:
        return False, "no startxref before %%EOF"
    n = int(m.group(1))
    target = start + n
    if not start <= target < eof_pos:
        return False, f"startxref {n} outside candidate"
    head = bytes(buf[target:target + 32])
    if head.startswith(b"xref"):
        return True, f"startxref {n} -> xref table"
    if OBJ_HEADER.match(head):
        return True, f"startxref {n} -> xref stream object"
    return False, f"startxref {n} does not point at xref"


def parse(buf, offset, max_len):
    limit = offset + max_len
    m = HEADER.match(bytes(buf[offset:offset + 8]))
    if not m:
        return invalid(offset, "no %PDF-d.d header")
    version = m.group(1).decode()
    checks = [f"header %PDF-{version}"]
    nxt = buf.find(b"%PDF-", offset + 5, limit)
    window_end = nxt if nxt != -1 else limit
    if nxt != -1:
        checks.append(f"window ends at next %PDF- header (+{nxt - offset})")

    eofs = []
    pos = buf.find(EOF_MARK, offset, window_end)
    while pos != -1:
        eofs.append(pos)
        pos = buf.find(EOF_MARK, pos + len(EOF_MARK), window_end)
    details = {"version": version, "eof_markers_in_window": len(eofs)}

    for eof_pos in reversed(eofs):
        ok, why = _xref_ok(buf, offset, eof_pos)
        if not ok:
            checks.append(f"%%EOF at +{eof_pos - offset} rejected: {why}")
            continue
        after = eof_pos + len(EOF_MARK)
        end = after + _line_end(buf, after, window_end)
        updates = sum(1 for e in eofs if e <= eof_pos)
        encrypted = buf.find(b"/Encrypt", offset, end) != -1
        details.update(eof_markers=updates, incremental_updates=updates - 1,
                       encrypted=encrypted)
        checks.append(f"%%EOF at +{eof_pos - offset} accepted: {why}")
        checks.append(f"{updates} %%EOF marker(s) in file")
        notes = ["/Encrypt present: document is encrypted/password-protected"] \
            if encrypted else []
        return ParseResult(VALID, offset, end, subtype=f"pdf-{version}",
                           checks=checks, notes=notes, details=details)

    if eofs:
        after = eofs[-1] + len(EOF_MARK)
        end = after + _line_end(buf, after, window_end)
        checks.append("no %%EOF consistent with startxref; "
                      "ended at last %%EOF in window")
    else:
        end = window_end
        checks.append("no %%EOF in window; ended at window end")
    details["encrypted"] = buf.find(b"/Encrypt", offset, end) != -1
    return ParseResult(PARTIAL, offset, end, subtype=f"pdf-{version}",
                       checks=checks, details=details)
