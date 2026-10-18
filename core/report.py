"""Run log and reports."""

import csv
import html
import json
import os
from collections import Counter
from datetime import datetime

from core import hashing

# Statement of limitations (spec Section 10, item 7). Kept in one place so the
# JSON, HTML and GUI all show the same wording. Added to as features are built.
LIMITATIONS = [
    "No fragment reconstruction: carving assumes each file is stored in one "
    "contiguous run of bytes. Fragmented files are recovered PARTIAL or not "
    "at all.",
    "Carving cannot recover file names, paths or timestamps for files with no "
    "surviving file-system record (Unattributed results).",
    "FAT timestamps are stored on disk as local wall-clock time with no time "
    "zone. The report shows that stored value as 'local wall-clock' and leaves "
    "UTC empty, because converting it to UTC would require knowing the time "
    "zone of the device that wrote it. The raw epoch value is TSK's conversion "
    "using the analysis machine's time zone and is recorded only for "
    "reference; it changes if the same image is analysed in another time "
    "zone. FAT access times store a date only, and FAT has no metadata-change "
    "(ctime) field.",
    "Deleted FAT files: deletion clears the FAT cluster chain, so the data "
    "location of a deleted file is TSK's reconstruction assuming its clusters "
    "are contiguous. A carved file is attributed to a deleted FAT entry only "
    "when its start offset matches exactly; otherwise it is Unattributed.",
    "NTFS compressed, sparse or encrypted data and ZIP64 archives are not "
    "reconstructed; affected results are marked PARTIAL with a note.",
    "Carved data is not attributed specifically to slack space.",
    "Validation scope: LiteCarve was evaluated on two test images (NTFS and "
    "FAT32) that were zeroed before the test files were written. On them "
    "every carved file starts at a file-system record, so the Unattributed "
    "path (carved data with no surviving record) has been tested only with "
    "synthetic data in the unit tests, not with real residual data.",
    "MP3 has no length field: a carve ends after the last complete, "
    "consistent audio frame (plus trailing APEv2/ID3v1 tags). A truncated or "
    "partly overwritten MP3 is therefore recovered as a shorter but valid "
    "stream; its hash will not match the original file.",
    "PDF has no length field. A carved PDF ends after its last %%EOF that is "
    "consistent with startxref, plus one optional line ending (CR LF, LF or "
    "CR). If the original file ended without a line ending and the next byte "
    "on disk happens to be CR or LF (e.g. old data in slack space), one or two "
    "extra bytes are included and the hash will not match the original. "
    "Carved bytes are never trimmed; attributed PDFs whose length differs from "
    "the file-system size by 1-2 bytes are flagged on the record.",
]


def now_local_iso():
    # astimezone() attaches the machine's local offset, e.g. +13:00.
    return datetime.now().astimezone().isoformat(timespec="seconds")


class RunLog:
    """Append-only, line-per-action log.

    Lines logged before the case folder exists (evidence hashing, disk-space
    check) are buffered and written out as soon as ``attach`` is called, so the
    log file is complete from the first action (decision I-6).
    """

    def __init__(self, echo=None):
        self.entries = []          # (timestamp, step, level, details)
        self._path = None
        self._echo = echo          # optional callable(line) for live display

    @staticmethod
    def _format(entry):
        ts, step, level, details = entry
        # Newlines in details would break the one-line-per-action format.
        details = details.replace("\r", " ").replace("\n", " | ")
        return f"{ts}  {level:<7} {step:<22} {details}"

    def log(self, step, details, level="INFO"):
        entry = (now_local_iso(), step, level, details)
        self.entries.append(entry)
        line = self._format(entry)
        if self._path is not None:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        if self._echo is not None:
            self._echo(level, line)

    def attach(self, path):
        """Start writing to ``path``; flush everything logged so far."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # "x": the log of an earlier run is never overwritten.
        with open(path, "x", encoding="utf-8") as f:
            for entry in self.entries:
                f.write(self._format(entry) + "\n")
        self._path = path

    @property
    def path(self):
        return self._path


def write_json(path, record):
    """Write the report record as indented UTF-8 JSON."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, ensure_ascii=False, default=str)
        f.write("\n")
    # Replace in one step so a crash never leaves a half-written report.
    os.replace(tmp, path)
    return path


# --------------------------------------------------------------------------
# Result records
# --------------------------------------------------------------------------

# Every result in report.json has these keys (spec Section 10), whatever its
# method; missing values are None/"".
RESULT_FIELDS = [
    "id", "method", "type", "subtype", "status", "separation", "attributed",
    "offset", "end", "length", "extension", "original_name", "original_path",
    "meta_addr", "resident", "fs_data_runs", "timestamps", "timestamp_basis",
    "fs_size", "size_consistent", "all_zero", "md5", "sha256", "export_path",
    "export_hash_match", "parser_status", "parent_offset", "details", "checks",
    "notes",
]
TIMESTAMP_FIELDS = ("mtime", "atime", "ctime", "crtime")


def normalise_result(res):
    out = {k: res.get(k) for k in RESULT_FIELDS}
    for k in ("checks", "notes"):
        out[k] = list(out[k] or [])
    for k in ("original_name", "original_path", "export_path", "subtype"):
        out[k] = out[k] or ""
    out["details"] = out["details"] or {}
    return out


def _ts_value(ts):
    """One timestamp as (utc, local_wallclock) strings."""
    if not ts:
        return "", ""
    return ts.get("utc") or "", ts.get("local_wallclock") or ""


RESIDENT_TEXT = "resident (MFT)"


def offset_text(r):
    """Offset for display; NTFS resident files have none (decision C-13)."""
    if r.get("offset") is not None:
        return f"{r['offset']:,}"
    if r.get("resident"):
        return RESIDENT_TEXT
    return ""


def ts_display(ts):
    """Human-readable timestamp: UTC + analysis-machine local, or FAT value."""
    if not ts:
        return ""
    if ts.get("utc"):
        utc = datetime.fromisoformat(ts["utc"])
        local = utc.astimezone()
        return (f"{utc.strftime('%Y-%m-%d %H:%M:%S')} UTC "
                f"({local.strftime('%Y-%m-%d %H:%M:%S %Z')})")
    if ts.get("local_wallclock"):
        return f"{ts['local_wallclock'].replace('T', ' ')} (FAT local, no zone)"
    return ""


CSV_COLUMNS = [
    "id", "method", "type", "subtype", "status", "separation", "offset",
    "length", "original_name", "original_path", "meta_addr", "resident",
    "fs_size", "size_consistent",
] + [f"{t}_{kind}" for t in TIMESTAMP_FIELDS
     for kind in ("utc", "local_wallclock")] + [
    "md5", "sha256", "export_path", "export_hash_match", "parser_status",
    "parent_offset", "checks", "notes",
]


def write_csv(path, results):
    rows = []
    for r in results:
        row = {k: r.get(k) for k in CSV_COLUMNS if k in r}
        stamps = r.get("timestamps") or {}
        for t in TIMESTAMP_FIELDS:
            row[f"{t}_utc"], row[f"{t}_local_wallclock"] = _ts_value(stamps.get(t))
        row["checks"] = " | ".join(r.get("checks") or [])
        row["notes"] = " | ".join(r.get("notes") or [])
        rows.append(row)
    tmp = path + ".tmp"
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    os.replace(tmp, path)
    return path


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------

def _e(v):
    return html.escape("" if v is None else str(v))


def _kv_table(pairs):
    rows = "".join(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in pairs)
    return f"<table class='kv'>{rows}</table>"


def _badge(value):
    cls = "ok" if value in ("MATCH", True) else "bad"
    text = "MATCH" if value is True else "MISMATCH" if value is False else value
    return f"<span class='badge {cls}'>{_e(text)}</span>"


def _table(headers, rows, cls=""):
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>"
                   for row in rows)
    return (f"<table class='grid {cls}'><thead><tr>{head}</tr></thead>"
            f"<tbody>{body}</tbody></table>")


_CSS = """
body{font-family:system-ui,Segoe UI,Arial,sans-serif;font-size:13px;color:#111;
     background:#fff;margin:24px;max-width:1400px}
h1{font-size:22px;margin:0 0 4px} h2{font-size:17px;margin:28px 0 8px;
   border-bottom:2px solid #333;padding-bottom:3px}
h3{font-size:14px;margin:16px 0 6px}
table{border-collapse:collapse;margin:6px 0 10px}
.kv th{text-align:left;padding:3px 12px 3px 0;vertical-align:top;color:#444;
       white-space:nowrap}
.kv td{padding:3px 0}
.grid th,.grid td{border:1px solid #bbb;padding:3px 6px;vertical-align:top;
                  text-align:left}
.grid th{background:#eee}
.grid.results td{font-size:12px}
.mono{font-family:Consolas,Menlo,monospace;font-size:11px;word-break:break-all}
.badge{display:inline-block;padding:1px 7px;border-radius:3px;font-weight:600}
.badge.ok{background:#d6f5d6;color:#0a5a0a}.badge.bad{background:#fbd5d5;color:#8a0000}
.banner{padding:10px 14px;border-radius:4px;font-size:15px;font-weight:600;
        margin:10px 0}
.banner.ok{background:#d6f5d6;color:#0a5a0a}.banner.bad{background:#fbd5d5;color:#8a0000}
.small{color:#555;font-size:12px} ul.notes{margin:0;padding-left:16px}
@media print{body{margin:10mm;font-size:10px}.grid.results td{font-size:9px}
             h2{page-break-after:avoid} tr{page-break-inside:avoid}}
"""


def _hash_row(label, h):
    if not h:
        return [_e(label), "", "", ""]
    return [_e(label), f"<span class='mono'>{_e(h.get('md5'))}</span>",
            f"<span class='mono'>{_e(h.get('sha256'))}</span>", _e(h.get("size"))]


def _cmp_row(label, cmp):
    if not cmp:
        return [_e(label), "not performed", "", ""]
    return [_e(label), _badge(cmp["md5"]), _badge(cmp["sha256"]),
            _badge(cmp["size"])]


def _result_row(r):
    stamps = r.get("timestamps") or {}
    times = "<br>".join(f"{t}: {_e(ts_display(stamps.get(t)))}"
                        for t in TIMESTAMP_FIELDS if ts_display(stamps.get(t)))
    notes = "".join(f"<li>{_e(n)}</li>" for n in
                    (r.get("notes") or []) + (r.get("checks") or []))
    return [
        _e(r["id"]), _e(r["method"]),
        _e(r["type"] + (f" / {r['subtype']}" if r.get("subtype") else "")),
        _e(r["status"]), _e(r.get("separation")), _e(offset_text(r)),
        _e(r.get("length")),
        _e(r.get("original_path")) + (f"<div class='small'>{times}</div>"
                                      if times else ""),
        _e(r.get("fs_size")), _e(r.get("size_consistent")),
        f"<span class='mono'>MD5 {_e(r.get('md5'))}<br>"
        f"SHA-256 {_e(r.get('sha256'))}</span>",
        f"<span class='mono'>{_e(r.get('export_path'))}</span>",
        f"<ul class='notes'>{notes}</ul>",
    ]


COMPLETE_STATUSES = ("VALID", "RECOVERED")


def headline(summary):
    """One-line recovered-files summary used by HTML, CLI and GUI."""
    rf = summary["recovered_files"]
    text = (f"Recovered: {rf['complete']} complete (VALID/RECOVERED), "
            f"{rf['partial']} partial")
    if rf.get("failed"):
        text += f", {rf['failed']} failed"
    return text


def summarise(results):
    """Counts for the report summary (decision C-9).

    Embedded objects are counted separately from recovered files: they are
    part of another recovered file's content, not additional files.
    """
    files = [r for r in results if r["status"] != "EMBEDDED"]
    embedded = [r for r in results if r["status"] == "EMBEDDED"]
    by_sep = Counter(r.get("separation") or "" for r in files)
    complete = [r for r in files if r["status"] in COMPLETE_STATUSES]
    partial = [r for r in files if r["status"] == "PARTIAL"]
    failed = [r for r in files if r["status"] == "FAILED"]
    return {
        "recovered_files": {
            # Complete and partial recoveries are never added together in a
            # headline figure (decision C-11): a 40-byte PARTIAL is not a
            # recovered file in the same sense as a hash-exact VALID one.
            "complete": len(complete),
            "partial": len(partial),
            "failed": len(failed),
            "complete_by_separation": dict(sorted(Counter(
                r.get("separation") or "" for r in complete).items())),
            "partial_by_separation": dict(sorted(Counter(
                r.get("separation") or "" for r in partial).items())),
            "total": len(files),
            "carved": sum(r["method"] == "carved" for r in files),
            "metadata_txt": sum(r["method"] == "metadata" for r in files),
            "by_separation": dict(sorted(by_sep.items())),
            "by_status": dict(sorted(Counter(r["status"] for r in files).items())),
            "by_type_separation_status": [
                {"type": t, "separation": sep, "status": st, "count": n}
                for (t, sep, st), n in sorted(Counter(
                    (r["type"], r.get("separation") or "", r["status"])
                    for r in files).items())],
        },
        "embedded_objects": {
            "total": len(embedded),
            "by_type": dict(sorted(Counter(r["type"] for r in embedded).items())),
            "exported": sum(bool(r.get("export_path")) for r in embedded),
        },
    }


def build_html(rec, listing=None):
    case = rec.get("case") or {}
    ev = rec.get("evidence") or {}
    wc = rec.get("working_copy") or {}
    cmps = rec.get("hash_comparisons") or {}
    vol = rec.get("volume") or {}
    env = rec.get("environment") or {}
    results = rec.get("results") or []
    carving = rec.get("carving") or {}
    final_ok = all(cmps.get(k, {}).get("match") for k in
                   ("evidence_initial_vs_final", "copy_initial_vs_final"))
    final_done = all(k in cmps for k in
                     ("evidence_initial_vs_final", "copy_initial_vs_final"))
    parts = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
             f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
             f"<title>LiteCarve report {_e(case.get('case_number'))}</title>"
             f"<style>{_CSS}</style></head><body>"]
    parts.append(f"<h1>LiteCarve examination report</h1><div class='small'>"
                 f"Case {_e(case.get('case_number'))} &middot; generated "
                 f"{_e(now_local_iso())} &middot; status "
                 f"<b>{_e(rec.get('status'))}</b> {_e(rec.get('message'))}</div>")

    # 1 Case and examiner
    parts.append("<h2>1. Case and examiner details</h2>" + _kv_table([
        ("Examiner name", case.get("examiner_name")),
        ("Examiner ID", case.get("examiner_id")),
        ("Organisation", case.get("organisation")),
        ("Case number", case.get("case_number")),
        ("Evidence item", case.get("evidence_description")),
        ("Notes", case.get("notes")),
        ("Run start", rec.get("run_start")), ("Run end", rec.get("run_end")),
        ("Case folder", rec.get("case_dir")),
    ]))

    # 2 Evidence integrity
    if final_done:
        banner = ("<div class='banner ok'>Evidence and working copy re-hashed "
                  "after analysis: both MATCH their initial hashes.</div>"
                  if final_ok else
                  "<div class='banner bad'>FINAL HASH MISMATCH: the evidence "
                  "or the working copy changed during the run.</div>")
    else:
        banner = ("<div class='banner bad'>Final re-hash not performed (run "
                  "stopped early).</div>")
    init = (ev.get("initial") or {})
    parts.append("<h2>2. Evidence integrity</h2>" + banner + _kv_table([
        ("Evidence path", init.get("path")), ("Size (bytes)", init.get("size")),
        ("Modified (mtime, UTC)", init.get("mtime_utc")),
        ("Working copy", wc.get("path")),
    ]))
    parts.append(_table(["Item", "MD5", "SHA-256", "Bytes"], [
        _hash_row("Evidence (initial)", init.get("hashes")),
        _hash_row("Working copy (initial)", wc.get("initial")),
        _hash_row("Evidence (final)", (ev.get("final") or {})),
        _hash_row("Working copy (final)", wc.get("final")),
    ]))
    parts.append(_table(["Comparison", "MD5", "SHA-256", "Size"], [
        _cmp_row("Evidence vs working copy", cmps.get("evidence_vs_copy")),
        _cmp_row("Evidence initial vs final", cmps.get("evidence_initial_vs_final")),
        _cmp_row("Working copy initial vs final", cmps.get("copy_initial_vs_final")),
    ]))
    ro = rec.get("read_only_actions") or []
    if ro:
        parts.append("<h3>Read-only actions</h3>" + _table(
            ["File", "Previous mode", "Changed", "New mode", "Warning"],
            [[f"<span class='mono'>{_e(a['path'])}</span>", _e(a["previous_mode"]),
              _e("yes" if a["changed"] else "no"), _e(a["new_mode"]),
              _e(a.get("warning"))] for a in ro]))
        parts.append(f"<p class='small'>{_e(ro[0].get('note'))}</p>")

    # 3 Environment
    st = rec.get("settings") or {}
    parts.append("<h2>3. Environment and tool</h2>" + _kv_table(
        [(k.replace("_", " ").capitalize(), v) for k, v in env.items()]
        + [("Export embedded objects", st.get("export_embedded")),
           ("Formats carved", ", ".join(st.get("formats") or [])),
           ("Maximum sizes (bytes)", ", ".join(
               f"{k} {v:,}" for k, v in (st.get("max_sizes") or {}).items()))]))

    # 4 Partition and FS
    parts.append("<h2>4. Partition and file system</h2>" + _kv_table([
        ("Partition table", vol.get("partition_table")),
        ("Detection method", vol.get("detection_method")),
        ("MBR partition entry", vol.get("mbr_entry")),
        ("TSK slot", vol.get("tsk_slot")),
        ("Partition type", vol.get("partition_type")),
        ("Start sector", vol.get("start_sector")),
        ("Sector size", vol.get("sector_size")),
        ("Byte offset", vol.get("offset_bytes")),
        ("Partition size (bytes)", vol.get("size_bytes")),
        ("File system (TSK)", vol.get("fs_type")),
        ("Boot-sector signature", f"{vol.get('boot_signature')} (consistent: "
                                  f"{vol.get('boot_signature_consistent')})"),
        ("Block size / cluster size", f"{vol.get('block_size')} / "
                                      f"{vol.get('cluster_size')} bytes"),
        ("Volume label", vol.get("volume_label")),
    ]))

    # 5 Summary
    ms = rec.get("metadata_summary") or {}
    txt = [r for r in results if r["method"] == "metadata"]
    corr = rec.get("correlation") or {}
    summ = rec.get("summary") or summarise(results)
    rf, eo = summ["recovered_files"], summ["embedded_objects"]
    parts.append("<h2>5. Summary</h2>")
    parts.append("<h3>Recovered files</h3>" + _kv_table([
        ("Recovered", headline(summ)),
        ("Complete, by separation", ", ".join(
            f"{k} {v}" for k, v in rf["complete_by_separation"].items()) or "none"),
        ("Partial, by separation", ", ".join(
            f"{k} {v}" for k, v in rf["partial_by_separation"].items()) or "none"),
        ("Method", f"{rf['carved']} carved, {rf['metadata_txt']} TXT via "
                   "metadata"),
        ("By status", ", ".join(f"{k} {v}" for k, v in rf["by_status"].items())),
    ]))
    parts.append(_table(["Type", "Separation", "Status", "Count"],
                        [[_e(x["type"]), _e(x["separation"]), _e(x["status"]),
                          _e(x["count"])]
                         for x in rf["by_type_separation_status"]]))
    parts.append("<h3>Embedded objects</h3><p class='small'>Objects found "
                 "inside another recovered file (e.g. an EXIF thumbnail). They "
                 "are part of that file's content and are not counted as "
                 "recovered files.</p>" + _kv_table([
                     ("Embedded objects", eo["total"]),
                     ("By type", ", ".join(f"{k} {v}" for k, v in
                                           eo["by_type"].items()) or "none"),
                     ("Exported separately", eo["exported"]),
                 ]))
    parts.append("<h3>Other counts</h3>")
    parts.append(_kv_table([
        ("TXT files recovered via metadata",
         f"{sum(r['status'] == 'RECOVERED' for r in txt)} of {len(txt)}"),
        ("Non-VALID hits inside VALID files (counted only)",
         carving.get("embedded_nonvalid_counted")),
        ("INVALID candidates (not exported)",
         ", ".join(f"{k} {v}" for k, v in (carving.get("invalid") or {}).items())
         or "0"),
        ("Header hits", ", ".join(f"{k} {v}" for k, v in
                                  (carving.get("header_hits") or {}).items())),
        ("Headerless MP3 pass", ", ".join(
            f"{k.replace('_', ' ')} {v}" for k, v in
            (carving.get("headerless_mp3") or {}).items())),
        ("File-system entries listed",
         f"{ms.get('listed')} ({ms.get('files')} files: {ms.get('files_deleted')} "
         f"deleted, {ms.get('files_allocated')} allocated; "
         f"{ms.get('directories')} folders)"),
        ("Correlation", f"Deleted {corr.get('attributed_deleted')}, "
                        f"Non-deleted {corr.get('attributed_non_deleted')}, "
                        f"Unattributed {corr.get('unattributed')}"),
        ("Processing time", f"{rec.get('run_processing_seconds')} s "
                            "(excludes waiting for the examiner)"),
        ("Waiting for the examiner (hash confirmation)",
         f"{rec.get('examiner_wait_seconds')} s"),
        ("Wall-clock run time", f"{rec.get('run_wall_seconds')} s"),
    ]))
    parts.append("<h3>Step timings</h3>" + _table(
        ["Step", "Start", "End", "Processing (s)", "Examiner wait (s)",
         "Wall (s)", "OK"],
        [[_e(k), _e(v["start"]), _e(v["end"]), _e(v["seconds"]),
          _e(v.get("examiner_wait_seconds")), _e(v.get("wall_seconds")),
          _e(v["ok"])]
         for k, v in (rec.get("timings") or {}).items()]))

    # 6 Results
    parts.append("<h2>6. Results</h2>" + _table(
        ["ID", "Method", "Type", "Status", "Separation", "Offset", "Length",
         "Original path / timestamps", "FS size", "Size consistent", "Hashes",
         "Export path", "Notes and checks"],
        [_result_row(r) for r in results], cls="results"))

    # 7 Limitations
    lim = "".join(f"<li>{_e(x)}</li>" for x in rec.get("limitations") or [])
    other = "".join(f"<li>{_e(x)}</li>" for x in rec.get("notes") or [])
    parts.append(f"<h2>7. Statement of limitations</h2><ul>{lim}{other}</ul>")
    listing = listing or []
    basis = {m.get("timestamp_basis") for m in listing}
    if basis:
        parts.append("<p class='small'>Timestamp basis for this image: "
                     + _e("; ".join(sorted(b for b in basis if b))) + "</p>")

    # Appendices
    if listing:
        ref = rec.get("metadata_listing_file") or {}
        parts.append("<h2>Appendix A. File-system listing</h2>"
                     f"<p class='small'>Also in {_e(ref.get('file'))} "
                     f"(SHA-256 <span class='mono'>{_e(ref.get('sha256'))}"
                     "</span>).</p>" + _table(
            ["Path", "Type", "Status", "MFT/inode", "Size", "Data runs",
             "Modified", "Created", "Flags / notes"],
            [[_e(m["path"]), _e("dir" if m["is_dir"] else "file"),
              _e(m["separation"]), _e(m["meta_addr"]), _e(m["size"]),
              _e(len(m["data_runs"])) + (" (resident)" if m["resident"] else ""),
              _e(ts_display(m["timestamps"].get("mtime"))),
              _e(ts_display(m["timestamps"].get("crtime"))),
              _e("; ".join([f for f in ("compressed", "sparse", "encrypted",
                                        "realloc") if m.get(f)] + m["notes"]))]
             for m in listing]))
    missing = corr.get("fs_files_without_carve") or []
    if missing:
        parts.append("<h2>Appendix B. File-system files with no carved result "
                     "at their first data run</h2>" + _table(
                         ["Path", "Separation", "Offset", "Size", "Data runs"],
                         [[_e(m["path"]), _e(m["separation"]), _e(m["offset"]),
                           _e(m["size"]), _e(m["data_runs"])] for m in missing]))
    parts.append("</body></html>")
    return "".join(parts)


def write_html(path, rec, listing=None):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(build_html(rec, listing))
    os.replace(tmp, path)
    return path


LISTING_FILE = "metadata_listing.json"


def write_all(reports_dir, rec, listing=None):
    """Write the reports; return their paths.

    If a file-system listing is given it is written first to
    metadata_listing.json, and report.json records its name, entry count and
    SHA-256 (decision C-8), so the reference is verifiable.
    """
    os.makedirs(reports_dir, exist_ok=True)
    rec["results"] = [normalise_result(r) for r in rec.get("results") or []]
    rec["summary"] = summarise(rec["results"])
    paths = []
    if listing is not None:
        lp = write_json(os.path.join(reports_dir, LISTING_FILE),
                        {"case_number": (rec.get("case") or {}).get("case_number"),
                         "entries": listing})
        h = hashing.hash_file(lp)
        rec["metadata_listing_file"] = {"file": LISTING_FILE,
                                        "entries": len(listing),
                                        "md5": h.md5, "sha256": h.sha256}
        paths.append(lp)
    paths += [write_json(os.path.join(reports_dir, "report.json"), rec),
              write_csv(os.path.join(reports_dir, "report.csv"), rec["results"]),
              write_html(os.path.join(reports_dir, "report.html"), rec, listing)]
    return paths
