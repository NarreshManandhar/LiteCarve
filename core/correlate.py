"""Correlation: link carved results to file-system records by exact offset."""

from collections import defaultdict

DELETED = "Deleted"
NON_DELETED = "Non-deleted"
UNATTRIBUTED = "Unattributed"

FRAGMENT_NOTE = ("File system records {n} data runs (fragmented); carving "
                 "recovered only the first fragment")
PDF_EOL_NOTE = "probable optional line ending after %%EOF"


def build_offset_index(records):
    """Absolute first-run offset -> list of metadata records (files only)."""
    index = defaultdict(list)
    for r in records:
        if r.is_dir or r.resident or not r.data_runs or r.realloc:
            continue
        index[r.data_runs[0][0]].append(r)
    return index


def _choose(candidates):
    """Pick one record for an offset; return (record, note or None)."""
    if len(candidates) == 1:
        return candidates[0], None
    allocated = [c for c in candidates if not c.deleted]
    chosen = allocated[0] if len(allocated) == 1 else None
    names = ", ".join(f"{c.path} ({c.separation})" for c in candidates)
    if chosen is None:
        return None, (f"{len(candidates)} file-system entries start at this "
                      f"offset and none can be preferred: {names}")
    return chosen, (f"{len(candidates)} file-system entries start at this "
                    f"offset ({names}); the allocated one was chosen because "
                    "the bytes there are its current content")


def _attribute(res, rec, note):
    res["separation"] = rec.separation
    res["attributed"] = True
    res["original_name"] = rec.name
    res["original_path"] = rec.path
    res["meta_addr"] = rec.meta_addr
    res["timestamps"] = rec.timestamps
    res["timestamp_basis"] = rec.timestamp_basis
    res["fs_size"] = rec.size
    res["fs_data_runs"] = len(rec.data_runs)
    res["size_consistent"] = res["length"] == rec.size
    notes = res.setdefault("notes", [])
    if note:
        notes.append(note)
    notes.extend(n for n in rec.notes if n not in notes)
    if len(rec.data_runs) > 1:
        notes.append(FRAGMENT_NOTE.format(n=len(rec.data_runs)))
    if res["type"] == "pdf" and 1 <= res["length"] - rec.size <= 2:
        notes.append(PDF_EOL_NOTE)


def _unattributed(res, note=None):
    res["separation"] = UNATTRIBUTED
    res["attributed"] = False
    res.setdefault("original_name", "")
    res.setdefault("original_path", "")
    res.setdefault("timestamps", None)
    res.setdefault("fs_size", None)
    res.setdefault("size_consistent", None)
    if note:
        res.setdefault("notes", []).append(note)


def correlate(carved_results, records, fs_type, log=None,
              metadata_recovered=()):
    """Label every carved result in place. Returns a summary dict.

    log: optional callable(message, level) for the run log.
    metadata_recovered: paths already recovered through metadata (TXT);
    they are not reported as "file without a carve".
    """
    log = log or (lambda msg, level="INFO": None)
    index = build_offset_index(records)
    by_offset = {r["offset"]: r for r in carved_results
                 if r["status"] != "EMBEDDED"}
    counts = defaultdict(int)

    for res in carved_results:
        if res["status"] == "EMBEDDED":
            continue
        cands = index.get(res["offset"])
        if not cands:
            _unattributed(res)
            counts[UNATTRIBUTED] += 1
            continue
        rec, note = _choose(cands)
        if rec is None:
            _unattributed(res, note)
            counts[UNATTRIBUTED] += 1
            log(f"{res['id']}: ambiguous offset, left Unattributed: {note}",
                "WARNING")
            continue
        _attribute(res, rec, note)
        counts[rec.separation] += 1

    # Embedded objects inherit the label of the file that contains them.
    for res in carved_results:
        if res["status"] != "EMBEDDED":
            continue
        parent = by_offset.get(res["parent_offset"])
        if parent is None:
            _unattributed(res)
        else:
            res["separation"] = parent["separation"]
            res["attributed"] = False
            res.setdefault("original_name", "")
            res.setdefault("original_path", "")
            res.setdefault("timestamps", None)
            res.setdefault("fs_size", None)
            res.setdefault("size_consistent", None)
            res.setdefault("notes", []).append(
                f"embedded in {parent['id']} at offset {parent['offset']}"
                + (f" ({parent['original_path']})"
                   if parent.get("original_path") else "")
                + "; label inherited from the parent")
        counts["EMBEDDED"] += 1

    # Files the file system knows about but that no carve starts at.
    carved_offsets = set(by_offset)
    unmatched = []
    for offset, cands in index.items():
        if offset in carved_offsets:
            continue
        for rec in cands:
            if rec.path in metadata_recovered:
                continue
            unmatched.append({"path": rec.path, "separation": rec.separation,
                              "offset": offset, "size": rec.size,
                              "data_runs": len(rec.data_runs)})
            level = "WARNING" if (fs_type == "FAT32" and rec.deleted) else "INFO"
            why = ("deleted FAT file: exact offset match failed (TSK's "
                   "contiguity assumption may not hold, or the content is "
                   "not a carvable format)") if level == "WARNING" else \
                  "no carved result starts at this file's first data run"
            log(f"{rec.path} [{rec.separation}] @ {offset}: {why}", level)
    return {"attributed_deleted": counts[DELETED],
            "attributed_non_deleted": counts[NON_DELETED],
            "unattributed": counts[UNATTRIBUTED],
            "embedded": counts["EMBEDDED"],
            "fs_files_without_carve": unmatched}
