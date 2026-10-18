"""Carving engine: sequential signature scan, parser dispatch, overlap handling."""

import mmap
import os
import re
from collections import Counter
from dataclasses import dataclass, field

from core import hashing, signatures
from core.parsers import PARSERS, ParseResult, VALID, PARTIAL, INVALID, mp3

SCAN_BLOCK = 4 * 1024 * 1024   # bytes per progress step of the header scan
EMBEDDED = "EMBEDDED"
# Frame sync: 11 set bits = FF followed by a byte with its top 3 bits set.
FRAME_SYNC = re.compile(rb"\xFF[\xE0-\xFF]")


class CarveCancelled(Exception):
    pass


@dataclass
class CarveSettings:
    formats: tuple = tuple(PARSERS)     # formats with a parser
    headerless_mp3: bool = True
    max_sizes: dict = field(default_factory=lambda: {
        name: spec.max_size for name, spec in signatures.FORMATS.items()})


@dataclass
class CarveScan:
    results: list            # dicts in the common result shape (no INVALID)
    candidates: dict         # format -> header hits
    status_counts: dict      # "format:status" -> count
    invalid: dict            # format -> INVALID count
    embedded: int
    image_size: int
    embedded_nonvalid: int = 0          # non-VALID hits inside VALID files
    headerless: dict = field(default_factory=dict)


def find_candidates(buf, size, formats, progress=None, cancel=None):
    """Sequential byte-aligned header scan.

    The image is scanned block by block (4 MiB). Each block is extended by
    the longest signature length minus one, so a signature that straddles a
    block boundary is still found, and a hit is kept only if it *starts*
    inside the block, so nothing is counted twice.
    Returns a sorted list of (start_offset, format).
    """
    specs = [signatures.FORMATS[f] for f in formats]
    overlap = signatures.LONGEST_SIGNATURE - 1
    found = []
    for block_start in range(0, size, SCAN_BLOCK):
        if cancel is not None and cancel():
            raise CarveCancelled()
        block_end = min(block_start + SCAN_BLOCK, size)
        search_end = min(block_end + overlap, size)
        for spec in specs:
            for sig in spec.signatures:
                pos = buf.find(sig, block_start, search_end)
                while pos != -1 and pos < block_end:
                    start = pos - spec.header_offset
                    if start >= 0:
                        found.append((start, spec.name))
                    pos = buf.find(sig, pos + 1, search_end)
        if progress is not None:
            progress(block_end, size)
    order = {name: i for i, name in enumerate(signatures.FORMAT_ORDER)}
    found.sort(key=lambda c: (c[0], order[c[1]]))
    return found


def _safe_parse(name, buf, start, max_len):
    try:
        return PARSERS[name](buf, start, max_len)
    except Exception as exc:   # second line of defence; parsers should not raise
        return ParseResult(INVALID, start, start,
                           checks=[f"parser exception: {type(exc).__name__}: {exc}"])


def carve(image_path, settings=None, progress=None, cancel=None, log=None):
    """Carve the image at ``image_path`` (the working copy). Returns CarveScan."""
    settings = settings or CarveSettings()
    log = log or (lambda msg, level="INFO": None)
    size = os.path.getsize(image_path)
    with open(image_path, "rb") as f, \
            mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as buf:
        cands = find_candidates(buf, size, settings.formats,
                                progress=progress, cancel=cancel)
        counts = Counter(name for _, name in cands)
        log(f"header hits: {dict(counts)} (total {len(cands)})")
        scan = _process(buf, size, cands, counts, settings, cancel, log)
        if settings.headerless_mp3 and "mp3" in settings.formats:
            _headerless_mp3_pass(buf, size, scan, settings, cancel, log)
        scan.results.sort(key=lambda r: (r["offset"], r["type"]))
        return scan


def _process(buf, size, cands, counts, settings, cancel, log):
    results, status_counts, invalid = [], Counter(), Counter()
    valid_ranges = []     # (start, end) of accepted VALID results, by start
    embedded = embedded_nonvalid = 0
    for i, (start, name) in enumerate(cands):
        if cancel is not None and i % 256 == 0 and cancel():
            raise CarveCancelled()
        max_len = min(settings.max_sizes[name], size - start)
        res = _safe_parse(name, buf, start, max_len)
        if res.status == INVALID or res.end <= res.start:
            invalid[name] += 1
            status_counts[f"{name}:{INVALID}"] += 1
            continue
        # Outermost accepted VALID file that contains this start, if any.
        parent = next((r for r in valid_ranges if r[0] < start < r[1]), None)
        if parent and res.status != VALID:
            embedded_nonvalid += 1      # structure/chance bytes inside a file
            status_counts[f"{name}:embedded_nonvalid"] += 1
            continue
        status = EMBEDDED if parent else res.status
        status_counts[f"{name}:{status}"] += 1
        rec = _result(buf, name, res, status, parent)
        results.append(rec)
        if parent:
            embedded += 1
        elif res.status == VALID:
            valid_ranges.append((res.start, res.end))
    log(f"results: {dict(sorted(status_counts.items()))}")
    return CarveScan(results=results, candidates=dict(counts),
                     status_counts=dict(status_counts),
                     invalid=dict(invalid), embedded=embedded, image_size=size,
                     embedded_nonvalid=embedded_nonvalid)


def _covered_ranges(results):
    """Merged (start, end) ranges of accepted VALID/PARTIAL results."""
    spans = sorted((r["offset"], r["end"]) for r in results
                   if r["status"] in (VALID, PARTIAL))
    merged = []
    for s, e in spans:
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    return merged


def _headerless_mp3_pass(buf, size, scan, settings, cancel, log):
    covered = _covered_ranges(scan.results)
    skipped = sum(1 for s, e in covered for _ in FRAME_SYNC.finditer(buf, s, e))
    gaps, prev = [], 0
    for s, e in covered:
        if s > prev:
            gaps.append((prev, s))
        prev = max(prev, e)
    if prev < size:
        gaps.append((prev, size))
    examined = rejected = found = 0
    max_size = settings.max_sizes["mp3"]
    for g_start, g_end in gaps:
        resume = g_start
        for m in FRAME_SYNC.finditer(buf, g_start, g_end):
            pos = m.start()
            if pos < resume:
                continue
            if cancel is not None and examined % 4096 == 0 and cancel():
                raise CarveCancelled()
            if mp3.frame_header(buf, pos, g_end) is None:
                continue            # sync bits only, not a valid header
            examined += 1
            # Bounded by the gap: a headerless MP3 in free space cannot
            # extend into an accepted file.
            res = mp3.parse_headerless(buf, pos, min(max_size, g_end - pos))
            if res.status != VALID:
                rejected += 1
                continue
            found += 1
            scan.results.append(_result(buf, "mp3", res, VALID, None))
            scan.status_counts["mp3:VALID (headerless)"] = found
            resume = res.end
    scan.headerless = {"sync_hits_inside_accepted_files_skipped": skipped,
                       "uncovered_ranges": len(gaps),
                       "valid_headers_examined": examined,
                       "rejected": rejected, "accepted": found}
    log(f"headerless MP3 pass: {scan.headerless}")


def _result(buf, name, res, status, parent):
    spec = signatures.FORMATS[name]
    h = hashing.hash_range(buf, res.start, res.end)
    checks = list(res.checks)
    if parent:
        checks.append(f"inside VALID file at offset {parent[0]} "
                      f"(ends {parent[1]}); parser status {res.status}")
    return {
        "method": "carved",
        "type": name,
        "subtype": res.subtype,
        "status": status,
        "parser_status": res.status,
        "parent_offset": parent[0] if parent else None,
        "offset": res.start,
        "length": res.length,
        "end": res.end,
        "extension": res.details.get("extension", spec.extension),
        "md5": h.md5,
        "sha256": h.sha256,
        "details": res.details,
        "checks": checks,
        "notes": list(res.notes),
    }
