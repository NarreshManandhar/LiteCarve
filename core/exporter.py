"""Writing recovered files into the case folder."""

import os
import re
from dataclasses import dataclass

from core import hashing

# Characters that must not appear in an exported file name.
_BAD_CHARS = re.compile(r'[\x00-\x1f\x7f/\\]')
MAX_NAME_BYTES = 200   # leaves room for offset prefixes and counters (ext4: 255)

# Folder layout (spec Section 10). "non_deleted" is used for allocated files
# so that the TXT folders match the carved/ folders (see DESIGN.md I-9).
TXT_DIR = os.path.join("metadata_recovered", "txt")
CARVED_DIR = "carved"
SEPARATION_DIRS = {"Deleted": "deleted", "Non-deleted": "non_deleted",
                   "Unattributed": "unattributed"}
# Folder per carved format.
TYPE_DIRS = {"jpeg": "jpg", "png": "png", "gif": "gif", "pdf": "pdf",
             "zip": "docx", "mp3": "mp3", "mp4": "mp4"}
# Original-name extensions that are consistent with each carved format.
TYPE_EXTENSIONS = {"jpeg": {"jpg", "jpeg", "jpe", "jfif"}, "png": {"png"},
                   "gif": {"gif"}, "pdf": {"pdf"}, "zip": {"docx"},
                   "mp3": {"mp3"}, "mp4": {"mp4", "m4v", "m4a", "mov", "3gp"}}


def case_layout(case_dir, export_embedded=False):
    """Create the fixed folder layout of spec Section 10; return the paths."""
    dirs = [os.path.join(CARVED_DIR, d) for d in SEPARATION_DIRS.values()]
    dirs += [os.path.join(CARVED_DIR, "other"),
             os.path.join(TXT_DIR, "deleted"),
             os.path.join(TXT_DIR, "non_deleted"), "reports"]
    if export_embedded:
        dirs.append(os.path.join(CARVED_DIR, "embedded"))
    for d in dirs:
        os.makedirs(os.path.join(case_dir, d), exist_ok=True)
    return dirs


def carved_folder(result):
    """Relative folder for a carved result (after correlation)."""
    if result["status"] == "EMBEDDED":
        return os.path.join(CARVED_DIR, "embedded")
    if result["type"] == "zip" and result["subtype"] != "docx":
        return os.path.join(CARVED_DIR, "other")
    return os.path.join(CARVED_DIR, SEPARATION_DIRS[result["separation"]],
                        TYPE_DIRS[result["type"]])


def carved_filename(result):
    """Spec Section 10 file name for a carved result."""
    ext = result["extension"]
    stem = f"{result['offset']:012d}"
    original = result.get("original_name") if result.get("attributed") else ""
    if original:
        o_stem, o_ext = os.path.splitext(original)
        if o_ext[1:].lower() in TYPE_EXTENSIONS.get(result["type"], ()):
            stem, ext = f"{stem}_{o_stem}", o_ext[1:]
        else:
            stem = f"{stem}_{original}"
    if result["status"] == "PARTIAL":
        stem += "_PARTIAL"
    return sanitise_name(f"{stem}.{ext}")


def sanitise_name(name, fallback="unnamed"):
    name = _BAD_CHARS.sub("_", name).strip()
    # "." and ".." would refer to directories rather than a file.
    if name in ("", ".", ".."):
        name = fallback
    encoded = name.encode("utf-8")
    if len(encoded) > MAX_NAME_BYTES:
        stem, ext = os.path.splitext(name)
        keep = MAX_NAME_BYTES - len(ext.encode("utf-8"))
        stem = stem.encode("utf-8")[:keep].decode("utf-8", "ignore")
        name = stem + ext
    return name


def _open_unique(directory, filename):
    """Open a new file for writing without overwriting: name, name_2, ..."""
    stem, ext = os.path.splitext(filename)
    counter = 1
    while True:
        candidate = filename if counter == 1 else f"{stem}_{counter}{ext}"
        path = os.path.join(directory, candidate)
        try:
            return path, open(path, "xb")
        except FileExistsError:
            counter += 1


@dataclass
class ExportResult:
    path: str
    bytes_written: int
    all_zero: bool
    error: str
    hashes: object   # hashing.HashResult or None


def export_stream(chunks, directory, filename):
    """Write an iterable of byte chunks to a new file in ``directory``.

    An exception raised by ``chunks`` part-way is caught and returned as
    ``error`` together with the bytes already written, so a read error yields
    a PARTIAL/FAILED record instead of aborting the run.
    """
    os.makedirs(directory, exist_ok=True)
    path, f = _open_unique(directory, sanitise_name(filename))
    written, all_zero, error = 0, True, ""
    with f:
        try:
            for chunk in chunks:
                f.write(chunk)
                written += len(chunk)
                # A cheap check that the content is entirely 0x00 (the
                # typical sign of overwritten/zeroed clusters).
                if all_zero and chunk.count(0) != len(chunk):
                    all_zero = False
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        f.flush()
        os.fsync(f.fileno())
    return ExportResult(path=path, bytes_written=written,
                        all_zero=all_zero and written > 0, error=error,
                        hashes=hashing.hash_file(path))


def export_carved(buf, result, case_dir):
    """Write one carved result from the mapped image; returns ExportResult.

    The file is hashed by re-reading it from disk, and compared with the hash
    computed over the same byte range during carving.
    """
    out_dir = os.path.join(case_dir, carved_folder(result))
    start, end = result["offset"], result["end"]
    # Slicing the mmap copies at most 1 MiB at a time.
    chunks = (buf[p:min(p + hashing.CHUNK_SIZE, end)]
              for p in range(start, end, hashing.CHUNK_SIZE))
    return export_stream(chunks, out_dir, carved_filename(result))
