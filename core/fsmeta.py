"""Metadata engine: file-system walk with pytsk3, and TXT recovery."""

import re
from collections import Counter
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone

import pytsk3

from core import exporter

READ_CHUNK = 1024 * 1024

_META_UNALLOC = int(pytsk3.TSK_FS_META_FLAG_UNALLOC)
_META_ALLOC = int(pytsk3.TSK_FS_META_FLAG_ALLOC)
_NAME_UNALLOC = int(pytsk3.TSK_FS_NAME_FLAG_UNALLOC)
_DIR_TYPES = {int(pytsk3.TSK_FS_META_TYPE_DIR),
              int(pytsk3.TSK_FS_META_TYPE_VIRT_DIR)}
_VIRT_META = {int(pytsk3.TSK_FS_META_TYPE_VIRT),
              int(pytsk3.TSK_FS_META_TYPE_VIRT_DIR)}
_VIRT_NAME = {int(pytsk3.TSK_FS_NAME_TYPE_VIRT),
              int(pytsk3.TSK_FS_NAME_TYPE_VIRT_DIR)}
_DATA_ATTR = {int(pytsk3.TSK_FS_ATTR_TYPE_DEFAULT),
              int(pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA)}
_ATTR_RES = int(pytsk3.TSK_FS_ATTR_RES)
_ATTR_COMP = int(pytsk3.TSK_FS_ATTR_COMP)
_ATTR_ENC = int(pytsk3.TSK_FS_ATTR_ENC)
_ATTR_SPARSE = int(pytsk3.TSK_FS_ATTR_SPARSE)
_RUN_FILLER = int(pytsk3.TSK_FS_ATTR_RUN_FLAG_FILLER)
_RUN_SPARSE = int(pytsk3.TSK_FS_ATTR_RUN_FLAG_SPARSE)

TIMESTAMP_FIELDS = ("mtime", "atime", "ctime", "crtime")


# --------------------------------------------------------------------------
# The exclusion filter (spec Section 6). It is deliberately written against a
# minimal EntryKey that both a pytsk3 entry and an `fls -r -l -p` line can
# supply, so the Phase 2 acceptance test applies *this same function* to the
# fls output (review decision 4).
# --------------------------------------------------------------------------

SYNTHETIC_ORPHAN_NAME = re.compile(r"^OrphanFile-\d+$")
ORPHAN_DIR = "$OrphanFiles"
FAT_VOLUME_LABEL_SUFFIX = "(Volume Label Entry)"


@dataclass
class EntryKey:
    path: str          # "/Docs/PW.docx" (from the file-system root)
    name: str
    is_virtual: bool   # TSK virtual entry ($MBR, $FAT1, $OrphanFiles, ...)
    size: int          # data size in bytes (0 if unknown)
    has_meta: bool     # a metadata entry exists for this name
    fs_type: str       # "NTFS" or "FAT32"


def exclusion_reason(key):
    """Return why an entry is hidden from the listing, or None to keep it.

    Reasons:
    dot_entry        "." and ".."
    orphan_dir       TSK's virtual $OrphanFiles folder itself
    orphan_empty     an "OrphanFile-N" entry with neither a real name nor
                     data (e.g. NTFS reserved MFT entries 16-23). Orphans with
                     a recovered name or with data are KEPT: they are often
                     deleted files whose parent folder is gone.
    tsk_virtual      other TSK virtual entries (FAT $MBR, $FAT1, $FAT2)
    ntfs_system      NTFS metadata files: any entry whose top-level name in
                     the root starts with "$" (includes the $Extend subtree)
    fat_volume_label the FAT volume-label directory entry (not a file; the
                     label is reported in the volume details instead)
    no_metadata      a name with no metadata entry behind it
    """
    if key.name in (".", ".."):
        return "dot_entry"
    parts = [p for p in key.path.split("/") if p]
    top = parts[0] if parts else ""
    if top == ORPHAN_DIR:
        if len(parts) == 1:
            return "orphan_dir"
        if SYNTHETIC_ORPHAN_NAME.match(key.name) and not key.size:
            return "orphan_empty"
    elif key.is_virtual:
        return "tsk_virtual"
    elif key.fs_type == "NTFS" and top.startswith("$"):
        return "ntfs_system"
    if (key.fs_type == "FAT32" and len(parts) == 1
            and key.name.endswith(FAT_VOLUME_LABEL_SUFFIX)):
        return "fat_volume_label"
    if not key.has_meta:
        return "no_metadata"
    return None


# --------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------

@dataclass
class MetaRecord:
    path: str
    name: str
    meta_addr: int
    is_dir: bool
    deleted: bool
    name_unalloc: bool
    meta_unalloc: bool
    realloc: bool               # name deleted but MFT entry/inode reused
    size: int
    resident: bool
    compressed: bool
    sparse: bool
    encrypted: bool
    data_runs: list             # [(absolute_offset, length_bytes), ...]
    streams: list               # NTFS named data streams [{"name", "size"}]
    timestamps: dict
    timestamp_basis: str
    notes: list = field(default_factory=list)

    @property
    def separation(self):
        return "Deleted" if self.deleted else "Non-deleted"

    @property
    def first_offset(self):
        return self.data_runs[0][0] if self.data_runs else None

    def to_dict(self):
        d = asdict(self)
        d["separation"] = self.separation
        return d


@dataclass
class MetaScan:
    records: list
    excluded: dict          # reason -> count
    errors: list
    summary: dict


def _decode(raw):
    if raw is None:
        return ""
    return raw.decode("utf-8", "replace")


def _timestamps(meta, fs_type):
    out = {}
    for name in TIMESTAMP_FIELDS:
        epoch = int(getattr(meta, name, 0) or 0)
        nano = int(getattr(meta, name + "_nano", 0) or 0)
        entry = {"epoch": epoch or None, "nano": nano, "utc": None,
                 "local_wallclock": None}
        if epoch:
            if fs_type == "FAT32":
                # Invert TSK's mktime() in this process's time zone to get
                # back the wall-clock value that is actually stored on disk.
                wall = datetime.fromtimestamp(epoch)
                entry["local_wallclock"] = wall.replace(
                    microsecond=nano // 1000).isoformat()
            else:
                utc = datetime.fromtimestamp(epoch, tz=timezone.utc)
                entry["utc"] = utc.replace(microsecond=nano // 1000).isoformat()
        out[name] = entry
    return out


def _timestamp_basis(fs_type):
    if fs_type == "FAT32":
        tz = datetime.now().astimezone().tzname()
        return ("FAT local time, no time zone stored. 'local_wallclock' is "
                "the value on disk; 'epoch' is TSK's conversion assuming the "
                f"analysis machine's time zone ({tz}).")
    return "NTFS FILETIME (UTC)"


def _data_info(file_obj, partition_offset, block_size):
    """Default data stream: runs, flags; named streams listed separately."""
    runs, streams = [], []
    resident = compressed = sparse = encrypted = False
    for attr in file_obj:
        ai = attr.info
        if int(ai.type) not in _DATA_ATTR:
            continue
        if ai.name:   # named NTFS stream (ADS); not the file's main content
            streams.append({"name": _decode(ai.name), "size": int(ai.size)})
            continue
        flags = int(ai.flags)
        resident = bool(flags & _ATTR_RES)
        compressed = bool(flags & _ATTR_COMP)
        encrypted = bool(flags & _ATTR_ENC)
        sparse = bool(flags & _ATTR_SPARSE)
        if resident:
            continue    # content lives inside the MFT entry: no runs
        for run in attr:
            rflags = int(run.flags)
            if rflags & _RUN_FILLER:
                continue
            if rflags & _RUN_SPARSE:
                sparse = True     # no physical clusters behind this run
                continue
            runs.append((partition_offset + int(run.addr) * block_size,
                         int(run.len) * block_size))
    return runs, streams, resident, compressed, sparse, encrypted


def scan(fs, vol, cancel=None, progress=None, log=None):
    """Walk the file system and return a MetaScan.

    vol: VolumeInfo (for partition offset, block size, fs type).
    """
    log = log or (lambda msg, level="INFO": None)
    fs_type = vol.fs_type
    basis = _timestamp_basis(fs_type)
    records, errors = [], []
    excluded = Counter()
    visited = set()
    seen = [0]

    def walk(directory, parent_path):
        for entry in directory:
            if cancel is not None and cancel():
                raise InterruptedError("metadata scan cancelled")
            seen[0] += 1
            if progress is not None and seen[0] % 50 == 0:
                progress(seen[0], 0)
            nm = entry.info.name
            name = _decode(nm.name)
            path = f"{parent_path}/{name}" if parent_path != "/" else f"/{name}"
            file_obj, meta = entry, entry.info.meta
            if meta is None and nm.meta_addr:
                # See module docstring: deleted NTFS names come without meta.
                try:
                    file_obj = fs.open_meta(inode=nm.meta_addr)
                    meta = file_obj.info.meta
                except (IOError, OSError, RuntimeError) as exc:
                    errors.append(f"{path}: open_meta({nm.meta_addr}) failed: {exc}")
                    meta = None
            mtype = int(meta.type) if meta is not None else None
            is_virtual = (int(nm.type) in _VIRT_NAME) or (mtype in _VIRT_META)
            size = int(meta.size) if meta is not None else 0
            key = EntryKey(path=path, name=name, is_virtual=is_virtual,
                           size=size, has_meta=meta is not None,
                           fs_type=fs_type)
            reason = exclusion_reason(key)
            is_dir = mtype in _DIR_TYPES

            if reason is None:
                try:
                    records.append(_make_record(
                        file_obj, meta, nm, name, path, is_dir, fs_type,
                        vol.offset_bytes, vol.block_size, basis))
                except Exception as exc:  # one bad entry must not stop the walk
                    errors.append(f"{path}: record failed: {exc}")
            else:
                excluded[reason] += 1

            # Recurse into every directory, deleted or excluded ones too:
            # $OrphanFiles holds real orphans, and deleted folders can still
            # list deleted files. `visited` stops loops via reused entries.
            if is_dir and name not in (".", "..") and meta is not None:
                addr = int(meta.addr)
                if addr in visited:
                    continue
                visited.add(addr)
                try:
                    walk(file_obj.as_directory(), path)
                except (IOError, OSError, RuntimeError) as exc:
                    errors.append(f"{path}: cannot open directory: {exc}")

    root = fs.open_dir(inode=fs.info.root_inum)
    visited.add(int(fs.info.root_inum))
    walk(root, "/")

    summary = _summary(records, excluded, seen[0])
    for e in errors:
        log(e, "WARNING")
    return MetaScan(records=records, excluded=dict(excluded), errors=errors,
                    summary=summary)


def _make_record(file_obj, meta, nm, name, path, is_dir, fs_type,
                 part_offset, block_size, basis):
    meta_flags, name_flags = int(meta.flags), int(nm.flags)
    name_unalloc = bool(name_flags & _NAME_UNALLOC)
    meta_unalloc = bool(meta_flags & _META_UNALLOC)
    runs, streams, resident, comp, sparse, enc = _data_info(
        file_obj, part_offset, block_size)
    rec = MetaRecord(
        path=path, name=name, meta_addr=int(meta.addr), is_dir=is_dir,
        deleted=name_unalloc or meta_unalloc,
        name_unalloc=name_unalloc, meta_unalloc=meta_unalloc,
        realloc=name_unalloc and bool(meta_flags & _META_ALLOC),
        size=int(meta.size), resident=resident, compressed=comp,
        sparse=sparse, encrypted=enc, data_runs=runs, streams=streams,
        timestamps=_timestamps(meta, fs_type), timestamp_basis=basis)
    if rec.realloc:
        rec.notes.append("Name is deleted but its metadata entry has been "
                         "reused; size, times and data belong to the new file.")
    if fs_type == "FAT32" and rec.deleted and runs:
        rec.notes.append("Deleted FAT file: data run reconstructed by TSK "
                         "assuming contiguous clusters.")
    return rec


def _summary(records, excluded, seen):
    files = [r for r in records if not r.is_dir]
    ext = Counter()
    for r in files:
        dot = r.name.rfind(".")
        ext[r.name[dot + 1:].lower() if dot > 0 else "(none)"] += 1
    return {
        "entries_seen": seen,
        "listed": len(records),
        "directories": sum(r.is_dir for r in records),
        "files": len(files),
        "files_deleted": sum(r.deleted for r in files),
        "files_allocated": sum(not r.deleted for r in files),
        "per_extension": dict(sorted(ext.items())),
        "excluded": dict(excluded),
        "flagged_compressed": sum(r.compressed for r in files),
        "flagged_sparse": sum(r.sparse for r in files),
        "flagged_encrypted": sum(r.encrypted for r in files),
    }


# --------------------------------------------------------------------------
# TXT recovery
# --------------------------------------------------------------------------

def is_txt(record):
    # By design, TXT is the one type chosen by extension (spec Section 2).
    return (not record.is_dir) and record.name.lower().endswith(".txt")


def _content_chunks(file_obj, size):
    offset = 0
    while offset < size:
        n = min(READ_CHUNK, size - offset)
        data = file_obj.read_random(offset, n)
        if not data:
            return      # short read: caller sees fewer bytes than size
        yield data
        offset += len(data)


def recover_txt(fs, record, case_dir):
    """Recover one TXT file via its metadata and export it.

    Returns a result dict in the common report-record shape.
    """
    sep_dir = exporter.SEPARATION_DIRS[record.separation]
    out_dir = f"{case_dir}/{exporter.TXT_DIR}/{sep_dir}"
    checks, notes = [], list(record.notes)
    try:
        file_obj = fs.open_meta(inode=record.meta_addr)
        res = exporter.export_stream(_content_chunks(file_obj, record.size),
                                     out_dir, record.name)
    except Exception as exc:
        return _txt_result(record, "FAILED", None, [f"open failed: {exc}"],
                           notes)
    if res.error and res.bytes_written == 0:
        status = "FAILED"
    elif res.bytes_written == record.size and not res.error:
        status = "RECOVERED"
    else:
        status = "PARTIAL"
    checks.append(f"bytes read {res.bytes_written} of fs size {record.size}")
    if res.error:
        checks.append(f"read error: {res.error}")
    if res.all_zero:
        checks.append("ALL_ZERO: content is entirely 0x00 (likely overwritten)")
    for flag in ("compressed", "sparse", "encrypted"):
        if getattr(record, flag):
            if status == "RECOVERED":
                status = "PARTIAL"
            notes.append(f"Data attribute is {flag}: out of scope for "
                         "LiteCarve; content is as returned by TSK and is "
                         "not verified.")
    return _txt_result(record, status, res, checks, notes)


def _txt_result(record, status, res, checks, notes):
    return {
        "method": "metadata",
        "type": "txt",
        "subtype": "",
        "status": status,
        "all_zero": bool(res and res.all_zero),
        "separation": record.separation,
        "offset": record.first_offset,
        "length": res.bytes_written if res else 0,
        "original_name": record.name,
        "original_path": record.path,
        "meta_addr": record.meta_addr,
        "resident": record.resident,
        "timestamps": record.timestamps,
        "timestamp_basis": record.timestamp_basis,
        "fs_size": record.size,
        "size_consistent": bool(res and res.bytes_written == record.size),
        "md5": res.hashes.md5 if res else "",
        "sha256": res.hashes.sha256 if res else "",
        "export_path": res.path if res else "",
        "checks": checks,
        "notes": notes,
    }
