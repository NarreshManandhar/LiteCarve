"""Partition and file-system detection."""

import struct
from dataclasses import dataclass, asdict, field

import pytsk3

DEFAULT_SECTOR_SIZE = 512

SUPPORTED_FS = {
    int(pytsk3.TSK_FS_TYPE_NTFS): "NTFS",
    int(pytsk3.TSK_FS_TYPE_FAT32): "FAT32",
}

VS_TYPE_NAMES = {
    int(pytsk3.TSK_VS_TYPE_DOS): "MBR (DOS)",
    int(pytsk3.TSK_VS_TYPE_GPT): "GPT",
}

# Boot-sector signatures: (offset, bytes) -> file-system name.
BOOT_SIGNATURES = [
    (3, b"NTFS    ", "NTFS"),
    (0x52, b"FAT32   ", "FAT32"),
]


class VolumeError(Exception):
    pass


@dataclass
class VolumeInfo:
    partition_table: str          # "MBR (DOS)", "GPT", "MBR (manual parse)", "none"
    detection_method: str         # "tsk_volume_system", "manual_mbr", "offset_0"
    mbr_entry: object             # MBR partition-table entry 0-3 (primary value);
                                  # None for a bare partition image
    tsk_slot: object              # TSK's volume-system slot address ("TSK slot")
    partition_type: str           # description / MBR type byte
    start_sector: int
    sector_size: int
    offset_bytes: int
    size_bytes: int
    fs_type: str                  # "NTFS" or "FAT32" (from TSK)
    boot_signature: str           # what the boot sector string says, or "none"
    boot_signature_consistent: bool
    block_size: int               # TSK data-unit size (NTFS cluster / FAT sector)
    cluster_size: int             # file-system allocation unit in bytes
    volume_label: str = ""
    candidates: list = field(default_factory=list)  # every partition considered

    def to_dict(self):
        return asdict(self)


def parse_mbr(sector0, image_size, sector_size=DEFAULT_SECTOR_SIZE):
    """Return plausible MBR partition entries from the first sector.

    Each entry is a dict(index, type, start_lba, num_sectors). Entries are
    rejected if the type is 0 (unused), the boot flag is not 0x00/0x80, the
    start is 0, or the partition would extend past the end of the image:
    this filters out boot-code bytes of a bare file-system image.
    """
    if len(sector0) < 512 or sector0[510:512] != b"\x55\xaa":
        return []
    entries = []
    for i in range(4):
        e = sector0[0x1BE + 16 * i: 0x1BE + 16 * (i + 1)]
        boot_flag, ptype = e[0], e[4]
        start_lba, num = struct.unpack_from("<II", e, 8)
        if ptype == 0 or boot_flag not in (0x00, 0x80):
            continue
        if start_lba == 0 or num == 0:
            continue
        if (start_lba + num) * sector_size > image_size:
            continue
        entries.append({"index": i, "type": f"0x{ptype:02x}",
                        "start_lba": start_lba, "num_sectors": num})
    return entries


def boot_signature(boot_sector):
    """Which file system the boot-sector strings indicate ("none" if neither)."""
    for off, sig, name in BOOT_SIGNATURES:
        if boot_sector[off:off + len(sig)] == sig:
            return name
    return "none"


def _fat32_label(boot_sector):
    # FAT32 extended BPB: volume label is 11 bytes at offset 0x47.
    return boot_sector[0x47:0x52].decode("ascii", "replace").strip()


def _ntfs_label(fs):
    # The label is the $VOLUME_NAME attribute (type 0x60, UTF-16LE) of MFT
    # entry 3 ($Volume).
    try:
        f = fs.open_meta(inode=3)
        for attr in f:
            if int(attr.info.type) == int(pytsk3.TSK_FS_ATTR_TYPE_NTFS_VNAME):
                data = f.read_random(0, attr.info.size, attr.info.type,
                                     attr.info.id)
                return data.decode("utf-16-le", "replace").strip("\x00 ")
    except Exception:
        pass
    return ""


def _try_fs(img, offset):
    try:
        return pytsk3.FS_Info(img, offset=offset)
    except (IOError, OSError, RuntimeError):
        return None


def _candidates(img, image_size):
    """Yield (method, table, mbr_entry, tsk_slot, ptype, start_sector,
    sector_size, size).

    Two partition numbers are kept: the MBR entry (0-3, what a partition
    editor shows) and TSK's slot address (what mmls/TSK tools show, which
    also counts the table itself and unallocated gaps).
    """
    try:
        vol = pytsk3.Volume_Info(img)
    except (IOError, OSError, RuntimeError):
        vol = None
    if vol is not None:
        sector_size = int(vol.info.block_size or 0) or DEFAULT_SECTOR_SIZE
        table = VS_TYPE_NAMES.get(int(vol.info.vstype), str(vol.info.vstype))
        for part in vol:
            # Only allocated partitions: "Meta" is the table itself and
            # "Unallocated" is the gap before the first partition.
            if not int(part.flags) & int(pytsk3.TSK_VS_PART_FLAG_ALLOC):
                continue
            # slot_num is the entry inside the partition table (-1 for
            # non-table entries; extended-partition tables are not in scope).
            entry = int(part.slot_num) if int(part.slot_num) >= 0 else None
            yield ("tsk_volume_system", table, entry, int(part.addr),
                   part.desc.decode("utf-8", "replace"), int(part.start),
                   sector_size, int(part.len) * sector_size)
        return
    sector0 = img.read(0, DEFAULT_SECTOR_SIZE)
    for e in parse_mbr(sector0, image_size):
        yield ("manual_mbr", "MBR (manual parse)", e["index"], None, e["type"],
               e["start_lba"], DEFAULT_SECTOR_SIZE,
               e["num_sectors"] * DEFAULT_SECTOR_SIZE)
    yield ("offset_0", "none", None, None, "partition image", 0,
           DEFAULT_SECTOR_SIZE, image_size)


def open_filesystem(image_path, log=None):
    """Find the first supported file system in the image.

    Returns (VolumeInfo, img, fs). ``img`` and ``fs`` are pytsk3 handles for
    the metadata scan. Raises VolumeError if nothing usable is found.
    log: optional callable(message) for the run log.
    """
    log = log or (lambda msg: None)
    img = pytsk3.Img_Info(image_path)
    image_size = img.get_size()
    tried = []
    seen_offsets = set()
    for (method, table, entry, slot, ptype, start, ssize, size) in _candidates(
            img, image_size):
        offset = start * ssize
        if offset in seen_offsets:
            continue
        seen_offsets.add(offset)
        fs = _try_fs(img, offset)
        ftype = SUPPORTED_FS.get(int(fs.info.ftype)) if fs else None
        desc = {"method": method, "mbr_entry": entry, "tsk_slot": slot,
                "type": ptype,
                "start_sector": start, "offset_bytes": offset,
                "file_system": ftype or ("unsupported" if fs else "none")}
        tried.append(desc)
        log(f"candidate {desc}")
        if ftype is None:
            continue
        boot = img.read(offset, DEFAULT_SECTOR_SIZE)
        sig = boot_signature(boot)
        block = int(fs.info.block_size)
        if ftype == "FAT32":
            # BPB: bytes/sector at 0x0B, sectors/cluster at 0x0D.
            cluster = struct.unpack_from("<H", boot, 0x0B)[0] * boot[0x0D]
            label = _fat32_label(boot)
        else:
            cluster = block
            label = _ntfs_label(fs)
        info = VolumeInfo(
            partition_table=table, detection_method=method,
            mbr_entry=entry, tsk_slot=slot, partition_type=ptype,
            start_sector=start, sector_size=ssize, offset_bytes=offset,
            size_bytes=size, fs_type=ftype, boot_signature=sig,
            boot_signature_consistent=(sig == ftype), block_size=block,
            cluster_size=cluster or block, volume_label=label,
            candidates=tried)
        return info, img, fs
    raise VolumeError("No NTFS or FAT32 file system found. Tried: "
                      + "; ".join(str(t) for t in tried))
