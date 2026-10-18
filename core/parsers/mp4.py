"""MP4 / ISO base media file parser: walks top-level boxes."""

import struct

from core.parsers import ParseResult, VALID, PARTIAL, invalid

TOP_LEVEL = {b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"uuid",
             b"meta", b"pdin", b"moof", b"mfra", b"sidx", b"styp", b"prft",
             b"emsg"}
MP4_BRANDS = {b"isom", b"iso2", b"mp41", b"mp42", b"avc1", b"M4V "}
MAX_UNKNOWN = 16   # bounds the walk through unrecognised boxes


def _printable(b):
    return all(0x20 <= c <= 0x7E for c in b)


def subtype_for(brand):
    if brand in MP4_BRANDS:
        return "mp4", "mp4"
    if brand == b"M4A ":
        return "m4a", "m4a"
    if brand == b"qt  ":
        return "mov", "mov"
    if brand.startswith(b"3gp"):
        return "3gp", "3gp"
    return f"mp4 ({brand.decode('ascii', 'replace').strip()})", "mp4"


def parse(buf, offset, max_len):
    limit = offset + max_len
    if offset + 16 > limit or bytes(buf[offset + 4:offset + 8]) != b"ftyp":
        return invalid(offset, "no ftyp box")
    ftyp_size = struct.unpack_from(">I", buf, offset)[0]
    brand = bytes(buf[offset + 8:offset + 12])
    if not 8 <= ftyp_size <= 256 or not _printable(brand):
        return invalid(offset, f"implausible ftyp (size {ftyp_size}, "
                       f"brand {brand!r})")
    subtype, ext = subtype_for(brand)
    checks = [f"ftyp size {ftyp_size}, major brand {brand.decode('ascii')!r}"]
    p = offset
    boxes = []
    unknown = []
    stop_reason = "reached read limit"
    while p + 8 <= limit:
        size, btype = struct.unpack_from(">I4s", buf, p)
        header = 8
        if size == 1:
            if p + 16 > limit:
                break
            size = struct.unpack_from(">Q", buf, p + 8)[0]
            header = 16
        seen = {b for b, _ in boxes}
        complete = "moov" in seen and bool(seen & {"mdat", "moof"})
        if btype not in TOP_LEVEL:
            if complete or not _printable(btype) or len(unknown) >= MAX_UNKNOWN:
                stop_reason = (f"box type {btype!r} at +{p - offset} is not a "
                               "known top-level box"
                               + (" (file already complete)" if complete else ""))
                break
        if size == 0:
            stop_reason = f"{btype.decode()} box has size 0 (to end of file)"
            break
        if size < header or p + size > limit:
            stop_reason = f"{btype.decode()} box size {size} does not fit"
            break
        if btype not in TOP_LEVEL:
            unknown.append((btype.decode("ascii"), p - offset, size))
        boxes.append((btype.decode("ascii"), size))
        p += size
    names = {b for b, _ in boxes}
    checks.append("boxes: " + " ".join(f"{b}({s})" for b, s in boxes))
    for name, rel, size in unknown:
        checks.append(f"skipped unknown box {name!r} at +{rel} ({size} bytes)")
    details = {"major_brand": brand.decode("ascii"), "boxes": boxes,
               "unknown_boxes": [u[0] for u in unknown], "extension": ext}
    if "moov" in names and ("mdat" in names or "moof" in names):
        return ParseResult(VALID, offset, p, subtype=subtype, checks=checks,
                           details=details)
    checks.append(stop_reason)
    if "moov" not in names:
        checks.append("no moov box")
    if not names & {"mdat", "moof"}:
        checks.append("no mdat/moof box")
    return ParseResult(PARTIAL, offset, p, subtype=subtype, checks=checks,
                       details=details)
