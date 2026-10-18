"""ZIP / DOCX parser: end found through the central directory, type from content."""

import io
import struct
import zipfile

from core.parsers import ParseResult, VALID, PARTIAL, invalid

LOCAL = b"PK\x03\x04"
EOCD = b"PK\x05\x06"
ZIP64_EOCD = b"PK\x06\x06"
ZIP64_LOCATOR = b"PK\x06\x07"
EOCD_SIZE = 22

SUBTYPE_EXT = {"docx": "docx", "xlsx": "xlsx", "pptx": "pptx", "zip": "zip"}


def _classify(names):
    names = set(names)
    if "[Content_Types].xml" in names and "word/document.xml" in names:
        return "docx"
    if "xl/workbook.xml" in names:
        return "xlsx"
    if "ppt/presentation.xml" in names:
        return "pptx"
    return "zip"


def _local_header(buf, p, limit):
    """Check a local file header for plausibility.

    Returns None if implausible, else the position after the member's data,
    or -1 if that position cannot be known from the header alone: with a
    data descriptor (flag bit 3) the sizes follow the data, and with ZIP64
    the 32-bit size fields hold 0xFFFFFFFF.
    """
    if p + 30 > limit or bytes(buf[p:p + 4]) != LOCAL:
        return None
    (ver, flags, method, _t, _d, _crc, csize, _usize, nlen,
     xlen) = struct.unpack_from("<HHHHHIIIHH", buf, p + 4)
    if ver > 100 or method not in (0, 8, 9, 12, 14, 93, 95, 98, 99) \
            or nlen == 0 or nlen > 1024:
        return None
    if flags & 0x08 or csize == 0xFFFFFFFF:
        return -1
    return p + 30 + nlen + xlen + csize


CENTRAL = b"PK\x01\x02"
ZIP64_EXTRA_ID = 0x0001


def _has_zip64_extra(buf, x, x_end):
    while x + 4 <= x_end:
        hid, hlen = struct.unpack_from("<HH", buf, x)
        if hid == ZIP64_EXTRA_ID:
            return True
        x += 4 + hlen
    return False


def _members_use_zip64(buf, start, cd_start, cd_end):
    """True if any member signals ZIP64 in its central or local header.

    ZIP64 can be used per member (APPNOTE 4.5.3): a size or offset field holds
    0xFFFFFFFF and the real value sits in an extra field with ID 0x0001. Some
    writers mark this only in the local header, so both are checked.
    """
    p = cd_start
    while p + 46 <= cd_end and bytes(buf[p:p + 4]) == CENTRAL:
        csize, usize = struct.unpack_from("<II", buf, p + 20)
        nlen, xlen, clen = struct.unpack_from("<HHH", buf, p + 28)
        local_off = struct.unpack_from("<I", buf, p + 42)[0]
        if 0xFFFFFFFF in (csize, usize, local_off):
            return True
        if _has_zip64_extra(buf, p + 46 + nlen, p + 46 + nlen + xlen):
            return True
        lp = start + local_off
        if lp + 30 <= cd_start and bytes(buf[lp:lp + 4]) == LOCAL:
            lcs, lus = struct.unpack_from("<II", buf, lp + 18)
            lnl, lxl = struct.unpack_from("<HH", buf, lp + 26)
            if 0xFFFFFFFF in (lcs, lus) or _has_zip64_extra(
                    buf, lp + 30 + lnl, lp + 30 + lnl + lxl):
                return True
        p += 46 + nlen + xlen + clen
    return False


def _walk_locals(buf, start, limit):
    """Count complete members by local headers; return (members, end)."""
    p, members = start, 0
    while True:
        nxt = _local_header(buf, p, limit)
        if nxt is None or nxt == -1 or nxt > limit:
            return members, p
        members += 1
        p = nxt


def parse(buf, offset, max_len):
    limit = offset + max_len
    if _local_header(buf, offset, limit) is None:
        return invalid(offset, "implausible local file header")
    checks = ["local file header plausible"]

    pos = buf.find(EOCD, offset, limit)
    eocd_pos = -1
    while pos != -1 and pos + EOCD_SIZE <= limit:
        entries, cd_size, cd_off, clen = struct.unpack_from("<HIIH", buf, pos + 10)
        if offset + cd_off + cd_size == pos and pos + EOCD_SIZE + clen <= limit:
            eocd_pos = pos
            break
        pos = buf.find(EOCD, pos + 4, limit)

    if eocd_pos == -1:
        members, end = _walk_locals(buf, offset, limit)
        checks.append("no consistent end of central directory")
        if members == 0:
            return invalid(offset, "no complete member", checks)
        checks.append(f"{members} complete member(s) by local headers")
        return ParseResult(PARTIAL, offset, end, subtype="zip", checks=checks,
                           details={"members": members, "extension": "zip"})

    end = eocd_pos + EOCD_SIZE + clen
    checks.append(f"EOCD at +{eocd_pos - offset} consistent with central "
                  f"directory ({entries} entries)")
    details = {"entries": entries, "comment_length": clen}

    zip64 = (buf.find(ZIP64_LOCATOR, offset, eocd_pos) != -1
             or buf.find(ZIP64_EOCD, offset, eocd_pos) != -1
             or cd_size == 0xFFFFFFFF or cd_off == 0xFFFFFFFF
             or entries == 0xFFFF
             or _members_use_zip64(buf, offset, offset + cd_off, eocd_pos))
    if zip64:
        details["extension"] = "zip"
        return ParseResult(PARTIAL, offset, end, subtype="zip64",
                           checks=checks + ["ZIP64 structures present"],
                           notes=["ZIP64 not supported"], details=details)

    try:
        with zipfile.ZipFile(io.BytesIO(bytes(buf[offset:end]))) as zf:
            names = zf.namelist()
            bad = zf.testzip()
    except Exception as exc:    # corrupt archive: structure found, content bad
        details["extension"] = "zip"
        return ParseResult(PARTIAL, offset, end, subtype="zip",
                           checks=checks + [f"zipfile rejected archive: {exc}"],
                           details=details)
    subtype = _classify(names)
    details.update(members=len(names), extension=SUBTYPE_EXT[subtype],
                   names_sample=names[:10])
    checks.append(f"classified as {subtype} from member names")
    if bad is not None:
        return ParseResult(PARTIAL, offset, end, subtype=subtype,
                           checks=checks + [f"CRC failure in member {bad!r}"],
                           details=details)
    checks.append(f"testzip: all {len(names)} member CRCs OK")
    return ParseResult(VALID, offset, end, subtype=subtype, checks=checks,
                       details=details)
