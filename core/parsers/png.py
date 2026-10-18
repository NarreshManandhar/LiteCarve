"""PNG parser: walks chunks and verifies every CRC."""

import struct
import zlib

from core.parsers import ParseResult, VALID, PARTIAL, invalid

SIGNATURE = b"\x89PNG\r\n\x1a\n"
COLOUR_TYPES = {0: "greyscale", 2: "truecolour", 3: "indexed",
                4: "greyscale+alpha", 6: "truecolour+alpha"}
MAX_CHUNK = 0x7FFFFFFF   # PNG spec: lengths must not exceed 2^31 - 1


def _is_chunk_type(t):
    return all(65 <= c <= 90 or 97 <= c <= 122 for c in t)


def parse(buf, offset, max_len):
    limit = offset + max_len
    if buf[offset:offset + 8] != SIGNATURE:
        return invalid(offset, "no PNG signature")
    p = offset + 8
    checks = ["PNG signature"]
    details = {}
    chunks = 0
    crc_failures = 0
    good_end = p
    stop_reason = "reached read limit without IEND"

    while p + 12 <= limit:
        length = struct.unpack_from(">I", buf, p)[0]
        ctype = bytes(buf[p + 4:p + 8])
        if not _is_chunk_type(ctype) or length > MAX_CHUNK:
            stop_reason = f"no valid chunk at +{p - offset}"
            break
        crc_end = p + 12 + length
        if crc_end > limit:
            stop_reason = f"chunk {ctype.decode()} runs past read limit"
            break
        if chunks == 0:
            if ctype != b"IHDR" or length != 13:
                return invalid(offset, "first chunk is not IHDR(13)", checks)
            w, h, depth, colour = struct.unpack_from(">IIBB", buf, p + 8)
            details.update(width=w, height=h, bit_depth=depth,
                           colour_type=COLOUR_TYPES.get(colour, str(colour)))
            checks.append(f"IHDR {w}x{h} depth {depth} "
                          f"{details['colour_type']}")
        stored = struct.unpack_from(">I", buf, crc_end - 4)[0]
        if zlib.crc32(buf[p + 4:crc_end - 4]) != stored:
            crc_failures += 1
            checks.append(f"CRC mismatch in {ctype.decode()} at +{p - offset}")
        chunks += 1
        p = crc_end
        good_end = p
        if ctype == b"IEND":
            details.update(chunks=chunks, crc_failures=crc_failures)
            checks.append(f"IEND reached; {chunks} chunks, "
                          f"{crc_failures} CRC failures")
            status = VALID if crc_failures == 0 else PARTIAL
            return ParseResult(status, offset, p, checks=checks,
                               details=details)

    if chunks == 0:
        return invalid(offset, "no complete IHDR chunk", checks)
    details.update(chunks=chunks, crc_failures=crc_failures)
    checks.append(stop_reason)
    return ParseResult(PARTIAL, offset, good_end, checks=checks,
                       details=details)
