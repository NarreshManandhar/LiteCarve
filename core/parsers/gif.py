#GIF parser: walks blocks to the real trailer.

import struct

from core.parsers import ParseResult, VALID, PARTIAL, invalid

SIGNATURES = (b"GIF87a", b"GIF89a")


def _colour_table_size(packed):
    return 3 * (2 ** ((packed & 7) + 1)) if packed & 0x80 else 0


def _skip_sub_blocks(buf, p, limit):
    """Return the position after the zero-length terminator, or -1."""
    while p < limit:
        n = buf[p]
        if n == 0:
            return p + 1
        p += n + 1
    return -1


def parse(buf, offset, max_len):
    limit = offset + max_len
    if bytes(buf[offset:offset + 6]) not in SIGNATURES or offset + 13 > limit:
        return invalid(offset, "no GIF header / logical screen descriptor")
    version = bytes(buf[offset + 3:offset + 6]).decode()
    width, height, packed = struct.unpack_from("<HHB", buf, offset + 6)
    checks = [f"GIF{version} {width}x{height}"]
    p = offset + 13 + _colour_table_size(packed)
    if p > limit:
        return invalid(offset, "global colour table runs past read limit", checks)
    if packed & 0x80:
        checks.append(f"global colour table {_colour_table_size(packed)} bytes")
    frames = extensions = 0
    good_end = p
    stop_reason = "reached read limit without trailer"

    while p < limit:
        intro = buf[p]
        if intro == 0x3B:
            end = p + 1
            details = {"version": version, "width": width, "height": height,
                       "frames": frames, "extensions": extensions,
                       "animated": frames > 1}
            checks.append(f"trailer reached: {frames} frame(s), "
                          f"{extensions} extension(s)")
            status = VALID if frames else PARTIAL
            if not frames:
                checks.append("no image frame")
            return ParseResult(status, offset, end,
                               subtype="animated" if frames > 1 else "static",
                               checks=checks, details=details)
        if intro == 0x2C:
            if p + 11 > limit:
                break
            lpacked = buf[p + 9]
            q = p + 10 + _colour_table_size(lpacked)
            if q >= limit:
                break
            lzw = buf[q]
            if not 1 <= lzw <= 12:
                stop_reason = f"invalid LZW code size {lzw} at +{q - offset}"
                break
            q = _skip_sub_blocks(buf, q + 1, limit)
            if q == -1:
                stop_reason = "image data runs past read limit"
                break
            frames += 1
        elif intro == 0x21:
            if p + 2 > limit:
                break
            q = _skip_sub_blocks(buf, p + 2, limit)
            if q == -1:
                stop_reason = "extension runs past read limit"
                break
            extensions += 1
        else:
            stop_reason = f"unknown block 0x{intro:02X} at +{p - offset}"
            break
        p = q
        good_end = p

    details = {"version": version, "width": width, "height": height,
               "frames": frames, "extensions": extensions}
    if frames + extensions == 0:
        return invalid(offset, stop_reason, checks)
    checks.append(stop_reason)
    return ParseResult(PARTIAL, offset, good_end,
                       subtype="animated" if frames > 1 else "static",
                       checks=checks, details=details)
