"""JPEG parser: walks marker segments from SOI to EOI."""

import struct

from core.parsers import ParseResult, VALID, PARTIAL, invalid

SOI = b"\xFF\xD8\xFF"
EOI = 0xD9
SOS = 0xDA
# SOF markers C0-CF except DHT (C4), JPG extension (C8) and DAC (CC).
SOF_MARKERS = {m for m in range(0xC0, 0xD0)} - {0xC4, 0xC8, 0xCC}
SOF_NAMES = {0xC0: "baseline", 0xC1: "extended sequential",
             0xC2: "progressive", 0xC3: "lossless"}
# Segments that a real JPEG header is made of (used for the PARTIAL rule).
STANDARD_SEGMENTS = (set(range(0xE0, 0xF0))           # APP0-APP15
                     | {0xDB, 0xC4, 0xDD, 0xFE, 0xCC}  # DQT DHT DRI COM DAC
                     | SOF_MARKERS)


def _sof_details(buf, seg, seg_len, marker):
    """Parse a SOF segment; return details dict or None if malformed."""
    if seg_len < 8:
        return None
    precision, height, width, ncomp = struct.unpack_from(">BHHB", buf, seg)
    # Length must be exactly 8 + 3 bytes per component (T.81 B.2.2).
    if (precision not in (8, 12, 16) or width == 0 or not 1 <= ncomp <= 4
            or seg_len != 8 + 3 * ncomp):
        return None
    return {"sof": f"SOF{marker - 0xC0}",
            "coding": SOF_NAMES.get(marker, "other"),
            "width": width, "height": height,
            "precision": precision, "components": ncomp}


def parse(buf, offset, max_len):
    limit = offset + max_len
    if limit - offset < 4 or buf[offset:offset + 3] != SOI:
        return invalid(offset, "no SOI marker")
    checks = ["SOI at start"]
    p = offset + 2
    good_end = p          # last byte boundary up to which the structure is valid
    sof = None
    sos_count = 0
    segments = 0
    eoi_found = False
    stop_reason = "reached read limit without EOI"

    while p < limit:
        if buf[p] != 0xFF:
            stop_reason = f"expected marker at +{p - offset}, found 0x{buf[p]:02X}"
            break
        while p < limit and buf[p] == 0xFF:    # fill bytes before a marker
            p += 1
        if p >= limit:
            break
        marker = buf[p]
        p += 1
        if marker == EOI:
            good_end = p
            eoi_found = True
            checks.append(f"EOI at +{p - 2 - offset}")
            break
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            good_end = p                         # standalone, no length
            continue
        if marker in (0x00, 0xD8):
            stop_reason = f"unexpected marker FF{marker:02X} at +{p - 2 - offset}"
            break
        if p + 2 > limit:
            break
        seg_len = struct.unpack_from(">H", buf, p)[0]
        if seg_len < 2:
            stop_reason = f"segment FF{marker:02X} has invalid length {seg_len}"
            break
        seg_end = p + seg_len
        if seg_end > limit:
            stop_reason = f"segment FF{marker:02X} runs past read limit"
            break
        if marker in SOF_MARKERS and sof is None:
            sof = _sof_details(buf, p + 2, seg_len, marker)
            if sof is None:
                stop_reason = f"malformed SOF FF{marker:02X}"
                break
            checks.append(f"{sof['sof']} ({sof['coding']}) "
                          f"{sof['width']}x{sof['height']}")
        segments += 1 if marker in STANDARD_SEGMENTS else 0
        p = seg_end
        good_end = p
        if marker == SOS:
            sos_count += 1
            # Entropy-coded data: find the next FF that is a real marker.
            q = p
            while True:
                q = buf.find(b"\xFF", q, limit)
                if q == -1 or q + 1 >= limit:
                    q = -1
                    break
                nxt = buf[q + 1]
                if nxt == 0x00 or 0xD0 <= nxt <= 0xD7:
                    q += 2           # stuffed byte or restart marker: data
                    continue
                break
            if q == -1:
                stop_reason = "entropy-coded data runs to read limit"
                good_end = limit
                p = limit
                break
            p = q
            good_end = p

    details = dict(sof or {})
    details["scans"] = sos_count
    if sos_count:
        checks.append(f"{sos_count} scan(s) (SOS)")
    subtype = sof["coding"] if sof else ""
    if eoi_found and sof and sos_count:
        return ParseResult(VALID, offset, good_end, subtype=subtype,
                           checks=checks, details=details)
    if sof or segments >= 2:
        if not eoi_found:
            checks.append(stop_reason)
        if not sof:
            checks.append("no SOF frame header")
        if not sos_count:
            checks.append("no SOS scan")
        return ParseResult(PARTIAL, offset, good_end, subtype=subtype,
                           checks=checks, details=details)
    return invalid(offset, stop_reason if not eoi_found
                   else "EOI without frame/scan", checks)
