"""MP3 parser: ID3v2 tag, then a walk of consecutive MPEG audio frames."""

import struct

from core.parsers import ParseResult, VALID, PARTIAL, invalid

FIRST_FRAME_SEARCH = 4096
MIN_FRAMES_ID3 = 10
MIN_FRAMES_HEADERLESS = 30
ID3V1_SIZE = 128
APE_FOOTER = 32
APE_SEARCH = 1024 * 1024

# Bitrates (kbit/s) by (version group, layer) and bitrate index.
_BITRATES = {
    (1, 1): [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448],
    (1, 2): [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384],
    (1, 3): [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320],
    (2, 1): [0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256],
    (2, 2): [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
    (2, 3): [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
}
_SAMPLE_RATES = {"1": [44100, 48000, 32000], "2": [22050, 24000, 16000],
                 "2.5": [11025, 12000, 8000]}
_VERSIONS = {3: "1", 2: "2", 0: "2.5"}      # bits 19-20; 1 is reserved
_LAYERS = {3: 1, 2: 2, 1: 3}               # bits 17-18; 0 is reserved
_SAMPLES_PER_FRAME = {(1, "1"): 384, (2, "1"): 1152, (3, "1"): 1152,
                      (1, "2"): 384, (2, "2"): 1152, (3, "2"): 576,
                      (1, "2.5"): 384, (2, "2.5"): 1152, (3, "2.5"): 576}


def frame_header(buf, p, limit):
    """Decode a frame header at p; return dict or None if not valid."""
    if p + 4 > limit:
        return None
    h = struct.unpack_from(">I", buf, p)[0]
    if (h >> 21) & 0x7FF != 0x7FF:
        return None
    version = _VERSIONS.get((h >> 19) & 3)
    layer = _LAYERS.get((h >> 17) & 3)
    br_idx, sr_idx, pad = (h >> 12) & 0xF, (h >> 10) & 3, (h >> 9) & 1
    if version is None or layer is None or br_idx in (0, 15) or sr_idx == 3:
        return None
    group = 1 if version == "1" else 2
    bitrate = _BITRATES[(group, layer)][br_idx] * 1000
    rate = _SAMPLE_RATES[version][sr_idx]
    if layer == 1:
        length = (12 * bitrate // rate + pad) * 4
    elif layer == 3 and version != "1":
        length = 72 * bitrate // rate + pad
    else:
        length = 144 * bitrate // rate + pad
    if length < 4:
        return None
    return {"version": version, "layer": layer, "bitrate": bitrate,
            "rate": rate, "length": length,
            "samples": _SAMPLES_PER_FRAME[(layer, version)]}


def _walk_frames(buf, p, limit):
    """Walk consecutive consistent frames from p. Returns (count, end, info)."""
    first = frame_header(buf, p, limit)
    if first is None:
        return 0, p, None
    count, bitrates, samples = 0, set(), 0
    while True:
        h = frame_header(buf, p, limit)
        if h is None or (h["version"], h["layer"], h["rate"]) != \
                (first["version"], first["layer"], first["rate"]):
            break
        if p + h["length"] > limit:
            break
        count += 1
        bitrates.add(h["bitrate"])
        samples += h["samples"]
        p += h["length"]
    info = {"mpeg_version": first["version"], "layer": first["layer"],
            "sample_rate": first["rate"],
            "bitrate": (first["bitrate"] if len(bitrates) == 1 else "VBR"),
            "duration_s": round(samples / first["rate"], 2)}
    return count, p, info


def _trailing_tags(buf, p, limit, checks):
    """Include an APEv2 tag and/or an ID3v1 tag that follow the audio."""
    if bytes(buf[p:p + 8]) == b"APETAGEX" and p + APE_FOOTER <= limit:
        # Tag header first: size counts items + footer, not the header.
        size = struct.unpack_from("<I", buf, p + 12)[0]
        if p + APE_FOOTER + size <= limit:
            p += APE_FOOTER + size
            checks.append("APEv2 tag (with header)")
    else:
        # Header-less APEv2: footer at p + size - 32.
        f = buf.find(b"APETAGEX", p, min(limit, p + APE_SEARCH))
        if f != -1 and f + APE_FOOTER <= limit:
            size = struct.unpack_from("<I", buf, f + 12)[0]
            if f + APE_FOOTER - size == p:
                p = f + APE_FOOTER
                checks.append("APEv2 tag (footer)")
    if bytes(buf[p:p + 3]) == b"TAG" and p + ID3V1_SIZE <= limit:
        p += ID3V1_SIZE
        checks.append("ID3v1 tag")
    return p


def _syncsafe(b):
    if any(x & 0x80 for x in b):
        return None
    v = 0
    for x in b:
        v = (v << 7) | x
    return v


def parse(buf, offset, max_len):
    """Candidate with an ID3v2 header."""
    limit = offset + max_len
    if bytes(buf[offset:offset + 3]) != b"ID3" or offset + 10 > limit:
        return invalid(offset, "no ID3v2 header")
    major, rev, flags = buf[offset + 3], buf[offset + 4], buf[offset + 5]
    size = _syncsafe(bytes(buf[offset + 6:offset + 10]))
    if major not in (2, 3, 4) or rev == 0xFF or size is None:
        return invalid(offset, "invalid ID3v2 version/size")
    tag_end = offset + 10 + size + (10 if (flags & 0x10 and major == 4) else 0)
    if tag_end > limit:
        return invalid(offset, "ID3v2 tag runs past read limit")
    checks = [f"ID3v2.{major} tag, {tag_end - offset} bytes"]

    # First frame: allow padding/junk, but require the next frame to be
    # valid as well so a stray FF Fx in the padding is not taken.
    start = None
    for p in range(tag_end, min(tag_end + FIRST_FRAME_SEARCH, limit - 4)):
        if buf[p] != 0xFF:
            continue
        h = frame_header(buf, p, limit)
        if h and frame_header(buf, p + h["length"], limit):
            start = p
            break
    if start is None:
        frame_id = bytes(buf[offset + 10:offset + 14])
        if frame_id.isalnum() and frame_id.upper() == frame_id:
            return ParseResult(PARTIAL, offset, tag_end, subtype="id3-only",
                               checks=checks + ["no audio frames after tag"])
        return invalid(offset, "no audio frames and no ID3 frames", checks)
    if start != tag_end:
        checks.append(f"{start - tag_end} bytes between tag and first frame")
    count, end, info = _walk_frames(buf, start, limit)
    checks.append(f"{count} consecutive frames")
    end = _trailing_tags(buf, end, limit, checks)
    info["frames"] = count
    status = VALID if count >= MIN_FRAMES_ID3 else PARTIAL
    if status == PARTIAL:
        checks.append(f"fewer than {MIN_FRAMES_ID3} frames")
    return ParseResult(status, offset, end, subtype=f"mpeg{info['mpeg_version']}"
                       f"-layer{info['layer']}", checks=checks, details=info)


def parse_headerless(buf, offset, max_len):
    """Candidate at a raw frame sync (no ID3): strict, VALID or INVALID only."""
    limit = offset + max_len
    count, end, info = _walk_frames(buf, offset, limit)
    if count < MIN_FRAMES_HEADERLESS:
        return invalid(offset, f"only {count} consecutive frames "
                       f"(< {MIN_FRAMES_HEADERLESS})")
    checks = [f"no ID3v2 tag; {count} consecutive consistent frames"]
    end = _trailing_tags(buf, end, limit, checks)
    info["frames"] = count
    return ParseResult(VALID, offset, end, subtype=f"mpeg{info['mpeg_version']}"
                       f"-layer{info['layer']}", checks=checks,
                       notes=["headerless MP3 (frame sync, no ID3 tag)"],
                       details=info)

