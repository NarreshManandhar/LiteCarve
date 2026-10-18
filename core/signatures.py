"""Header signatures and per-format settings."""

from dataclasses import dataclass

MiB = 1024 * 1024
GiB = 1024 * MiB


@dataclass(frozen=True)
class FormatSpec:
    name: str              # format id, also the parser registry key
    signatures: tuple      # byte strings that mark a candidate
    header_offset: int     # where the signature sits inside the file
    max_size: int          # bytes a parser may read from the start
    extension: str         # extension for exported files
    label: str             # human-readable name


FORMATS = {
    "jpeg": FormatSpec("jpeg", (b"\xFF\xD8\xFF",), 0, 50 * MiB, "jpg", "JPEG"),
    "png": FormatSpec("png", (b"\x89PNG\r\n\x1a\n",), 0, 50 * MiB, "png", "PNG"),
    "gif": FormatSpec("gif", (b"GIF87a", b"GIF89a"), 0, 50 * MiB, "gif", "GIF"),
    "pdf": FormatSpec("pdf", (b"%PDF-",), 0, 200 * MiB, "pdf", "PDF"),
    "zip": FormatSpec("zip", (b"PK\x03\x04",), 0, 200 * MiB, "zip", "ZIP/DOCX"),
    "mp3": FormatSpec("mp3", (b"ID3",), 0, 50 * MiB, "mp3", "MP3"),
    "mp4": FormatSpec("mp4", (b"ftyp",), 4, 1 * GiB, "mp4", "MP4"),
}

# Order used to break ties when two formats claim the same start offset.
FORMAT_ORDER = list(FORMATS)

LONGEST_SIGNATURE = max(len(sig) for f in FORMATS.values()
                        for sig in f.signatures)
