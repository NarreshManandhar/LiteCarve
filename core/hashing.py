"""MD5 + SHA-256 hashing in a single pass."""

import hashlib
import os
from dataclasses import dataclass, asdict

CHUNK_SIZE = 1024 * 1024  # 1 MiB, spec Section 3 step 3


@dataclass(frozen=True)
class HashResult:
    """Digests of one byte stream, plus the number of bytes actually hashed.

    ``size`` is kept because a hash is only meaningful together with the
    length it covers; a short read would otherwise go unnoticed.
    """

    md5: str
    sha256: str
    size: int

    def to_dict(self):
        return asdict(self)


class HashCancelled(Exception):
    """Raised when the caller's cancel check asks hashing to stop."""


def hash_file(path, progress=None, cancel=None, chunk_size=CHUNK_SIZE):
    """Hash a file read-only in chunks.

    progress: optional callable(bytes_done, total_bytes), called after each chunk.
    cancel:   optional callable() -> bool; if it returns True, HashCancelled is raised.
    """
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    total = os.path.getsize(path)
    done = 0
    # "rb" only: the evidence must never be opened in a writable mode.
    with open(path, "rb") as f:
        while True:
            if cancel is not None and cancel():
                raise HashCancelled(path)
            chunk = f.read(chunk_size)
            if not chunk:
                break
            md5.update(chunk)
            sha256.update(chunk)
            done += len(chunk)
            if progress is not None:
                progress(done, total)
    return HashResult(md5=md5.hexdigest(), sha256=sha256.hexdigest(), size=done)


def hash_bytes(data):
    """Hash an in-memory byte string (used for carved and recovered files)."""
    return HashResult(
        md5=hashlib.md5(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
    )


def hash_range(buf, start, end, chunk_size=CHUNK_SIZE):
    """Hash buf[start:end] (e.g. an mmap of the image) without copying it all.

    Used for carved files: the hash is computed over exactly the bytes the
    carver accepted, in 1 MiB slices so a 1 GiB MP4 does not need 1 GiB RAM.
    """
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    view = memoryview(buf)
    try:
        for pos in range(start, end, chunk_size):
            piece = view[pos:min(pos + chunk_size, end)]
            md5.update(piece)
            sha256.update(piece)
            piece.release()
    finally:
        view.release()
    return HashResult(md5=md5.hexdigest(), sha256=sha256.hexdigest(),
                      size=max(0, end - start))


def compare(expected, actual):
    """Compare two HashResults field by field.

    Returns a dict with MATCH/MISMATCH per algorithm and an overall boolean.
    Size is compared too: two different lengths can never be the same file,
    and reporting it separately makes a truncated copy obvious.
    """
    md5_ok = expected.md5 == actual.md5
    sha_ok = expected.sha256 == actual.sha256
    size_ok = expected.size == actual.size
    return {
        "md5": "MATCH" if md5_ok else "MISMATCH",
        "sha256": "MATCH" if sha_ok else "MISMATCH",
        "size": "MATCH" if size_ok else "MISMATCH",
        "match": md5_ok and sha_ok and size_ok,
        "expected": expected.to_dict(),
        "actual": actual.to_dict(),
    }
