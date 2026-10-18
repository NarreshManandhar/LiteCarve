"""Evidence handling: hashing, disk-space check, working copy, read-only, re-verification."""

import os
import shutil
import stat
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone

from core import hashing

COPY_CHUNK_SIZE = hashing.CHUNK_SIZE
SPACE_MARGIN = 0.10  # spec Section 3 step 4: image size + 10 %

# Text that must appear in the log and report wherever permissions are
# discussed (spec Section 3 step 7, review decision 2).
CTIME_STATEMENT = (
    "A permission change (chmod) updates the file's ctime, which is a "
    "metadata change on the examiner's machine. It does not alter the file's "
    "content or its hash."
)


class EvidenceError(Exception):
    """A problem that must stop the run (missing file, no space, ...)."""


class CopyCancelled(Exception):
    pass


def iso_utc(epoch):
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


@dataclass
class EvidenceInfo:
    path: str
    size: int
    mtime_epoch: float
    mtime_utc: str
    mode_octal: str
    hashes: hashing.HashResult

    def to_dict(self):
        d = asdict(self)
        d["hashes"] = self.hashes.to_dict()
        return d


@dataclass
class ReadOnlyAction:
    """What happened when step 7 tried to make one file read-only."""

    path: str
    previous_mode: str
    changed: bool
    new_mode: str
    warning: str = ""
    note: str = field(default=CTIME_STATEMENT)

    def to_dict(self):
        return asdict(self)


def _mode_str(st_mode):
    return oct(stat.S_IMODE(st_mode))


def inspect_evidence(path, progress=None, cancel=None):
    """Step 3: check the evidence is a regular file, then hash it read-only."""
    path = os.path.abspath(path)
    if not os.path.exists(path):
        raise EvidenceError(f"Evidence file not found: {path}")
    # os.stat follows symlinks; we record the real file's properties.
    st = os.stat(path)
    if not stat.S_ISREG(st.st_mode):
        # Block devices are out of scope (no acquisition from /dev/sdX).
        raise EvidenceError(f"Evidence is not a regular file: {path}")
    if st.st_size == 0:
        raise EvidenceError(f"Evidence file is empty: {path}")
    hashes = hashing.hash_file(path, progress=progress, cancel=cancel)
    if hashes.size != st.st_size:
        # The file changed size while we read it: not a stable evidence item.
        raise EvidenceError(
            f"Read {hashes.size} bytes but file size is {st.st_size}: "
            "evidence changed during hashing")
    return EvidenceInfo(
        path=path,
        size=st.st_size,
        mtime_epoch=st.st_mtime,
        mtime_utc=iso_utc(st.st_mtime),
        mode_octal=_mode_str(st.st_mode),
        hashes=hashes,
    )


def check_disk_space(output_dir, image_size):
    """Step 4: require image size + 10 % free in the output folder.

    Returns (free_bytes, required_bytes). Raises EvidenceError if short.
    Only the working copy is budgeted here; exported files are usually much
    smaller than the image and their total is unknown before carving.
    """
    free = shutil.disk_usage(output_dir).free
    required = int(image_size * (1 + SPACE_MARGIN))
    if free < required:
        raise EvidenceError(
            f"Not enough free space in {output_dir}: {free:,} bytes free, "
            f"{required:,} bytes required (image size + 10%).")
    return free, required


def create_case_folder(output_dir, case, now=None):
    """Step 5a: create <output>/<CASE>_<YYYYMMDD-HHMMSS>/ without overwriting."""
    now = now or datetime.now()
    base = f"{case.folder_token()}_{now.strftime('%Y%m%d-%H%M%S')}"
    candidate = os.path.join(output_dir, base)
    counter = 1
    while True:
        try:
            # mkdir (not makedirs with exist_ok) fails if it exists, so an
            # earlier case folder can never be reused or overwritten.
            os.mkdir(candidate)
            return candidate
        except FileExistsError:
            counter += 1
            candidate = os.path.join(output_dir, f"{base}_{counter}")


def copy_evidence(src, dest_dir, progress=None, cancel=None):
    """Step 5b: chunked copy of the evidence into dest_dir.

    The destination is opened with "xb" (exclusive create) so an existing file
    is never overwritten, and fsync'd so the later hash is of data on disk.
    """
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, os.path.basename(src))
    total = os.path.getsize(src)
    done = 0
    try:
        with open(src, "rb") as fin, open(dest, "xb") as fout:
            while True:
                if cancel is not None and cancel():
                    raise CopyCancelled(dest)
                chunk = fin.read(COPY_CHUNK_SIZE)
                if not chunk:
                    break
                fout.write(chunk)
                done += len(chunk)
                if progress is not None:
                    progress(done, total)
            fout.flush()
            os.fsync(fout.fileno())
    except CopyCancelled:
        # A half-written copy must not be mistaken for a working copy later.
        os.remove(dest)
        raise
    return dest


def is_read_only(st_mode):
    """True when no write bit is set for owner, group or others (decision I-1)."""
    return (stat.S_IMODE(st_mode) & 0o222) == 0


def make_read_only(path):
    """Step 7: set 0o444 only if the file is still writable by anyone.

    A failed chmod (e.g. the examiner does not own the original evidence) is
    a warning, not a fatal error: the hashes still protect integrity, and the
    analysis only uses the working copy.
    """
    st = os.stat(path)
    previous = _mode_str(st.st_mode)
    if is_read_only(st.st_mode):
        return ReadOnlyAction(path=path, previous_mode=previous,
                              changed=False, new_mode=previous)
    try:
        os.chmod(path, 0o444)
    except OSError as exc:
        return ReadOnlyAction(path=path, previous_mode=previous, changed=False,
                              new_mode=previous,
                              warning=f"chmod 0o444 failed: {exc}")
    new = _mode_str(os.stat(path).st_mode)
    return ReadOnlyAction(path=path, previous_mode=previous, changed=True,
                          new_mode=new)


def reverify(path, expected, progress=None, cancel=None):
    """Step 13: hash a file again and compare with an earlier HashResult."""
    actual = hashing.hash_file(path, progress=progress, cancel=cancel)
    return hashing.compare(expected, actual)
