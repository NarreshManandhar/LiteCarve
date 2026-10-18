#Format parsers: the common result type and the registry.

from dataclasses import dataclass, field

VALID = "VALID"
PARTIAL = "PARTIAL"
INVALID = "INVALID"


@dataclass
class ParseResult:
    status: str
    start: int
    end: int                         # exclusive
    subtype: str = ""
    checks: list = field(default_factory=list)   # what passed / failed
    notes: list = field(default_factory=list)
    details: dict = field(default_factory=dict)  # width, height, version, ...

    @property
    def length(self):
        return max(0, self.end - self.start)


def invalid(offset, reason, checks=None):
    """Shorthand for an INVALID result with its reason as the last check."""
    return ParseResult(INVALID, offset, offset, checks=(checks or []) + [reason])


# Registry (imports placed after ParseResult so the modules can import it).
from core.parsers import jpeg, png, gif, pdf, zipooxml, mp3, mp4  # noqa: E402

PARSERS = {
    "jpeg": jpeg.parse,
    "png": png.parse,
    "gif": gif.parse,
    "pdf": pdf.parse,
    "zip": zipooxml.parse,
    "mp3": mp3.parse,
    "mp4": mp4.parse,
}
