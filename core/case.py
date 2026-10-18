"""Case and examiner details."""

import re
from dataclasses import dataclass, asdict

# Characters allowed in the case-folder name. Anything else (e.g. "/" in
# "2026/014") is replaced so the case number cannot create sub-folders or an
# invalid path. The *unsanitised* case number is still used in all reports.
_UNSAFE_FOLDER_CHARS = re.compile(r"[^A-Za-z0-9._-]")


@dataclass
class CaseDetails:
    examiner_name: str
    case_number: str
    examiner_id: str = ""
    organisation: str = ""
    evidence_description: str = ""
    notes: str = ""

    def __post_init__(self):
        # Strip surrounding whitespace so "  " does not pass as a name.
        for name in ("examiner_name", "case_number", "examiner_id",
                     "organisation", "evidence_description", "notes"):
            value = getattr(self, name)
            setattr(self, name, (value or "").strip())

    def validate(self):
        """Return a list of human-readable problems; empty means valid."""
        problems = []
        if not self.examiner_name:
            problems.append("Examiner name is required.")
        if not self.case_number:
            problems.append("Case number is required.")
        # Control characters would corrupt the one-line-per-action run log.
        for name, value in asdict(self).items():
            if name != "notes" and any(ord(c) < 0x20 for c in value):
                problems.append(f"{name} contains control characters.")
        return problems

    def folder_token(self):
        """Case number made safe for use in a folder name."""
        token = _UNSAFE_FOLDER_CHARS.sub("_", self.case_number).strip("._")
        return token or "CASE"

    def to_dict(self):
        return asdict(self)
