#!/usr/bin/env python3
"""LiteCarve entry point.

    python3 litecarve.py                  # GUI (added in Phase 6)
    python3 litecarve.py --cli --image <path> --output <folder> \\
        --examiner "<name>" --case "<number>" [--org ...] [--examiner-id ...] \\
        [--item ...] [--notes ...] [--export-embedded]

The CLI and the GUI both run ``core.pipeline.Pipeline``, so they produce the
same case folder and reports. Exit codes: 0 success, 2 hash mismatch,
1 any other error (spec Section 15).
"""

import argparse
import os
import sys

# Make "core" importable however the script is started.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import VERSION, TOOL_NAME  # noqa: E402
from core.case import CaseDetails  # noqa: E402
from core import report  # noqa: E402
from core.pipeline import Pipeline, Settings, EXIT_ERROR  # noqa: E402


def build_parser():
    p = argparse.ArgumentParser(
        prog="litecarve.py",
        description=f"{TOOL_NAME} {VERSION} - signature-based file carving "
                    "for NTFS/FAT32 raw images.")
    p.add_argument("--cli", action="store_true",
                   help="run on the command line instead of the GUI")
    p.add_argument("--image", help="raw disk image (.dd/.img/.raw)")
    p.add_argument("--output", help="folder in which the case folder is created")
    p.add_argument("--examiner", help="examiner name (required)")
    p.add_argument("--case", help="case number (required)")
    p.add_argument("--examiner-id", default="")
    p.add_argument("--org", default="", help="organisation")
    p.add_argument("--item", default="", help="evidence item description")
    p.add_argument("--notes", default="")
    p.add_argument("--export-embedded", action="store_true",
                   help="also export embedded objects (default off)")
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {VERSION}")
    return p


class CliPrinter:
    """Prints pipeline events; progress only every 10 % to keep output short."""

    def __init__(self, stream=sys.stdout):
        self.stream = stream
        self._last_pct = {}

    def __call__(self, event):
        kind = event["type"]
        if kind == "log":
            print(event["line"], file=self.stream, flush=True)
        elif kind == "progress":
            total = event["total"]
            if not total:
                return      # unknown total (e.g. metadata walk): no percentage
            pct = int(event["done"] * 100 / total) // 10 * 10
            key = event["step"]
            if pct != self._last_pct.get(key):
                self._last_pct[key] = pct
                print(f"    [{key}] {pct:3d}%", file=self.stream, flush=True)
        elif kind == "step_start":
            self._last_pct.pop(event["step"], None)


def run_cli(args, out=sys.stdout):
    missing = [name for name in ("image", "output", "examiner", "case")
               if not getattr(args, name)]
    if missing:
        print("error: --cli requires " +
              ", ".join("--" + m for m in missing), file=sys.stderr)
        return EXIT_ERROR
    case = CaseDetails(
        examiner_name=args.examiner, case_number=args.case,
        examiner_id=args.examiner_id, organisation=args.org,
        evidence_description=args.item, notes=args.notes)

    def confirm(comparison):
        # The CLI has no dialog: it proceeds automatically and the pipeline
        # logs that the comparison was accepted (spec Section 3 step 6).
        print("Hashes MATCH (MD5 and SHA-256); proceeding automatically.",
              file=out, flush=True)
        return True

    pipeline = Pipeline(case, args.image, args.output,
                        settings=Settings(export_embedded=args.export_embedded),
                        on_event=CliPrinter(out), confirm_hashes=confirm)
    result = pipeline.run()
    print(file=out)
    print("=" * 70, file=out)
    print(f"Status    : {result.status.upper()}", file=out)
    print(f"Message   : {result.message}", file=out)
    if result.case_dir:
        print(f"Case dir  : {result.case_dir}", file=out)
    rec = result.record
    for key, label in (("evidence_vs_copy", "Evidence vs working copy"),
                       ("evidence_initial_vs_final", "Evidence initial vs final"),
                       ("copy_initial_vs_final", "Copy initial vs final")):
        cmp = rec["hash_comparisons"].get(key)
        if cmp:
            print(f"{label:<26}: MD5 {cmp['md5']}, SHA-256 {cmp['sha256']}",
                  file=out)
    summ = rec.get("summary")
    if summ:
        rf, eo = summ["recovered_files"], summ["embedded_objects"]
        print(f"Summary   : {report.headline(summ)}", file=out)
        print("  complete: " + (", ".join(f"{k} {v}" for k, v in
                                          rf["complete_by_separation"].items())
                                or "none")
              + "   partial: " + (", ".join(f"{k} {v}" for k, v in
                                            rf["partial_by_separation"].items())
                                  or "none"), file=out)
        print(f"Embedded  : {eo['total']} object(s) inside recovered files "
              f"(not counted as files)", file=out)
    if rec.get("run_wall_seconds") is not None:
        print(f"Time      : processing {rec['run_processing_seconds']:.2f} s, "
              f"waiting for examiner {rec['examiner_wait_seconds']:.2f} s, "
              f"wall {rec['run_wall_seconds']:.2f} s", file=out)
    if result.case_dir:
        print(f"Report    : {os.path.join(result.case_dir, 'reports', 'report.html')}",
              file=out)
    print(f"Exit code : {result.exit_code}", file=out)
    return result.exit_code


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.cli:
        return run_cli(args)
    # Imported only here so the CLI works on machines without a display.
    from gui.app import main as gui_main
    return gui_main()


if __name__ == "__main__":
    sys.exit(main())
