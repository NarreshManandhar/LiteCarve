"""The LiteCarve workflow, shared by the CLI and the GUI."""

import os
import platform
import sys
import threading
import time
from dataclasses import dataclass

import mmap

from core import (VERSION, TOOL_NAME, evidence, hashing, volume, fsmeta,
                  carver, correlate, exporter, report)
from core.report import RunLog, now_local_iso, LIMITATIONS

# (id, label) in workflow order; used by the GUI stage list later.
STEPS = [
    ("hash_evidence", "Verify and hash evidence"),
    ("disk_space", "Disk-space check"),
    ("working_copy", "Create working copy"),
    ("compare_hashes", "Compare hashes"),
    ("read_only", "Set read-only"),
    ("detect_volume", "Detect partition and file system"),
    ("metadata_scan", "Metadata scan and TXT recovery"),
    ("carve", "Carving scan"),
    ("correlate", "Correlate carved files with metadata"),
    ("export", "Export recovered files"),
    ("rehash", "Re-hash evidence and working copy"),
    ("reports", "Generate reports"),
]
STEP_LABELS = dict(STEPS)

# Exit codes (spec Section 15).
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_HASH_MISMATCH = 2


class Cancelled(Exception):
    pass


class HashMismatch(Exception):
    pass


class Aborted(Exception):
    """The examiner chose not to proceed after seeing the hash comparison."""


@dataclass
class Settings:
    export_embedded: bool = False


@dataclass
class PipelineResult:
    status: str            # completed | hash_mismatch | cancelled | aborted | error
    exit_code: int
    case_dir: str = ""
    message: str = ""
    record: dict = None


def environment_info():
    try:
        import pytsk3
        tsk = pytsk3.TSK_VERSION_STR
        pytsk3_ver = str(pytsk3.get_version())
    except Exception as exc:  # recorded, not fatal in steps 3-7
        tsk = pytsk3_ver = f"unavailable ({exc})"
    return {
        "tool": TOOL_NAME,
        "tool_version": VERSION,
        "python": sys.version.split()[0],
        "pytsk3": pytsk3_ver,
        "sleuthkit": tsk,
        "os": platform.platform(),
        "hostname": platform.node(),
    }


class Pipeline:
    def __init__(self, case, image_path, output_dir, settings=None,
                 on_event=None, confirm_hashes=None, cancel_event=None,
                 stop_after=None):
        # stop_after: optional step id after which the run ends successfully
        # (used by the unit tests, whose tiny synthetic images contain no
        # file system, to exercise steps 3-7 on their own).
        self.stop_after = stop_after
        self.case = case
        self.image_path = os.path.abspath(image_path)
        self.output_dir = os.path.abspath(output_dir)
        self.settings = settings or Settings()
        self._on_event = on_event or (lambda e: None)
        self._confirm = confirm_hashes or (lambda comparison: True)
        self.cancel_event = cancel_event or threading.Event()
        self.log = RunLog(echo=self._echo_log)
        self.case_dir = ""
        self.record = {
            "status": "running",
            "environment": environment_info(),
            "case": case.to_dict(),
            "settings": {"export_embedded": self.settings.export_embedded},
            "evidence": None,
            "working_copy": None,
            "hash_comparisons": {},
            "read_only_actions": [],
            "volume": None,
            "metadata_summary": None,
            # The full listing is written to reports/metadata_listing.json
            # (decision C-8); report.json carries a reference and its hash.
            "metadata_listing_file": None,
            "results": [],
            "timings": {},
            "notes": [evidence.CTIME_STATEMENT],
            "limitations": list(LIMITATIONS),
            "carving": None,
            "correlation": None,
        }
        self.final_mismatch = False
        # Time spent waiting for the examiner (hash dialog) is not processing
        # time: it is measured separately and excluded from step and run
        # durations (decision C-12).
        self._step_wait = 0.0
        self.examiner_wait_total = 0.0
        self.metadata_listing = None     # list of dicts once step 9 has run

    # ----- event helpers -------------------------------------------------

    def _emit(self, **event):
        self._on_event(event)

    def _echo_log(self, level, line):
        self._emit(type="log", level=level, line=line)

    def _progress(self, step):
        def cb(done, total):
            self._emit(type="progress", step=step, done=done, total=total)
        return cb

    def _cancelled(self):
        return self.cancel_event.is_set()

    def _check_cancel(self):
        if self._cancelled():
            raise Cancelled()

    def _run_step(self, step_id, func):
        """Run one step with timing and start/done/failed events."""
        self._check_cancel()
        label = STEP_LABELS[step_id]
        self._emit(type="step_start", step=step_id, label=label)
        self.log.log(step_id, f"START {label}")
        start_iso, t0 = now_local_iso(), time.perf_counter()
        self._step_wait = 0.0
        try:
            result = func()
        except BaseException:
            self._record_timing(step_id, start_iso, t0, ok=False)
            self._emit(type="step_failed", step=step_id, label=label)
            raise
        secs = self._record_timing(step_id, start_iso, t0, ok=True)
        wait = (f", {self._step_wait:.3f} s waiting for the examiner"
                if self._step_wait else "")
        self.log.log(step_id, f"DONE {label} ({secs:.3f} s processing{wait})")
        self._emit(type="step_done", step=step_id, label=label, seconds=secs,
                   examiner_wait=self._step_wait)
        return result

    def _record_timing(self, step_id, start_iso, t0, ok):
        """Record a step's processing time (wall time minus examiner wait)."""
        wall = time.perf_counter() - t0
        secs = max(0.0, wall - self._step_wait)
        self.record["timings"][step_id] = {
            "start": start_iso, "end": now_local_iso(),
            "seconds": round(secs, 6),
            "examiner_wait_seconds": round(self._step_wait, 6),
            "wall_seconds": round(wall, 6), "ok": ok,
        }
        return secs

    # ----- the workflow --------------------------------------------------

    def run(self):
        run_start_iso, t0 = now_local_iso(), time.perf_counter()
        self.record["run_start"] = run_start_iso
        self.log.log("start", f"{TOOL_NAME} {VERSION} run started")
        for k, v in self.record["environment"].items():
            self.log.log("environment", f"{k}={v}")
        for k, v in self.case.to_dict().items():
            self.log.log("case", f"{k}={v!r}")
        try:
            problems = self.case.validate()
            if problems:
                raise evidence.EvidenceError("; ".join(problems))
            done = []
            for step_id, _ in STEPS:
                self._run_step(step_id, getattr(self, "_step_" + step_id))
                done.append(step_id)
                if step_id == self.stop_after:
                    break
            if self.final_mismatch:
                status, code = "final_hash_mismatch", EXIT_HASH_MISMATCH
                msg = ("FINAL HASH MISMATCH: evidence or working copy changed "
                       "during the run.")
            else:
                status, code = "completed", EXIT_OK
                msg = f"Completed steps: {', '.join(done)}."
        except HashMismatch as exc:
            status, code, msg = "hash_mismatch", EXIT_HASH_MISMATCH, str(exc)
            self.log.log("compare_hashes", msg, level="ERROR")
        except (Cancelled, hashing.HashCancelled, evidence.CopyCancelled,
                InterruptedError, carver.CarveCancelled):
            status, code, msg = "cancelled", EXIT_ERROR, "Run cancelled by user."
            self.log.log("cancel", msg, level="WARNING")
        except Aborted as exc:
            status, code, msg = "aborted", EXIT_ERROR, str(exc)
            self.log.log("compare_hashes", msg, level="WARNING")
        except (evidence.EvidenceError, volume.VolumeError, OSError) as exc:
            status, code, msg = "error", EXIT_ERROR, str(exc)
            self.log.log("error", msg, level="ERROR")
        except Exception as exc:  # never let an unexpected error lose the log
            status, code = "error", EXIT_ERROR
            msg = f"Unexpected error: {type(exc).__name__}: {exc}"
            self.log.log("error", msg, level="ERROR")

        wall = time.perf_counter() - t0
        processing = max(0.0, wall - self.examiner_wait_total)
        self.record.update(status=status, message=msg, run_end=now_local_iso(),
                           run_seconds=round(processing, 6),
                           run_processing_seconds=round(processing, 6),
                           examiner_wait_seconds=round(self.examiner_wait_total, 6),
                           run_wall_seconds=round(wall, 6))
        self.log.log("end", f"status={status} exit_code={code} "
                            f"processing={processing:.3f} s "
                            f"examiner_wait={self.examiner_wait_total:.3f} s "
                            f"wall={wall:.3f} s")
        self._write_reports()
        self._emit(type="finished", status=status, exit_code=code,
                   message=msg, case_dir=self.case_dir,
                   processing_seconds=processing,
                   examiner_wait_seconds=self.examiner_wait_total,
                   wall_seconds=wall)
        return PipelineResult(status=status, exit_code=code,
                              case_dir=self.case_dir, message=msg,
                              record=self.record)

    def _write_reports(self, final=True):
        """Write report.json/.csv/.html (the "report so far" on early stops).

        Called by step 14 and again when the run ends, so the final status
        and the timing of every step, including step 14, are in the reports.
        After the final write the reports' own hashes go into the run log,
        so later changes to a report can be detected.
        """
        # Without a case folder (failure in steps 3-4) there is nowhere to
        # write; the events/console still carry the log.
        if not self.case_dir:
            return
        paths = report.write_all(os.path.join(self.case_dir, "reports"),
                                 self.record, self.metadata_listing)
        for path in paths:
            if final:
                h = hashing.hash_file(path)
                self.log.log("report", f"{os.path.basename(path)} written: "
                                       f"MD5={h.md5} SHA-256={h.sha256}")
            else:
                self.log.log("report", f"{os.path.basename(path)} written")

    # Step 3
    def _step_hash_evidence(self):
        self.log.log("hash_evidence", f"Opening read-only: {self.image_path}")
        info = evidence.inspect_evidence(
            self.image_path, progress=self._progress("hash_evidence"),
            cancel=self._cancelled)
        self.evidence_info = info
        self.record["evidence"] = {"initial": info.to_dict()}
        self.log.log("hash_evidence",
                     f"size={info.size} mtime_utc={info.mtime_utc} "
                     f"mode={info.mode_octal}")
        self.log.log("hash_evidence", f"MD5={info.hashes.md5}")
        self.log.log("hash_evidence", f"SHA-256={info.hashes.sha256}")

    # Step 4
    def _step_disk_space(self):
        if not os.path.isdir(self.output_dir):
            os.makedirs(self.output_dir)
            self.log.log("disk_space", f"Created output folder {self.output_dir}")
        free, required = evidence.check_disk_space(self.output_dir,
                                                   self.evidence_info.size)
        self.log.log("disk_space", f"free={free:,} required={required:,} OK")

    # Step 5
    def _step_working_copy(self):
        self.case_dir = evidence.create_case_folder(self.output_dir, self.case)
        self.log.attach(os.path.join(self.case_dir, "reports", "run_log.txt"))
        exporter.case_layout(self.case_dir, self.settings.export_embedded)
        self.record["case_dir"] = self.case_dir
        self.log.log("working_copy", f"Case folder: {self.case_dir}")
        dest = evidence.copy_evidence(
            self.image_path, os.path.join(self.case_dir, "evidence_copy"),
            progress=self._progress("working_copy"), cancel=self._cancelled)
        self.working_copy = dest
        self.log.log("working_copy", f"Copied to {dest}; hashing copy")
        hashes = hashing.hash_file(dest, progress=self._progress("working_copy"),
                                   cancel=self._cancelled)
        self.copy_hashes = hashes
        self.record["working_copy"] = {"path": dest, "initial": hashes.to_dict()}
        self.log.log("working_copy", f"MD5={hashes.md5}")
        self.log.log("working_copy", f"SHA-256={hashes.sha256}")

    # Step 6
    def _step_compare_hashes(self):
        cmp = hashing.compare(self.evidence_info.hashes, self.copy_hashes)
        self.record["hash_comparisons"]["evidence_vs_copy"] = cmp
        self.log.log("compare_hashes",
                     f"evidence vs copy: MD5 {cmp['md5']}, SHA-256 "
                     f"{cmp['sha256']}, size {cmp['size']}",
                     level="INFO" if cmp["match"] else "ERROR")
        self._emit(type="hash_comparison", comparison=cmp)
        if not cmp["match"]:
            raise HashMismatch("Working copy does not match the evidence; "
                               "analysis stopped.")
        t_wait = time.perf_counter()
        try:
            proceed = self._confirm(cmp)
        finally:
            waited = time.perf_counter() - t_wait
            self._step_wait += waited
            self.examiner_wait_total += waited
            self.log.log("compare_hashes", f"Examiner decision after "
                                           f"{waited:.3f} s")
        if not proceed:
            raise Aborted("Examiner chose not to proceed after hash comparison.")
        self.log.log("compare_hashes", "Examiner confirmed: proceed")

    # Step 7
    def _step_read_only(self):
        self.log.log("read_only", evidence.CTIME_STATEMENT)
        for path in (self.working_copy, self.image_path):
            action = evidence.make_read_only(path)
            self.record["read_only_actions"].append(action.to_dict())
            if action.warning:
                self.log.log("read_only", f"{path}: previous={action.previous_mode} "
                             f"WARNING {action.warning}; continuing",
                             level="WARNING")
            else:
                self.log.log("read_only",
                             f"{path}: previous={action.previous_mode} "
                             f"changed={'yes' if action.changed else 'no'} "
                             f"new={action.new_mode}")
        self.log.log("read_only", "All further analysis uses the working copy only")

    # Step 8
    def _step_detect_volume(self):
        info, self._img, self._fs = volume.open_filesystem(
            self.working_copy,
            log=lambda m: self.log.log("detect_volume", m))
        self.volume_info = info
        self.record["volume"] = info.to_dict()
        self.log.log("detect_volume",
                     f"table={info.partition_table} method={info.detection_method} "
                     f"mbr_entry={info.mbr_entry} (TSK slot {info.tsk_slot}) "
                     f"start_sector={info.start_sector} "
                     f"sector_size={info.sector_size} offset={info.offset_bytes} "
                     f"size={info.size_bytes}")
        self.log.log("detect_volume",
                     f"fs={info.fs_type} boot_signature={info.boot_signature} "
                     f"consistent={info.boot_signature_consistent} "
                     f"block_size={info.block_size} cluster_size={info.cluster_size} "
                     f"label={info.volume_label!r}")
        if not info.boot_signature_consistent:
            self.log.log("detect_volume", "Boot-sector string does not match "
                         "TSK's file-system type", level="WARNING")

    # Step 9
    def _step_metadata_scan(self):
        scan = fsmeta.scan(
            self._fs, self.volume_info, cancel=self._cancelled,
            progress=self._progress("metadata_scan"),
            log=lambda m, level="INFO": self.log.log("metadata_scan", m, level))
        self.meta_scan = scan
        self.record["metadata_summary"] = scan.summary
        self.metadata_listing = [r.to_dict() for r in scan.records]
        self.record["metadata_errors"] = scan.errors
        s = scan.summary
        self.log.log("metadata_scan",
                     f"entries_seen={s['entries_seen']} listed={s['listed']} "
                     f"files={s['files']} deleted={s['files_deleted']} "
                     f"allocated={s['files_allocated']} dirs={s['directories']}")
        self.log.log("metadata_scan", f"excluded from listing: {s['excluded']}")
        self.log.log("metadata_scan", f"per extension: {s['per_extension']}")
        if self.volume_info.fs_type == "FAT32":
            self.log.log("metadata_scan", "FAT timestamps are stored as local "
                         "time with no time zone")
        for r in scan.records:
            self._check_cancel()
            if not fsmeta.is_txt(r):
                continue
            res = fsmeta.recover_txt(self._fs, r, self.case_dir)
            res["id"] = f"M{len(self.record['results']) + 1:04d}"
            self.record["results"].append(res)
            self.log.log("metadata_scan",
                         f"TXT {res['id']} {r.path} [{r.separation}] "
                         f"{res['status']} {res['length']}/{r.size} bytes "
                         f"MD5={res['md5']} SHA-256={res['sha256']} "
                         f"-> {res['export_path']}",
                         level="INFO" if res["status"] == "RECOVERED" else "WARNING")

    # Step 10
    def _step_carve(self):
        settings = carver.CarveSettings()
        self.record["settings"]["formats"] = list(settings.formats)
        self.record["settings"]["max_sizes"] = settings.max_sizes
        scan = carver.carve(
            self.working_copy, settings, progress=self._progress("carve"),
            cancel=self._cancelled,
            log=lambda m, level="INFO": self.log.log("carve", m, level))
        self.carve_scan = scan
        self.record["carving"] = {
            "header_hits": scan.candidates,
            "status_counts": scan.status_counts,
            "invalid": scan.invalid,
            "embedded": scan.embedded,
            "embedded_nonvalid_counted": scan.embedded_nonvalid,
            "headerless_mp3": scan.headerless,
        }
        n = 0
        for res in scan.results:
            n += 1
            res["id"] = f"C{n:04d}"
            self.record["results"].append(res)
            parent = (f" parent@{res['parent_offset']}"
                      if res["parent_offset"] is not None else "")
            self.log.log("carve",
                         f"{res['id']} {res['type']} {res['status']}{parent} "
                         f"offset={res['offset']} length={res['length']} "
                         f"MD5={res['md5']} SHA-256={res['sha256']}")
        self.log.log("carve", f"INVALID candidates (not exported): "
                              f"{sum(scan.invalid.values())} {scan.invalid}")

    # Step 11
    def _step_correlate(self):
        carved = [r for r in self.record["results"] if r["method"] == "carved"]
        txt_paths = {r["original_path"] for r in self.record["results"]
                     if r["method"] == "metadata"}
        summary = correlate.correlate(
            carved, self.meta_scan.records, self.volume_info.fs_type,
            log=lambda m, level="INFO": self.log.log("correlate", m, level),
            metadata_recovered=txt_paths)
        self.record["correlation"] = summary
        for r in carved:
            self.log.log("correlate",
                         f"{r['id']} {r['type']} @{r['offset']} -> "
                         f"{r['separation']}"
                         + (f" {r['original_path']} fs_size={r['fs_size']} "
                            f"size_consistent={r['size_consistent']}"
                            if r.get("attributed") else ""))
        self.log.log("correlate",
                     f"Deleted={summary['attributed_deleted']} "
                     f"Non-deleted={summary['attributed_non_deleted']} "
                     f"Unattributed={summary['unattributed']} "
                     f"Embedded={summary['embedded']} "
                     f"fs files without carve="
                     f"{len(summary['fs_files_without_carve'])}")

    # Step 12
    def _step_export(self):
        """Export carved results (TXT files were exported in step 9)."""
        export_embedded = self.settings.export_embedded
        exported = skipped = mismatches = 0
        with open(self.working_copy, "rb") as f, \
                mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as buf:
            for r in self.record["results"]:
                self._check_cancel()
                if r["method"] != "carved":
                    continue
                if r["status"] == "EMBEDDED" and not export_embedded:
                    r["export_path"] = ""
                    r.setdefault("notes", []).append(
                        "embedded object: not exported (setting off); hashes "
                        "are of the carved byte range")
                    skipped += 1
                    continue
                res = exporter.export_carved(buf, r, self.case_dir)
                same = (res.hashes.sha256 == r["sha256"]
                        and res.hashes.md5 == r["md5"]
                        and res.bytes_written == r["length"])
                r["export_path"] = res.path
                r["export_hash_match"] = same
                r["md5"], r["sha256"] = res.hashes.md5, res.hashes.sha256
                exported += 1
                if not same or res.error:
                    mismatches += 1
                    self.log.log("export", f"{r['id']}: exported file does not "
                                 f"match the carved range ({res.error})",
                                 level="ERROR")
                self.log.log("export", f"{r['id']} -> {res.path} "
                             f"MD5={res.hashes.md5} SHA-256={res.hashes.sha256}")
        self.log.log("export", f"exported={exported} embedded_not_exported="
                               f"{skipped} hash_mismatches={mismatches}")

    # Step 13
    def _step_rehash(self):
        ev = evidence.reverify(self.image_path, self.evidence_info.hashes,
                               progress=self._progress("rehash"),
                               cancel=self._cancelled)
        wc = evidence.reverify(self.working_copy, self.copy_hashes,
                               progress=self._progress("rehash"),
                               cancel=self._cancelled)
        self.record["evidence"]["final"] = ev["actual"]
        self.record["working_copy"]["final"] = wc["actual"]
        self.record["hash_comparisons"]["evidence_initial_vs_final"] = ev
        self.record["hash_comparisons"]["copy_initial_vs_final"] = wc
        for label, cmp in (("evidence", ev), ("working copy", wc)):
            level = "INFO" if cmp["match"] else "ERROR"
            self.log.log("rehash", f"{label} final MD5={cmp['actual']['md5']} "
                         f"SHA-256={cmp['actual']['sha256']}")
            self.log.log("rehash", f"{label} initial vs final: MD5 {cmp['md5']}, "
                         f"SHA-256 {cmp['sha256']}, size {cmp['size']}", level)
        if not (ev["match"] and wc["match"]):
            self.final_mismatch = True
            self.log.log("rehash", "FINAL HASH MISMATCH", level="ERROR")
        else:
            self.log.log("rehash", "Evidence and working copy unchanged: MATCH")

    # Step 14
    def _step_reports(self):
        self._write_reports(final=False)
