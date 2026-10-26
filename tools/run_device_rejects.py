"""Run authenticated negative OTA fixtures and grade actual serial evidence.

No reset or provisioning commands are sent. An open port is held for the entire
run. PASS requires the expected failure gate and an unchanged, idle baseline.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import time
from urllib.parse import urlsplit

import serial


BASELINE_VERSION = "1.0.0"
BASELINE_SLOT = "ota_0"
BASELINE_ADDRESS = 0x20000
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
PHASE = re.compile(r"\bOTA:\s+phase=([A-Z_]+)\s+reason=(.*)$")
FORBIDDEN = re.compile(r"BOOT_SELECTED|READY_TO_BOOT|PENDING")
UNEXPECTED_RESET = re.compile(r"ESP-ROM:|rst:0x|Guru Meditation|panic'ed|Brownout detector|abort\(\)")
GATES = {
    "A01": ({"manifest compatibility before erase"}, "AUTH_MANIFEST", "ESP_ERR_INVALID_ARG", False),
    "A02": ({"manifest integer bound before erase", "manifest integer type before erase",
              "manifest slot bound before erase"}, "AUTH_MANIFEST", "ESP_ERR_INVALID_ARG", False),
    "A03": ({"raw manifest signature before parse"}, "AUTH_MANIFEST", "ESP_ERR_INVALID_CRC", False),
    "A04": ({"SDK native app signature validation", "SDK native app trusted-key mismatch"},
             "VERIFY_IMAGE", "ESP_ERR_OTA_VALIDATE_FAILED", True),
    "A05": ({"VERIFY_FILE full signed-file SHA256 mismatch"}, "VERIFY_FILE", "ESP_ERR_INVALID_CRC", True),
    "A06": ({"file descriptor differs from authenticated manifest"}, "VERIFY_FILE", "ESP_ERR_INVALID_VERSION", True),
    "A07": ({"HTTP length contract before writer"}, "DOWNLOAD", "ESP_ERR_INVALID_RESPONSE", False),
    "A08": ({"manifest schema before erase", "duplicate key before erase", "unknown field before erase"},
             "AUTH_MANIFEST", "ESP_ERR_INVALID_ARG", False),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def validate_index(index: dict, only: list[str]) -> list[dict]:
    if index.get("fixture_release_tag") != "lab-negative-v2":
        raise ValueError("Expected fixture_release_tag=lab-negative-v2; no device commands sent")
    repo = index.get("repo", "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("Index repository is missing or invalid")
    fixtures = index.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        raise ValueError("Index fixtures must be a nonempty list")
    names = set()
    for fixture in fixtures:
        name, test_id = fixture.get("name", ""), fixture.get("test_id")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,100}", name) or name in names:
            raise ValueError("Fixture names must be unique, safe file names")
        names.add(name)
        if test_id not in GATES:
            raise ValueError(f"Unsupported gate mapping: {test_id}")
        gates, _, _, writer = GATES[test_id]
        if fixture.get("expectedgate") not in gates or fixture.get("allow_writer") is not writer:
            raise ValueError(f"Ambiguous expected gate/writer contract: {name}")
        for key, suffix in (("manifest_url", ".json"), ("signature_url", ".sig")):
            url = fixture.get(key, "")
            parsed = urlsplit(url)
            expected = f"/{repo}/releases/download/lab-negative-v2/{name}{suffix}"
            if (parsed.scheme != "https" or parsed.netloc != "github.com" or parsed.path != expected
                    or parsed.query or parsed.fragment or any(ord(c) <= 32 or ord(c) >= 127 for c in url)):
                raise ValueError(f"Unexpected public release URL for {name}/{key}")
    selectors = {part for value in only for part in value.split(",") if part}
    known = names | {fixture["test_id"] for fixture in fixtures}
    if selectors - known:
        raise ValueError(f"Unknown --only selector(s): {', '.join(sorted(selectors - known))}")
    return [f for f in fixtures if not selectors or f["name"] in selectors or f["test_id"] in selectors]


def parse_baseline(lines: list[str]) -> dict:
    observed = {}
    for line in lines:
        status = re.search(r"\bSTATUS version=(\S+).*?selftest=(\S+)(?:\s+service_mode=(\d+))?", line)
        if status:
            observed.update(version=status[1], selftest=status[2])
            if status[3] is not None:
                observed["service_mode"] = int(status[3])
        ota = re.search(r"\bOTA running=(\w+)@(0x[0-9a-fA-F]+) boot=(\w+) next=\w+ state=(\w+)", line)
        if ota:
            observed.update(running_slot=ota[1], running_address=int(ota[2], 16), boot_slot=ota[3], sdk_state=ota[4])
        controller = re.search(r"\bOTA:\s+status ready=(\d+) busy=(\d+) phase=(\S+).*?wifi=(\w+)", line)
        if controller:
            observed.update(controller_ready=int(controller[1]), controller_busy=int(controller[2]),
                            controller_phase=controller[3], wifi=controller[4])
    return observed


def baseline_ok(observed: dict) -> bool:
    expected = {"version": BASELINE_VERSION, "selftest": "PASS", "running_slot": BASELINE_SLOT,
                "running_address": BASELINE_ADDRESS, "boot_slot": BASELINE_SLOT, "sdk_state": "VALID",
                "controller_ready": 1, "controller_busy": 0}
    return all(observed.get(key) == value for key, value in expected.items()) and observed.get("service_mode", 0) == 0


def baseline_complete(observed: dict) -> bool:
    return {"version", "selftest", "running_slot", "running_address", "boot_slot", "sdk_state",
            "controller_ready", "controller_busy"} <= observed.keys()


def assess_fixture(fixture: dict, lines: list[str], before: dict, after: dict) -> dict:
    _, expected_phase, expected_reason, expected_writer = GATES[fixture["test_id"]]
    started = False
    phases = []
    failed_reason = None
    last_phase = None
    for line in lines:
        match = PHASE.search(line)
        if not match:
            continue
        phase, reason = match[1], match[2].strip()
        if phase == "WAIT_NETWORK_TIME":
            started = True
        if not started:
            continue
        phases.append(phase)
        if phase == "FAILED":
            failed_reason = reason
            break
        last_phase = phase
    writer_seen = any("writer_started " in line for line in lines)
    forbidden = [line for line in lines if FORBIDDEN.search(line)]
    unexpected_reset = [line for line in lines if UNEXPECTED_RESET.search(line)]
    metadata_seen = any("accepted_metadata " in line for line in lines)
    header_reject = any("stream_header_reject " in line for line in lines)
    unchanged = baseline_ok(before) and baseline_ok(after)
    checks = {
        "new_session_started": started,
        "actual_FAILED_observed": failed_reason is not None,
        "expected_failure_phase": last_phase == expected_phase,
        "expected_failure_reason": failed_reason == expected_reason,
        "writer_contract": writer_seen == expected_writer,
        "boot_selection_not_observed": not forbidden,
        "unexpected_reset_not_observed": not unexpected_reset,
        "baseline_unchanged_and_idle": unchanged,
    }
    if expected_phase == "AUTH_MANIFEST":
        checks["no_metadata_accept_before_reject"] = not metadata_seen
    elif fixture["test_id"] == "A07":
        checks["actual_HTTP_header_reject"] = header_reject
        checks["metadata_authenticated_first"] = metadata_seen
    else:
        checks["metadata_authenticated_first"] = metadata_seen
        checks["SDK_verify_stage_reached"] = "VERIFY_IMAGE" in phases
    if all(checks.values()):
        verdict, why = "PASS", "Expected rejection gate observed; baseline remains VALID and idle"
    elif (forbidden or unexpected_reset or (not expected_writer and writer_seen)
          or (baseline_complete(after) and not unchanged)):
        verdict, why = "FAIL", "Safety/baseline/writer contract violated; stop further fixtures"
    elif failed_reason is None:
        verdict, why = "BLOCKED", "Expected FAILED response absent within capture window"
    elif last_phase in {"WAIT_NETWORK_TIME", "FETCH_MANIFEST", "WAIT_RETRY_NETWORK"}:
        verdict, why = "BLOCKED", "Transport/time prerequisites failed before the intended rejection gate"
    elif not baseline_complete(after):
        verdict, why = "BLOCKED", "Fresh post-failure baseline/idle response unavailable"
    else:
        verdict, why = "FAIL", "Observed failure does not satisfy the expected gate contract"
    return {"name": fixture["name"], "test_id": fixture["test_id"], "expectedgate": fixture["expectedgate"],
            "result": verdict, "reason": why, "checks": checks, "phases": phases,
            "observed_failure_phase": last_phase, "observed_failure_reason": failed_reason,
            "writer_seen": writer_seen, "forbidden_lines": forbidden,
            "unexpected_reset_lines": unexpected_reset,
            "baseline_before": before, "baseline_after": after}


class Capture:
    def __init__(self, port, redact):
        self.port = port
        self.redact = redact
        self.pending = bytearray()
        self.lines = []
        self.log = None

    def record(self, line: str, device: bool = True):
        line = ANSI.sub("", line).replace("\r", "")
        if device:
            self.lines.append(line)
        safe = self.redact(line)
        if self.log:
            self.log.write(f"{utc_now()} {safe}\n")
            self.log.flush()
        # Emit actual serial output, redacted before leaving this process.
        print(safe, flush=True)

    def send(self, command: str):
        if command.startswith("wifi ") or "\n" in command or "\r" in command:
            raise ValueError("This runner never provisions credentials or accepts multiline commands")
        self.port.write((command + "\n").encode("utf-8"))
        self.port.flush()
        self.record("[HOST] sent: " + command, device=False)

    def pump(self, seconds: float, stop=None):
        until = time.monotonic() + seconds
        begin = len(self.lines)
        while time.monotonic() < until:
            data = self.port.read(min(max(1, self.port.in_waiting), 16384))
            if data:
                self.pending.extend(data)
                while b"\n" in self.pending:
                    raw, _, remainder = self.pending.partition(b"\n")
                    self.pending = bytearray(remainder)
                    self.record(raw.decode("utf-8", errors="replace"))
            if stop and stop(self.lines[begin:]):
                break
        return self.lines[begin:]

    def baseline(self, timeout: float = 10) -> tuple[dict, list[str]]:
        begin = len(self.lines)
        self.send("status")
        self.send("otastatus")
        deadline, next_probe = time.monotonic() + timeout, time.monotonic() + 0.7
        while time.monotonic() < deadline:
            self.pump(0.2)
            observed = parse_baseline(self.lines[begin:])
            if {"version", "running_slot", "sdk_state", "controller_busy"} <= observed.keys():
                if observed["controller_busy"] == 0:
                    return observed, self.lines[begin:]
            if time.monotonic() >= next_probe:
                self.send("otastatus")
                next_probe = time.monotonic() + 0.7
        return parse_baseline(self.lines[begin:]), self.lines[begin:]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--port", default="COM13")
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=90)
    parser.add_argument("--only", nargs="+", default=[], help="Fixture names or test IDs, space/comma separated")
    parser.add_argument("--redact-file", type=Path, default=Path(__file__).resolve().parents[1] / ".secrets" / "wifi.json")
    parser.add_argument("--validate-only", action="store_true", help="Validate index/contracts without opening serial")
    args = parser.parse_args()
    try:
        index_bytes = args.index.read_bytes()
        index = json.loads(index_bytes.decode("utf-8-sig"))
        fixtures = validate_index(index, args.only)
        if not 1 <= args.timeout <= 900:
            raise ValueError("--timeout must be between 1 and 900 seconds per fixture")
        secrets = []
        if args.redact_file.is_file():
            private = json.loads(args.redact_file.read_text(encoding="utf-8-sig"))
            secrets = sorted({private.get("ssid", ""), private.get("password", "")} - {""}, key=len, reverse=True)
    except (OSError, ValueError, TypeError) as error:
        parser.error(str(error))

    def redact(value: str) -> str:
        for secret in secrets:
            value = value.replace(secret, "[REDACTED]")
        return value

    def redact_payload(value):
        if isinstance(value, str):
            return redact(value)
        if isinstance(value, dict):
            return {key: redact_payload(item) for key, item in value.items()}
        if isinstance(value, list):
            return [redact_payload(item) for item in value]
        return value

    if args.validate_only:
        print(json.dumps({"index_valid": True, "selected_count": len(fixtures),
                          "selected": [f["name"] for f in fixtures], "serial_opened": False}, indent=2))
        return 0
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    run_dir = args.evidence_dir / ("run-" + run_id)
    run_dir.mkdir(parents=True, exist_ok=False)
    summary = {"run_id": run_id, "started_utc": utc_now(), "evidence_kind": "ACTUAL_DEVICE_SERIAL",
               "index_sha256": hashlib.sha256(index_bytes).hexdigest(), "repo": index["repo"],
               "fixture_release_tag": index["fixture_release_tag"], "port": args.port, "baud": 115200,
               "reset_method": "NONE; RTS/DTR false before open; no reset command",
               "selected_count": len(fixtures), "results": []}

    def save_summary():
        summary["counts"] = dict(Counter(result["result"] for result in summary["results"]))
        summary["all_selected_passed"] = (len(summary["results"]) == len(fixtures)
                                           and all(r["result"] == "PASS" for r in summary["results"]))
        encoded = json.dumps(redact_payload(summary), ensure_ascii=False, indent=2) + "\n"
        (run_dir / "summary.json").write_text(encoded, encoding="utf-8")
        (args.evidence_dir / "summary.json").write_text(encoded, encoding="utf-8")

    port = serial.Serial(port=None, baudrate=115200, timeout=0.1, write_timeout=3,
                         rtscts=False, dsrdtr=False)
    port.dtr = False
    port.rts = False
    port.port = args.port
    capture = Capture(port, redact)
    abort_reason = None
    try:
        port.open()
        for fixture in fixtures:
            if abort_reason:
                summary["results"].append({"name": fixture["name"], "test_id": fixture["test_id"],
                                           "expectedgate": fixture["expectedgate"], "result": "BLOCKED",
                                           "reason": "Run stopped: " + abort_reason})
                save_summary()
                continue
            logfile = run_dir / (fixture["name"] + ".log")
            with logfile.open("w", encoding="utf-8", newline="\n") as log:
                capture.log = log
                capture.record("[HOST] fixture=" + fixture["name"] + " expectedgate=" + fixture["expectedgate"], False)
                capture.pump(0.35)  # Retain queued output; never discard unread board evidence.
                before, before_lines = capture.baseline()
                if not baseline_ok(before) or before.get("wifi") != "up" or any(FORBIDDEN.search(x) for x in before_lines):
                    result = {"name": fixture["name"], "test_id": fixture["test_id"],
                              "expectedgate": fixture["expectedgate"], "result": "BLOCKED",
                              "reason": "Fresh baseline must be v1.0.0 ota_0 VALID, healthy, idle and Wi-Fi up",
                              "baseline_before": before}
                    abort_reason = result["reason"]
                else:
                    capture.pump(0.25)
                    start = len(capture.lines)
                    capture.send("ota " + fixture["manifest_url"] + " " + fixture["signature_url"])

                    def terminal(lines):
                        if any(FORBIDDEN.search(line) for line in lines):
                            return True
                        fresh = False
                        for line in lines:
                            match = PHASE.search(line)
                            if match and match[1] == "WAIT_NETWORK_TIME":
                                fresh = True
                            if fresh and match and match[1] == "FAILED":
                                return True
                        return False

                    capture.pump(args.timeout, terminal)
                    body = list(capture.lines[start:])
                    if not any((m := PHASE.search(x)) and m[1] == "FAILED" for x in body):
                        if not any(FORBIDDEN.search(x) for x in body):
                            capture.send("cancel")
                            capture.pump(3)
                            body = list(capture.lines[start:])
                    after, after_lines = capture.baseline()
                    result = assess_fixture(fixture, body + after_lines, before, after)
                    if result["result"] == "FAIL" and (not baseline_ok(after) or result["forbidden_lines"]
                                                         or result["unexpected_reset_lines"]
                                                         or (not fixture["allow_writer"] and result["writer_seen"])):
                        abort_reason = result["reason"]
                    elif not baseline_ok(after):
                        abort_reason = "Post-failure baseline/idle could not be established"
                result["log"] = logfile.relative_to(args.evidence_dir).as_posix()
                summary["results"].append(result)
                capture.record("[HOST] fixture_result=" + result["result"] + " name=" + fixture["name"], False)
                save_summary()
                capture.log = None
    except (serial.SerialException, OSError, KeyboardInterrupt) as error:
        summary["run_error"] = redact(str(error) or type(error).__name__)
        completed = {result["name"] for result in summary["results"]}
        for fixture in fixtures:
            if fixture["name"] not in completed:
                summary["results"].append({"name": fixture["name"], "test_id": fixture["test_id"],
                                           "result": "BLOCKED", "reason": "Serial run interrupted; no PASS inferred"})
    finally:
        if port.is_open:
            port.close()
        summary["finished_utc"] = utc_now()
        save_summary()
    print(redact(json.dumps({"summary": str(run_dir / "summary.json"), "counts": summary["counts"],
                             "all_selected_passed": summary["all_selected_passed"]})), flush=True)
    if summary["all_selected_passed"]:
        return 0
    return 1 if summary["counts"].get("FAIL") else 2


if __name__ == "__main__":
    raise SystemExit(main())
