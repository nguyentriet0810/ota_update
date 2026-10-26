"""Capture actual v5 fault-profile DNS/TLS/HTTP failures without resetting it.

Start the isolated fault server separately. This tool only calls its fixed
localhost control API; it never creates a listener or provisions credentials.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
import time
from urllib.request import Request, ProxyHandler, build_opener

import serial


BASE = "https://192.168.137.1:8443/releases/download/lab-fault-v6/"
CONTROL = "http://127.0.0.1:8765"
PREFIX = "/releases/download/lab-fault-v6/"
SIGNATURE = BASE + "manifest.sig"
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
PHASE = re.compile(r"\bOTA:\s+phase=([A-Z_]+)\s+reason=(.*)$")
BAD_BOOT = re.compile(r"BOOT_SELECTED|READY_TO_BOOT|PENDING|ESP-ROM:|rst:0x|Guru Meditation|panic'ed|Brownout detector|abort\(\)")
DNS_ERROR = re.compile(r"getaddrinfo|couldn.t get hostname|DNS.*(?:error|fail)|(?:resolve|resolving).*(?:host|fail)", re.I)
CERT_ERROR = re.compile(r"(?:certificate|peer cert|x509).*(?:verif.*fail|fail.*verif|not trusted|CN mismatch|hostname.*mismatch)"
                        r"|fail.*verif.*(?:certificate|peer cert)|-0x2700|MBEDTLS_ERR_X509_CERT_VERIFY_FAILED", re.I)
TRANSPORT_ERRORS = {"ESP_FAIL", "ESP_ERR_TIMEOUT", "ESP_ERR_HTTP_CONNECT", "ESP_ERR_HTTP_FETCH_HEADER",
                    "ESP_ERR_HTTP_CONNECTION_CLOSED", "ESP_ERR_HTTP_EAGAIN"}
CASES = [
    {"name": "N01-dns", "test_id": "N01", "kind": "dns",
     "url": "https://unresolvable.invalid:8443" + PREFIX + "manifest.json"},
    {"name": "N03-untrusted-ca", "test_id": "N03", "kind": "tls", "port": 8444,
     "url": "https://192.168.137.1:8444" + PREFIX + "manifest.json"},
    {"name": "N03-hostname-mismatch", "test_id": "N03", "kind": "tls", "port": 8445,
     "url": "https://192.168.137.1:8445" + PREFIX + "manifest.json"},
    {"name": "N04-clock-not-ready", "test_id": "N04", "kind": "clock", "url": BASE + "manifest.json"},
    {"name": "N05-redirect-loop", "test_id": "N05", "kind": "redirect", "endpoint": "redirect-loop.json",
     "url": BASE + "redirect-loop.json"},
    {"name": "N05-redirect-http", "test_id": "N05", "kind": "redirect", "endpoint": "redirect-http.json",
     "url": BASE + "redirect-http.json"},
    {"name": "N05-redirect-host", "test_id": "N05", "kind": "redirect", "endpoint": "redirect-host.json",
     "url": BASE + "redirect-host.json"},
    {"name": "N06-http404", "test_id": "N06", "kind": "http", "endpoint": "404.json", "status": 404,
     "url": BASE + "404.json"},
    {"name": "N06-html200", "test_id": "N06", "kind": "http", "endpoint": "html.json", "status": 200,
     "url": BASE + "html.json"},
    {"name": "N07-http500", "test_id": "N07", "kind": "retry", "mode": "status500", "status": 500,
     "url": BASE + "manifest.json"},
    {"name": "N07-http429", "test_id": "N07", "kind": "retry", "mode": "status429", "status": 429,
     "url": BASE + "manifest.json"},
    {"name": "N07-timeout", "test_id": "N07", "kind": "retry", "mode": "timeout", "url": BASE + "manifest.json"},
]


def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def snapshot(lines):
    result = {}
    for line in lines:
        match = re.search(r"\bSTATUS version=(\S+).*?selftest=(\S+)\s+service_mode=(\d+)", line)
        if match:
            result.update(version=match[1], selftest=match[2], service_mode=int(match[3]))
        match = re.search(r"\bOTA running=(\w+)@(0x[0-9a-fA-F]+) boot=(\w+) next=\w+ state=(\w+)", line)
        if match:
            result.update(slot=match[1], address=int(match[2], 16), boot=match[3], state=match[4])
        match = re.search(r"\bOTA:\s+status ready=(\d+) busy=(\d+) phase=(\S+).*?wifi=(\w+)", line)
        if match:
            result.update(ready=int(match[1]), busy=int(match[2]), controller_phase=match[3], wifi=match[4])
    return result


def complete(state):
    return {"version", "selftest", "service_mode", "slot", "address", "boot", "state", "ready", "busy", "wifi"} <= state.keys()


def healthy(state, version="5.0.1", reference=None):
    slots = {"ota_0": 0x20000, "ota_1": 0x320000}
    valid = (complete(state) and state["version"] == version and state["selftest"] == "PASS"
             and state["service_mode"] == 0 and state["state"] == "VALID" and state["ready"] == 1
             and state["busy"] == 0 and state["slot"] in slots and state["address"] == slots[state["slot"]]
             and state["boot"] == state["slot"])
    if reference:
        valid = valid and all(state.get(key) == reference.get(key) for key in ("version", "slot", "address", "boot", "state"))
    return valid


def phase_result(lines):
    started, last, reason, phases = False, None, None, []
    for line in lines:
        match = PHASE.search(line)
        if not match:
            continue
        if match[1] == "WAIT_NETWORK_TIME":
            started = True
        if not started:
            continue
        phases.append(match[1])
        if match[1] == "FAILED":
            reason = match[2].strip()
            break
        last = match[1]
    return started, last, reason, phases


def case_events(server_before, server_after):
    history = server_after.get("history", [])
    markers = [event.get("monotonic", 0) for event in server_before.get("history", []) if "control" in event]
    epoch = max(markers) if markers else float("inf")
    return [event for event in history if event.get("monotonic", 0) >= epoch]


def request_events(events, path=None):
    return [event for event in events if "method" in event and "request_id" in event
            and (path is None or event.get("path") == path)]


def backoff_evidence(lines):
    attempts, gaps, rules, waited = {}, [], [], []
    failed_at = None
    for line in lines:
        stamp = re.search(r"\(\s*(\d+)\)\s+OTA:", line)
        failure = re.search(r"download_attempt=(\d+) failed=(\S+) budget=(\d+)", line)
        if failure:
            attempts[int(failure[1])] = {"attempt": int(failure[1]), "reason": failure[2], "budget": int(failure[3])}
            failed_at = int(stamp[1]) if stamp else None
        failure = re.search(r"http_attempt phase=payload attempt=(\d+) budget=(\d+) status=(-?\d+) error=(\S+) retryable=(\d+)", line)
        if failure:
            attempts[int(failure[1])] = {"attempt": int(failure[1]), "budget": int(failure[2]),
                                        "status": int(failure[3]), "reason": failure[4], "retryable": int(failure[5])}
            failed_at = int(stamp[1]) if stamp else None
        rule = re.search(r"retry_backoff phase=payload failed_attempt=(\d+) next_attempt=(\d+) delay_ms=(\d+) status=(-?\d+) retry_after_ms=(\d+)", line)
        if rule:
            rules.append(dict(failed_attempt=int(rule[1]), next_attempt=int(rule[2]), delay_ms=int(rule[3]),
                              status=int(rule[4]), retry_after_ms=int(rule[5])))
        finished = re.search(r"retry_backoff_complete phase=payload waited_ms=(\d+)", line)
        if finished:
            waited.append(int(finished[1]))
        phase = PHASE.search(line)
        if phase and phase[1] == "WAIT_RETRY_NETWORK" and failed_at is not None and stamp:
            gaps.append(int(stamp[1]) - failed_at)
            failed_at = None
    return list(attempts.values()), gaps, rules, waited


def assess(case, lines, before, after, reference, server_before, server_after,
           *, version="5.0.1", clock_on=False, clock_off=False):
    started, phase, reason, phases = phase_result(lines)
    text = "\n".join(lines)
    events = case_events(server_before, server_after)
    requests = request_events(events)
    forbidden = [line for line in lines if BAD_BOOT.search(line)]
    writer = any("writer_started " in line for line in lines)
    timeout_writer = case["kind"] == "retry" and case.get("mode") == "timeout"
    cleanup = bool(re.search(r"payload_cleanup .*writer_abort=1 http_closed=true result=ESP_OK", text))
    writer_ok = not writer or (timeout_writer and cleanup)
    checks = {"new_session_started": started, "FAILED_observed": reason is not None,
              "writer_contract": writer_ok, "no_boot_selection_or_reset": not forbidden,
              "unchanged_healthy_idle_baseline": healthy(before, version, reference) and healthy(after, version, reference)}
    details = {"server_asset_requests": len(requests)}
    kind = case["kind"]
    if kind == "dns":
        checks.update(expected_phase=phase == "FETCH_MANIFEST", actual_DNS_error=bool(DNS_ERROR.search(text)),
                      failing_hostname_logged="unresolvable.invalid" in text, transport_failure=reason in TRANSPORT_ERRORS,
                      no_asset_requests=len(requests) == 0)
    elif kind == "tls":
        checks.update(expected_phase=phase == "FETCH_MANIFEST", actual_certificate_verification_error=bool(CERT_ERROR.search(text)),
                      transport_failure=reason in TRANSPORT_ERRORS, no_HTTP_after_TLS_reject=len(requests) == 0)
    elif kind == "clock":
        checks.update(expected_phase=phase == "WAIT_NETWORK_TIME", policy_failure=reason == "ESP_ERR_INVALID_STATE",
                      diagnostic_enabled_ack=clock_on, diagnostic_disabled_ack=clock_off,
                      actual_NOT_READY_before_TLS="fault_profile_clock_policy=NOT_READY before_TLS=true" in text,
                      TLS_checks_not_disabled="skip_time_verification=false" in text,
                      fetch_not_started="FETCH_MANIFEST" not in phases, no_asset_requests=len(requests) == 0)
    elif kind == "redirect":
        hits = request_events(events, PREFIX + case["endpoint"])
        redirects = [event for event in events if event.get("status") == 302 and "location" in event]
        loop = case["endpoint"] == "redirect-loop.json"
        checks.update(expected_phase=phase == "FETCH_MANIFEST", header_policy_failure=reason == "ESP_ERR_INVALID_RESPONSE",
                      actual_redirect_responses=bool(redirects), bounded_redirect_requests=(2 <= len(hits) <= 6 if loop else len(hits) == 1),
                      no_other_asset_path=all(event.get("path") == PREFIX + case["endpoint"] for event in requests))
        details["redirect_requests"] = len(hits)
    elif kind == "http":
        hits = request_events(events, PREFIX + case["endpoint"])
        checks.update(expected_phase=phase == "FETCH_MANIFEST", metadata_contract_failure=reason == "ESP_ERR_INVALID_RESPONSE",
                      actual_endpoint_requested=len(hits) == 1,
                      actual_HTTP_status=any(event.get("response_status") == case["status"]
                                             and event.get("path") == PREFIX + case["endpoint"] for event in events))
    elif kind == "retry":
        images = request_events(events, PREFIX + "app.bin")
        attempts, gaps, rules, waited = backoff_evidence(lines)
        request_times = [event["monotonic"] for event in images]
        request_gaps = [round((later - earlier) * 1000, 3) for earlier, later in zip(request_times, request_times[1:])]
        logged_wait_ok = (bool(rules) and len(rules) >= max(1, len(images) - 1)
                          and all(800 <= rule["delay_ms"] <= 30000 and rule["delay_ms"] >= rule["retry_after_ms"]
                                  and rule["next_attempt"] == rule["failed_attempt"] + 1 <= 3 for rule in rules))
        # New firmware logs completion only after the requested delay elapses.
        # A declared future delay alone cannot satisfy this gate.
        actual_wait_ok = (bool(request_gaps) and all(gap >= 800 for gap in request_gaps)
                          and len(waited) >= len(rules) > 0
                          and all(wait >= max(800, rule["delay_ms"] - 1) for wait, rule in zip(waited, rules)))
        checks.update(expected_phase=phase == "DOWNLOAD", intended_image_fault_requested=bool(images),
                      injected_mode_observed=bool(images) and all(event.get("image_mode") == case["mode"] for event in images),
                      authenticated_metadata="accepted_metadata " in text and "AUTH_MANIFEST" in phases,
                      bounded_retry_count=2 <= len(images) <= 3,
                      retry_budget_logged=bool(attempts) and all(event["budget"] == 3 and 1 <= event["attempt"] <= 3 for event in attempts),
                      bounded_backoff_logged=logged_wait_ok, actual_backoff_observed=actual_wait_ok,
                      budget_exhaustion_logged=bool(re.search(r"retry_budget_exhausted phase=payload attempts=3", text)),
                      intended_failure_reason=reason in TRANSPORT_ERRORS | {"ESP_ERR_INVALID_RESPONSE"})
        if "status" in case:
            checks["injected_HTTP_status_observed"] = any(event.get("status") == case["status"] for event in events)
        details.update(image_requests=len(images), retry_logs=attempts, backoff_ms=gaps, backoff_rules=rules,
                       completed_wait_ms=waited, server_request_intervals_ms=request_gaps,
                       writer_abort_and_HTTP_cleanup_observed=cleanup)
    else:
        raise ValueError("Unsupported network case")
    gap = None
    if kind == "retry" and reason is not None and checks.get("intended_image_fault_requested"):
        if not (checks["bounded_retry_count"] and checks["bounded_backoff_logged"] and checks["actual_backoff_observed"]
                and checks["retry_budget_logged"] and checks["budget_exhaustion_logged"]):
            gap = "N07_RETRY_POLICY_GAP: intended HTTP/timeout failure lacks observed bounded retry and backoff"
    if all(checks.values()):
        verdict, why = "PASS", "Expected failure gate, actual diagnostic evidence and unchanged VALID baseline observed"
    elif forbidden or not writer_ok or (complete(after) and not healthy(after, version, reference)):
        verdict, why = "FAIL", "Writer/boot/reset/baseline safety contract violated"
    elif reason is None or not complete(after):
        verdict, why = "BLOCKED", "Terminal FAILED or fresh complete post-case status unavailable"
    elif phase == "WAIT_NETWORK_TIME" and kind != "clock":
        verdict, why = "BLOCKED", "Wi-Fi/time prerequisites failed before intended network fault"
    elif kind == "clock" and not clock_on:
        verdict, why = "BLOCKED", "Clock diagnostic injection was not acknowledged"
    elif gap:
        verdict, why = "FAIL", gap
    else:
        verdict, why = "FAIL", "Observed result does not prove the required case-specific failure gate"
    return {"name": case["name"], "test_id": case["test_id"], "result": verdict, "reason": why,
            "checks": checks, "coverage_gap": gap, "observed_failure_phase": phase, "observed_failure_reason": reason,
            "phases": phases, "forbidden_lines": forbidden, "writer_seen": writer, "writer_violation": not writer_ok,
            "baseline_before": before, "baseline_after": after, "details": details, "server_events": events}


class Control:
    def __init__(self):
        self.opener = build_opener(ProxyHandler({}))  # Never proxy loopback control.

    def call(self, settings=None):
        url = CONTROL + ("/control" if settings is not None else "/status")
        body = json.dumps(settings).encode() if settings is not None else None
        request = Request(url, data=body, headers={"Content-Type": "application/json"})
        with self.opener.open(request, timeout=5) as response:
            payload = response.read(262145)
        if len(payload) > 262144:
            raise ValueError("Oversize localhost control response")
        value = json.loads(payload)
        if not isinstance(value.get("history"), list) or type(value.get("request_count")) is not int:
            raise ValueError("Unexpected localhost fault-server schema")
        return value


class Capture:
    def __init__(self, port, redactor):
        self.port, self.redactor = port, redactor
        self.pending = bytearray()
        self.lines = []
        self.log = None

    def record(self, line, device=True):
        line = ANSI.sub("", line).replace("\r", "")
        if device:
            self.lines.append(line)
        safe = self.redactor(line)
        if self.log:
            self.log.write(f"{now()} {safe}\n")
            self.log.flush()
        print(safe, flush=True)

    def send(self, command):
        if "\r" in command or "\n" in command or command.startswith("wifi "):
            raise ValueError("No multiline/provisioning commands allowed")
        self.port.write((command + "\n").encode())
        self.port.flush()
        self.record("[HOST] sent: " + command, False)

    def pump(self, duration, stop=None):
        begin, deadline = len(self.lines), time.monotonic() + duration
        while time.monotonic() < deadline:
            data = self.port.read(min(16384, max(1, self.port.in_waiting)))
            if data:
                self.pending.extend(data)
                while b"\n" in self.pending:
                    raw, _, self.pending = self.pending.partition(b"\n")
                    self.pending = bytearray(self.pending)
                    self.record(raw.decode("utf-8", errors="replace"))
            if stop and stop(self.lines[begin:]):
                break
        return self.lines[begin:]

    def baseline(self):
        begin, deadline, probe = len(self.lines), time.monotonic() + 10, time.monotonic() + 0.8
        self.send("status")
        self.send("otastatus")
        while time.monotonic() < deadline:
            self.pump(0.2)
            state = snapshot(self.lines[begin:])
            if complete(state) and state["busy"] == 0:
                return state, self.lines[begin:]
            if time.monotonic() >= probe:
                self.send("otastatus")
                probe = time.monotonic() + 0.8
        return snapshot(self.lines[begin:]), self.lines[begin:]

    def clock(self, enabled):
        self.send("lab-clock-not-ready " + ("on" if enabled else "off"))
        marker = f"lab_clock_not_ready={int(enabled)} actual_clock_unchanged=true TLS_time_checks_enabled=true"
        lines = self.pump(3, lambda items: any(marker in line for line in items))
        return any(marker in line for line in lines)


def main():
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", default="COM13")
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--baseline-version", default="5.0.1")
    parser.add_argument("--timeout", type=float, default=90)
    parser.add_argument("--only", nargs="+", default=[])
    parser.add_argument("--redact-file", type=Path, default=Path(__file__).resolve().parents[1] / ".secrets" / "wifi.json")
    parser.add_argument("--validate-only", action="store_true", help="List/validate cases; no COM or control API access")
    args = parser.parse_args()
    selectors = {item for value in args.only for item in value.split(",") if item}
    known = {case["name"] for case in CASES} | {case["test_id"] for case in CASES}
    if selectors - known:
        parser.error("Unknown --only selectors: " + ", ".join(sorted(selectors - known)))
    cases = [case for case in CASES if not selectors or case["name"] in selectors or case["test_id"] in selectors]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,30}", args.baseline_version) or not 1 <= args.timeout <= 900:
        parser.error("Invalid baseline app version or per-case timeout (1..900 seconds)")
    if args.validate_only:
        print(json.dumps({"selected_count": len(cases), "cases": cases, "serial_opened": False,
                          "control_API_called": False, "listener_started": False}, indent=2))
        return 0
    try:
        if not args.redact_file.is_file():
            raise ValueError("Private redaction JSON is required; set --redact-file to the existing project .secrets/wifi.json")
        private = json.loads(args.redact_file.read_text(encoding="utf-8-sig"))
        if (not isinstance(private, dict) or not isinstance(private.get("ssid"), str)
                or not private["ssid"] or not isinstance(private.get("password"), str)):
            raise ValueError("Private redaction JSON must contain string ssid/password fields")
        secrets = sorted({private.get("ssid", ""), private.get("password", "")} - {""}, key=len, reverse=True)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    def redact(value):
        if isinstance(value, str):
            for secret in secrets:
                value = value.replace(secret, "[REDACTED]")
        elif isinstance(value, list):
            return [redact(item) for item in value]
        elif isinstance(value, dict):
            return {key: redact(item) for key, item in value.items()}
        return value

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    run_dir = args.evidence_dir / ("run-" + run_id)
    run_dir.mkdir(parents=True, exist_ok=False)
    summary = {"run_id": run_id, "started_utc": now(), "evidence_kind": "ACTUAL_DEVICE_SERIAL_AND_LOCAL_SERVER",
               "expected_version": args.baseline_version, "port": args.port, "selected_count": len(cases),
               "reset_method": "NONE; RTS/DTR false before serial open", "results": []}

    def save():
        summary["counts"] = dict(Counter(case["result"] for case in summary["results"]))
        summary["all_selected_passed"] = (len(summary["results"]) == len(cases)
                                           and all(case["result"] == "PASS" for case in summary["results"]))
        encoded = json.dumps(redact(summary), ensure_ascii=False, indent=2) + "\n"
        (run_dir / "summary.json").write_text(encoded, encoding="utf-8")
        (args.evidence_dir / "summary.json").write_text(encoded, encoding="utf-8")

    port = serial.Serial(port=None, baudrate=115200, timeout=0.1, write_timeout=3, rtscts=False, dsrdtr=False)
    port.dtr, port.rts, port.port = False, False, args.port
    capture, control = Capture(port, redact), Control()
    reference, abort_reason, clock_armed = None, None, False
    try:
        control.call()  # Missing controlled server is a prerequisite failure.
        port.open()
        for case in cases:
            if abort_reason:
                summary["results"].append({"name": case["name"], "test_id": case["test_id"], "result": "BLOCKED",
                                           "reason": "Run stopped: " + abort_reason})
                save()
                continue
            logfile = run_dir / (case["name"] + ".log")
            with logfile.open("w", encoding="utf-8", newline="\n") as log:
                capture.log = log
                capture.record("[HOST] case=" + case["name"] + " no host reset commands", False)
                capture.pump(0.3)
                before, initial_lines = capture.baseline()
                if reference is None and healthy(before, args.baseline_version):
                    reference = dict(before)
                    summary["observed_reference"] = reference
                if (not healthy(before, args.baseline_version, reference) or before.get("wifi") != "up"
                        or any(BAD_BOOT.search(line) for line in initial_lines)):
                    result = {"name": case["name"], "test_id": case["test_id"], "result": "BLOCKED",
                              "reason": "Expected v5 healthy VALID idle baseline and connected Wi-Fi not observed", "baseline_before": before}
                    abort_reason = result["reason"]
                else:
                    settings = {"reset": True}
                    if case["kind"] == "retry":
                        settings.update(image_mode=case["mode"], fault_requests=-1, delay_ms=18000)
                    server_before = control.call(settings)
                    capture.record("[HOST] server_settings=" + json.dumps(server_before["settings"], sort_keys=True), False)
                    clock_on = clock_off = False
                    if case["kind"] == "clock":
                        clock_armed = True
                        clock_on = capture.clock(True)
                    start = len(capture.lines)
                    capture.send("ota " + case["url"] + " " + SIGNATURE)
                    began = time.monotonic()
                    capture.pump(args.timeout, lambda lines: bool(phase_result(lines)[2])
                                 or any(BAD_BOOT.search(line) for line in lines))
                    body = list(capture.lines[start:])
                    if phase_result(body)[2] is None and not any(BAD_BOOT.search(line) for line in body):
                        capture.send("cancel")
                        capture.pump(3)
                        body = list(capture.lines[start:])
                    if clock_armed:
                        clock_off = capture.clock(False)
                        clock_armed = not clock_off
                    after, after_lines = capture.baseline()
                    server_after = control.call()
                    result = assess(case, body + after_lines, before, after, reference, server_before, server_after,
                                    version=args.baseline_version, clock_on=clock_on, clock_off=clock_off)
                    result.update(elapsed_seconds=round(time.monotonic() - began, 3),
                                  server_settings=server_before["settings"], server_request_count_after=server_after["request_count"])
                    if (result["forbidden_lines"] or result["writer_violation"] or not healthy(after, args.baseline_version, reference)
                            or clock_armed):
                        abort_reason = "Safety, baseline, idle or clock-cleanup condition requires review"
                    control.call({"reset": True})
                result["log"] = logfile.relative_to(args.evidence_dir).as_posix()
                summary["results"].append(result)
                capture.record("[HOST] case_result=" + result["result"] + " reason=" + result["reason"], False)
                save()
                capture.log = None
    except (OSError, ValueError, serial.SerialException, KeyboardInterrupt) as error:
        summary["run_error"] = str(error) or type(error).__name__
    finally:
        capture.log = None
        if clock_armed and port.is_open:
            try:
                if not capture.clock(False):
                    summary["clock_cleanup_not_proven"] = True
            except (OSError, serial.SerialException):
                summary["clock_cleanup_not_proven"] = True
        if port.is_open:
            port.close()
        try:
            control.call({"reset": True})
        except (OSError, ValueError):
            summary["server_cleanup_not_proven"] = True
        completed = {case["name"] for case in summary["results"]}
        for case in cases:
            if case["name"] not in completed:
                summary["results"].append({"name": case["name"], "test_id": case["test_id"], "result": "BLOCKED",
                                           "reason": "Run incomplete; no result inferred"})
        summary["finished_utc"] = now()
        save()
    print(json.dumps(redact({"summary": str(run_dir / "summary.json"), "counts": summary["counts"],
                             "all_selected_passed": summary["all_selected_passed"]})), flush=True)
    return 0 if summary["all_selected_passed"] else 1 if summary["counts"].get("FAIL") else 2


if __name__ == "__main__":
    raise SystemExit(main())
