"""Probe existing isolated listeners with TLS verification; never starts a server."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import ssl
from urllib.error import URLError
from urllib.request import HTTPSHandler, ProxyHandler, build_opener


def probe(ca: Path, timeout: float):
    context = ssl.create_default_context(cafile=str(ca.resolve(strict=True)))
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
    results = []
    for port, expected in ((8443, "ACCEPT"), (8444, "REJECT_UNTRUSTED_CA"), (8445, "REJECT_HOSTNAME")):
        url = f"https://192.168.137.1:{port}/releases/download/lab-fault-v6/manifest.json"
        item = {"port": port, "expected": expected}
        try:
            with opener.open(url, timeout=timeout) as response:
                raw = response.read(4097)
                data = json.loads(raw)
                good = (port == 8443 and response.status == 200 and len(raw) <= 4096
                        and data.get("version") == "9.9.9" and data.get("version_code") == 6)
                item.update(observed="TLS_ACCEPT_HTTP200", result="PASS" if good else "FAIL")
        except URLError as exc:
            reason = exc.reason
            if isinstance(reason, ssl.SSLCertVerificationError):
                message = reason.verify_message
                matches = ((port == 8444 and "self" in message.lower())
                           or (port == 8445 and ("mismatch" in message.lower() or "not valid for" in message.lower())))
                item.update(observed="TLS_CERTIFICATE_REJECT", detail=message, result="PASS" if matches else "FAIL")
            else:
                item.update(observed="CONNECT_OR_HTTP_FAILURE", detail=str(reason), result="FAIL")
        except (OSError, ValueError) as exc:
            item.update(observed="PROBE_FAILURE", detail=str(exc), result="FAIL")
        results.append(item)
    try:
        with opener.open("http://127.0.0.1:8765/status", timeout=timeout) as response:
            control = json.loads(response.read(65536))
            valid = response.status == 200 and isinstance(control.get("settings"), dict)
            results.append({"port": 8765, "observed": "LOOPBACK_CONTROL_STATUS", "result": "PASS" if valid else "FAIL"})
    except (OSError, ValueError) as exc:
        results.append({"port": 8765, "observed": "CONTROL_UNAVAILABLE", "detail": str(exc), "result": "FAIL"})
    return {"host_listener_probe": "PASS" if all(item["result"] == "PASS" for item in results) else "FAIL",
            "board_reachability": "NOT TESTED", "checks": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ca", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=5)
    args = parser.parse_args()
    report = probe(args.ca, args.timeout)
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["host_listener_probe"] == "PASS" else 1)


if __name__ == "__main__":
    main()
