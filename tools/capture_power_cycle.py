"""Observe USB removal/reconnection without asserting RTS/DTR resets."""
import argparse
import json
from pathlib import Path
import time

import serial


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', default='COM13')
    parser.add_argument('--duration', type=float, default=180)
    parser.add_argument('--log', type=Path, required=True)
    args = parser.parse_args()
    private = Path(__file__).resolve().parents[1] / '.secrets' / 'wifi.json'
    secrets = list(json.loads(private.read_text()).values()) if private.is_file() else []
    args.log.parent.mkdir(parents=True, exist_ok=True)
    port = None
    removed = reconnected = healthy = valid = False
    deadline = time.monotonic() + args.duration
    buffer = bytearray()
    with args.log.open('w', encoding='utf-8', newline='\n') as log:
        def record(line):
            for secret in secrets:
                if secret:
                    line = line.replace(secret, '[REDACTED]')
            print(line, flush=True)
            log.write(line + '\n')
            log.flush()
        record('[HOST] Waiting for physical USB removal/reconnection; no host reset commands')
        while time.monotonic() < deadline:
            try:
                if port is None:
                    attempt = serial.Serial(port=None, baudrate=115200, timeout=0.1)
                    attempt.dtr = False
                    attempt.rts = False
                    attempt.port = args.port
                    attempt.open()
                    port = attempt
                    if removed:
                        reconnected = True
                        record('[HOST] Serial device reconnected after observed removal')
                chunk = port.read(max(1, port.in_waiting))
                buffer.extend(chunk)
                while b'\n' in buffer:
                    raw, _, buffer = buffer.partition(b'\n')
                    line = raw.decode('utf-8', errors='replace').replace('\r', '')
                    record(line)
                    if reconnected:
                        healthy |= 'SELFTEST result=PASS' in line
                        valid |= 'OTA running=' in line and 'state=VALID' in line
                if reconnected and healthy and valid:
                    record('[HOST] Reconnected boot observed: self-test PASS and SDK VALID')
                    return 0
            except (serial.SerialException, OSError):
                if port is not None:
                    try:
                        port.close()
                    except Exception:
                        pass
                    port = None
                    removed = True
                    buffer.clear()
                    record('[HOST] Serial device removal observed')
                time.sleep(0.15)
        if port:
            port.close()
        record('[HOST] Physical cycle observation incomplete; do not label PASS')
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
