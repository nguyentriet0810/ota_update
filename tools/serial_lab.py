"""Capture board responses without echoing commands containing Wi-Fi secrets."""
import argparse
import getpass
import json
from pathlib import Path
import re
import sys
import time

import serial


def main():
    # Reset/boot noise can decode to U+FFFD; pipes must not inherit cp1252.
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', default='COM13')
    parser.add_argument('--baud', type=int, default=115200)
    parser.add_argument('--duration', type=float, default=30)
    parser.add_argument('--log', type=Path, required=True)
    parser.add_argument('--send', action='append', default=[])
    parser.add_argument('--until', help='Stop after this regex appears in a response')
    parser.add_argument('--wifi-file', type=Path, help='Private JSON {ssid,password}; never copied into evidence')
    parser.add_argument('--redact-file', type=Path, default=Path(__file__).resolve().parents[1] / '.secrets' / 'wifi.json',
                        help='Private JSON used only to redact responses; does not provision credentials')
    parser.add_argument('--provision', action='store_true', help='Prompt for Wi-Fi credentials without echoing password')
    parser.add_argument('--reset', action='store_true', help='Pulse EN using RTS (not a power-cut test)')
    parser.add_argument('--on', help='On this response regex, send --then once')
    parser.add_argument('--then', help='Fault/status command to send after --on matches')
    args = parser.parse_args()
    secrets = []
    if args.redact_file.is_file():
        redaction = json.loads(args.redact_file.read_text(encoding='utf-8-sig'))
        secrets.extend([redaction.get('password', ''), redaction.get('ssid', '')])
    wifi = None
    if args.wifi_file:
        wifi = json.loads(args.wifi_file.read_text(encoding='utf-8-sig'))
    elif args.provision:
        wifi = {'ssid': input('Wi-Fi SSID: '), 'password': getpass.getpass('Wi-Fi password: ')}
    if wifi:
        if any(c in wifi['ssid'] + wifi['password'] for c in '\r\n|'):
            parser.error('Credentials cannot contain newline or | in this serial provisioning protocol')
        secrets.extend([wifi['password'], wifi['ssid']])
    for cmd in args.send + ([args.then] if args.then else []):
        if cmd and cmd.startswith('wifi '):
            parser.error('Use --provision or --wifi-file; do not put credentials on the command line')
    args.log.parent.mkdir(parents=True, exist_ok=True)
    port = serial.Serial(port=None, baudrate=args.baud, timeout=0.1)
    port.dtr = False
    port.rts = False
    port.port = args.port
    start = time.monotonic()
    hit = False
    trigger_sent = False
    with args.log.open('w', encoding='utf-8', newline='\n') as log:
        def record(value):
            for secret in secrets:
                if secret:
                    value = value.replace(secret, '[REDACTED]')
            log.write(value)
            log.flush()
            sys.stdout.write(value)
            sys.stdout.flush()
        try:
            port.open()
            if args.reset:
                port.dtr = False
                port.rts = True
                time.sleep(0.12)
                port.rts = False
                record('[HOST] EN/RTS reset; this is not physical power removal\n')
            time.sleep(0.3)
            if wifi:
                port.write(('wifi ' + wifi['ssid'] + '|' + wifi['password'] + '\n').encode())
                record('[HOST] Wi-Fi credentials sent privately; command suppressed\n')
                time.sleep(0.2)
            for cmd in args.send:
                port.write((cmd + '\n').encode())
                record('[HOST] sent: ' + cmd + '\n')
                time.sleep(0.2)
            buffer = bytearray()
            while time.monotonic() - start < args.duration:
                chunk = port.read(max(1, port.in_waiting))
                if not chunk:
                    continue
                buffer.extend(chunk)
                while b'\n' in buffer:
                    raw, _, buffer = buffer.partition(b'\n')
                    line = raw.decode('utf-8', errors='replace').replace('\r', '')
                    record(line + '\n')
                    if args.on and args.then and not trigger_sent and re.search(args.on, line):
                        port.write((args.then + '\n').encode())
                        trigger_sent = True
                        record('[HOST] fault trigger sent: ' + args.then + '\n')
                    if args.until and re.search(args.until, line):
                        hit = True
                if hit:
                    break
            if buffer:
                record(buffer.decode('utf-8', errors='replace') + '\n')
        finally:
            if port.is_open:
                port.close()
    if args.until and not hit:
        print('Expected response pattern was not observed', file=sys.stderr)
        return 2
    if args.on and not trigger_sent:
        print('Fault trigger pattern was not observed', file=sys.stderr)
        return 3
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
