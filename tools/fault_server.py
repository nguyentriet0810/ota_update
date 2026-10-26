"""Isolated OTA TLS fault server. Binds the hotspot IP and localhost control only."""
from __future__ import annotations

import argparse
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import socket
import ssl
import threading
import time
from urllib.parse import unquote, urlsplit

PREFIX = "/releases/download/lab-fault-v6/"
DEFAULT = {"image_mode": "good", "range_mode": "correct", "fault_requests": -1,
           "delay_ms": 18000, "cut_after": 147456, "chunk_bytes": 4096,
           "chunk_delay_ms": 0}
IMAGE_MODES = {"good", "tamper_tail", "truncate", "html", "not_found", "status500", "status429", "timeout", "cut"}
RANGE_MODES = {"correct", "ignore", "416", "wrong_start", "wrong_total", "wrong_end"}


class LabState:
    def __init__(self, log):
        self.lock = threading.Lock()
        self.settings = dict(DEFAULT)
        self.history = deque(maxlen=100)
        self.request_count = 0
        self.bytes_sent = 0
        self.log = log

    def record(self, **event):
        with self.lock:
            event = {"monotonic": round(time.monotonic(), 3), **event}
            self.history.append(event)
            line = json.dumps(event, separators=(",", ":"))
            if self.log:
                self.log.write(line + "\n")
                self.log.flush()
        print(line, flush=True)

    def snapshot(self, *, image=False):
        with self.lock:
            settings = dict(self.settings)
            self.request_count += 1
            settings["request_id"] = self.request_count
            if image and settings["image_mode"] != "good":
                if settings["fault_requests"] == 0:
                    settings["image_mode"] = "good"
                elif settings["fault_requests"] > 0:
                    self.settings["fault_requests"] -= 1
            return settings

    def status(self):
        with self.lock:
            return {"settings": dict(self.settings), "request_count": self.request_count,
                    "bytes_sent": self.bytes_sent, "history": list(self.history)}

    def control(self, change):
        if not isinstance(change, dict):
            raise ValueError("control must be an object")
        if set(change) - (set(DEFAULT) | {"reset"}):
            raise ValueError("unknown control field")
        with self.lock:
            next_settings = dict(DEFAULT) if change.get("reset") else dict(self.settings)
            for key, value in change.items():
                if key == "reset":
                    if type(value) is not bool:
                        raise ValueError("reset must be boolean")
                    continue
                if key in ("image_mode", "range_mode"):
                    if not isinstance(value, str):
                        raise ValueError("mode must be a string")
                    value = value.lower()
                    if key == "range_mode":
                        value = {"200": "ignore", "wrong_content_range": "wrong_start"}.get(value, value)
                    allowed = IMAGE_MODES if key == "image_mode" else RANGE_MODES
                    if value not in allowed:
                        raise ValueError("unknown mode")
                else:
                    bounds = {"fault_requests": (-1, 100), "delay_ms": (0, 60000),
                              "cut_after": (1, 3145728), "chunk_bytes": (256, 65536),
                              "chunk_delay_ms": (0, 1000)}
                    low, high = bounds[key]
                    if type(value) is not int or not low <= value <= high:
                        raise ValueError(f"integer bound: {key}")
                next_settings[key] = value
            self.settings = next_settings
        self.record(control=next_settings)
        return self.status()


def handlers(root: Path, state: LabState):
    class Common(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "OtaFaultLab/1"
        sys_version = ""

        def log_message(self, *_):
            pass

        def response(self, code, body=b"", content_type="text/plain", extra=None):
            state.record(response_status=code, response_bytes=len(body), path=self.path,
                         handler=self.__class__.__name__)
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", content_type)
            self.send_header("Connection", "close")
            for name, value in (extra or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.close_connection = True
            if self.command != "HEAD":
                try:
                    self.wfile.write(body)
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass

    class Assets(Common):
        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            request = urlsplit(self.path)
            settings = state.snapshot(image=request.path.endswith(".bin"))
            rid = settings["request_id"]
            path = unquote(request.path)
            port = self.server.server_address[1]
            state.record(request_id=rid, port=port, path=path, method=self.command,
                         range=self.headers.get("Range", ""), image_mode=settings["image_mode"],
                         range_mode=settings["range_mode"])
            if request.query or request.fragment or not path.startswith(PREFIX):
                self.response(404, b"outside public fixture routes\n")
                return
            name = path[len(PREFIX):]
            if "/" in name or "\\" in name or not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or name.startswith("."):
                self.response(404)
                return
            redirects = {"redirect-loop.json": f"https://192.168.137.1:{port}{PREFIX}redirect-loop.json",
                         "redirect-http.json": f"http://192.168.137.1:{port}{PREFIX}manifest.json",
                         "redirect-host.json": f"https://not-allowed.invalid{PREFIX}manifest.json"}
            if name in redirects:
                state.record(request_id=rid, status=302, location=redirects[name])
                self.response(302, extra={"Location": redirects[name]})
                return
            if name in {"404.json", "not-found.json"}:
                self.response(404, b"fixture not found\n")
                return
            if name == "html.json":
                self.response(200, b"<!doctype html><title>Not firmware</title>", "text/html")
                return
            if name in {"status-500.json", "status-429.json"}:
                status = 500 if name == "status-500.json" else 429
                self.response(status, b"injected status\n", extra={"Retry-After": "1"})
                return
            if name == "timeout.json":
                time.sleep(settings["delay_ms"] / 1000)
                self.response(504, b"delayed metadata\n")
                return
            file = (root / name).resolve()
            if file.parent != root or not file.is_file() or file.suffix.lower() not in {".json", ".sig", ".bin"}:
                self.response(404)
                return
            data = file.read_bytes()
            image = file.suffix.lower() == ".bin"
            mode = settings["image_mode"] if image else "good"
            if mode == "timeout":
                time.sleep(settings["delay_ms"] / 1000)
            if mode in {"status500", "status429", "not_found"}:
                status = {"status500": 500, "status429": 429, "not_found": 404}[mode]
                state.record(request_id=rid, status=status)
                self.response(status, b"injected image status\n", extra={"Retry-After": "1"})
                return
            if mode == "html":
                self.response(200, b"<!doctype html><title>Not firmware</title>", "text/html")
                return
            if mode == "tamper_tail" and data:
                data = data[:-1] + bytes([data[-1] ^ 1])
            if mode == "truncate":
                data = data[:-4096]
            total = len(data)
            start, end, status = 0, total - 1, 200
            requested = self.headers.get("Range")
            range_mode = settings["range_mode"] if image else "correct"
            if requested and range_mode != "ignore":
                match = re.fullmatch(r"bytes=(\d+)-(\d*)", requested.strip())
                if not match:
                    self.response(416, extra={"Content-Range": f"bytes */{total}"})
                    return
                start = int(match.group(1))
                end = min(int(match.group(2)), total - 1) if match.group(2) else total - 1
                if start >= total or end < start or range_mode == "416":
                    state.record(request_id=rid, status=416, range_start=start, total=total)
                    self.response(416, extra={"Content-Range": f"bytes */{total}"})
                    return
                status = 206
            body = data[start:end + 1]
            content_range = None
            if status == 206:
                header_start = start + 1 if range_mode == "wrong_start" else start
                header_end = end - 1 if range_mode == "wrong_end" else end
                header_total = total + 4096 if range_mode == "wrong_total" else total
                content_range = f"bytes {header_start}-{header_end}/{header_total}"
            self.send_response(status)
            self.send_header("Content-Type", "application/json" if file.suffix == ".json" else "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Connection", "close")
            if content_range:
                self.send_header("Content-Range", content_range)
            self.end_headers()
            self.close_connection = True
            state.record(request_id=rid, status=status, content_length=len(body),
                         content_range=content_range, range_start=start, file_total=total)
            sent = 0
            send_limit = len(body)
            if image and mode == "cut":
                send_limit = max(0, min(send_limit, settings["cut_after"] - start))
            try:
                if self.command != "HEAD":
                    while sent < send_limit:
                        chunk = body[sent:min(send_limit, sent + settings["chunk_bytes"])]
                        self.wfile.write(chunk)
                        self.wfile.flush()
                        sent += len(chunk)
                        if image and settings["chunk_delay_ms"]:
                            time.sleep(settings["chunk_delay_ms"] / 1000)
                if image and mode == "cut":
                    try:
                        self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError) as exc:
                state.record(request_id=rid, peer_closed=type(exc).__name__)
            finally:
                with state.lock:
                    state.bytes_sent += sent
                state.record(request_id=rid, sent_bytes=sent, complete=(sent == len(body)), mode=mode)

    class Controller(Common):
        def do_GET(self):
            if self.path not in ("/status", "/health"):
                self.response(404)
                return
            self.response(200, json.dumps(state.status()).encode(), "application/json")

        def do_POST(self):
            if self.path != "/control":
                self.response(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 4096:
                    raise ValueError("body bound")
                result = state.control(json.loads(self.rfile.read(length)))
                self.response(200, json.dumps(result).encode(), "application/json")
            except (ValueError, json.JSONDecodeError) as exc:
                self.response(400, str(exc).encode())

    return Assets, Controller


def run(args):
    root = args.root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("public fixture root must be a directory")
    if args.bind != "192.168.137.1":
        raise ValueError("this lab server binds only the explicit hotspot IP192.168.137.1")
    args.log.parent.mkdir(parents=True, exist_ok=True)
    servers = []
    started = []
    with args.log.open("a", encoding="utf-8", buffering=1) as log:
        state = LabState(log)
        assets, controller = handlers(root, state)
        try:
            for port, name in ((8443, "good"), (8444, "untrusted"), (8445, "wrong-host")):
                server = ThreadingHTTPServer((args.bind, port), assets)
                servers.append(server)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                certificate = args.tls_dir / (f"{name}.cert.pem" if name == "untrusted" else f"{name}.chain.pem")
                context.load_cert_chain(str(certificate), str(args.tls_dir / f"{name}.key.pem"))
                server.socket = context.wrap_socket(server.socket, server_side=True)
            servers.append(ThreadingHTTPServer(("127.0.0.1", 8765), controller))
            for server in servers:
                threading.Thread(target=server.serve_forever, daemon=True).start()
                started.append(server)
            state.record(server="ready", https=["192.168.137.1:8443", "192.168.137.1:8444", "192.168.137.1:8445"],
                         control="http://127.0.0.1:8765", public_root=str(root))
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
        finally:
            for server in servers:
                if server in started:
                    server.shutdown()
                server.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--tls-dir", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--bind", default="192.168.137.1")
    args = parser.parse_args()
    try:
        run(args)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"SERVER ERROR: {exc}\n")


if __name__ == "__main__":
    main()
