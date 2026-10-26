"""Loopback HTTP handler checks only; no COM or external network."""
import http.client
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

import fault_server


class FaultServerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name).resolve()
        self.image = bytes(range(256)) * 32
        (self.root / "app.bin").write_bytes(self.image)
        (self.root / "manifest.json").write_bytes(b'{"fixture":true}')
        self.state = fault_server.LabState(io.StringIO())
        handler, _ = fault_server.handlers(self.root, self.state)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.directory.cleanup()

    def get(self, name="app.bin", headers=None):
        client = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=3)
        client.request("GET", fault_server.PREFIX + name, headers=headers or {})
        response = client.getresponse()
        result = (response.status, dict(response.getheaders()), response.read())
        client.close()
        return result

    def test_correct_range_and_length(self):
        status, headers, body = self.get(headers={"Range": "bytes=4096-"})
        self.assertEqual(status, 206)
        self.assertEqual(headers["Content-Range"], "bytes 4096-8191/8192")
        self.assertEqual(int(headers["Content-Length"]), len(body))
        self.assertEqual(body, self.image[4096:])

    def test_range_ignored_416_and_bad_header(self):
        for mode, status in (("ignore", 200), ("416", 416), ("wrong_start", 206)):
            with self.subTest(mode=mode):
                self.state.control({"range_mode": mode})
                got, headers, body = self.get(headers={"Range": "bytes=4096-"})
                self.assertEqual(got, status)
                if mode == "ignore":
                    self.assertEqual(body, self.image)
                if mode == "wrong_start":
                    self.assertEqual(headers["Content-Range"], "bytes 4097-8191/8192")

    def test_tamper_tail_fixed_url_and_single_fault_budget(self):
        self.state.control({"image_mode": "TAMPER_TAIL", "fault_requests": 1})
        _, _, first = self.get()
        _, _, second = self.get()
        self.assertEqual(first[:-1], self.image[:-1])
        self.assertNotEqual(first[-1], self.image[-1])
        self.assertEqual(second, self.image)

    def test_truncated_file_content_length_is_actual(self):
        self.state.control({"image_mode": "truncate"})
        _, headers, body = self.get()
        self.assertEqual(len(body), len(self.image) - 4096)
        self.assertEqual(int(headers["Content-Length"]), len(body))

    def test_metadata_redirects_html_and_status(self):
        for name, status in (("redirect-loop.json", 302), ("redirect-http.json", 302),
                             ("redirect-host.json", 302), ("404.json", 404), ("html.json", 200),
                             ("status-500.json", 500), ("status-429.json", 429)):
            with self.subTest(name=name):
                got, headers, body = self.get(name)
                self.assertEqual(got, status)
                self.assertEqual(int(headers["Content-Length"]), len(body))

    def test_no_file_traversal_or_private_extension(self):
        for name in ("../app.bin", "%2e%2e%2fapp.bin", "secret.key.pem", ".hidden.json"):
            with self.subTest(name=name):
                self.assertEqual(self.get(name)[0], 404)

    def test_control_rejects_unknown_fields_and_bounds(self):
        for change in ({"bind": "0.0.0.0"}, {"image_mode": "execute"}, {"chunk_bytes": -1},
                       {"fault_requests": True}, {"range_mode": "anything"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.state.control(change)


if __name__ == "__main__":
    unittest.main(verbosity=2)
