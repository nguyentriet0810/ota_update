"""Host security tests; these do not assert board or HTTPS coverage."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import release


def encoded(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


class ReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        image = bytearray(8192)
        image[0] = 0xE9
        struct.pack_into("<H", image, 12, 9)
        struct.pack_into("<II", image, 32, 0xABCD5432, 0)
        image[48:54] = b"2.0.0\0"
        project = b"studybook_ota_lab"
        image[80:112] = project + bytes(32 - len(project))
        cls.image = bytes(image)
        cls.manifest = {**release.PROFILE, "release": "v2.0.0", "version": "2.0.0",
                        "version_code": 2, "secure_version": 0, "config_schema": 2,
                        "min_updater_version": 1, "size": len(cls.image),
                        "sha256": hashlib.sha256(cls.image).hexdigest(),
                        "url": "https://github.com/test/ota-lab/releases/download/v2.0.0/app.bin"}

    def signed(self, raw):
        return self.key.sign(raw, release.PSS, hashes.SHA256())

    def test_valid_raw_signature_and_image(self):
        raw = encoded(self.manifest)
        got = release.verify_manifest(raw, self.signed(raw), self.key.public_key(), current_version_code=1)
        self.assertEqual(release.verify_image(self.image, got)["version"], "2.0.0")

    def test_exact_byte_newline_tamper(self):
        raw = encoded(self.manifest)
        with self.assertRaisesRegex(release.ReleaseError, "SIGNATURE"):
            release.verify_manifest(raw + b"\n", self.signed(raw), self.key.public_key())

    def test_signature_byte_tamper(self):
        raw = encoded(self.manifest)
        sig = bytearray(self.signed(raw))
        sig[17] ^= 1
        with self.assertRaisesRegex(release.ReleaseError, "SIGNATURE"):
            release.verify_manifest(raw, bytes(sig), self.key.public_key())

    def test_wrong_key(self):
        raw = encoded(self.manifest)
        other = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        with self.assertRaisesRegex(release.ReleaseError, "SIGNATURE"):
            release.verify_manifest(raw, self.signed(raw), other.public_key())

    def test_wrong_salt_rejected(self):
        raw = encoded(self.manifest)
        signature = self.key.sign(raw, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=0), hashes.SHA256())
        with self.assertRaisesRegex(release.ReleaseError, "SIGNATURE"):
            release.verify_manifest(raw, signature, self.key.public_key())

    def test_truncated_signature(self):
        raw = encoded(self.manifest)
        with self.assertRaisesRegex(release.ReleaseError, "AUTH_BOUND"):
            release.verify_manifest(raw, self.signed(raw)[:-1], self.key.public_key())

    def test_signed_duplicate_key_rejected(self):
        raw = encoded(self.manifest)[:-1] + b',"size":17}'
        with self.assertRaisesRegex(release.ReleaseError, "DUPLICATE_KEY"):
            release.verify_manifest(raw, self.signed(raw), self.key.public_key())

    def test_signed_unknown_field_rejected(self):
        value = {**self.manifest, "release_id": "a" * 64}
        raw = encoded(value)
        with self.assertRaisesRegex(release.ReleaseError, "FIELDS"):
            release.verify_manifest(raw, self.signed(raw), self.key.public_key())

    def test_numeric_bounds_and_types(self):
        fields = {"schema_version": [True, 2, 1.0], "size": [True, 0, -1, 3.5, release.MAX_IMAGE + 1],
                  "version_code": [0, -1, True, 2.0, 0x80000000], "secure_version": [1, False],
                  "config_schema": [0, 3], "min_updater_version": [0, 2]}
        for field, values in fields.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    data = {**self.manifest, field: value}
                    with self.assertRaises(release.ReleaseError):
                        release.validate_manifest(encoded(data))

    def test_profile_mismatch(self):
        for field in ("product", "board", "chip", "layout_id", "manifest_key_id"):
            with self.subTest(field=field), self.assertRaisesRegex(release.ReleaseError, "PROFILE"):
                release.validate_manifest(encoded({**self.manifest, field: "unknown"}))

    def test_bad_digest_format(self):
        for value in ("A" * 64, "0" * 63, "g" * 64, 1 * 10 ** 63, None):
            with self.subTest(value=value), self.assertRaisesRegex(release.ReleaseError, "DIGEST"):
                release.validate_manifest(encoded({**self.manifest, "sha256": value}))

    def test_url_policy(self):
        urls = ["http://github.com/o/r/releases/download/v2/app.bin",
                "https://github.com.evil.test/o/r/releases/download/v2/app.bin",
                "https://token@github.com/o/r/releases/download/v2/app.bin",
                "https://github.com/o/r/releases/tag/v2",
                "https://github.com/o/r/releases/download/v2/app.bin?token=secret",
                "https://github.com/o/r/releases/download/v2/app.bin#fragment",
                "https://github.com:444/o/r/releases/download/v2/app.bin",
                "https://github.com/o/r/releases/download/v2/app%0Abin"]
        for url in urls:
            with self.subTest(url=url), self.assertRaises(release.ReleaseError):
                release.validate_manifest(encoded({**self.manifest, "url": url}))

    def test_missing_required_field(self):
        for field in release.EXPECTED:
            data = copy.copy(self.manifest)
            del data[field]
            with self.subTest(field=field), self.assertRaisesRegex(release.ReleaseError, "FIELDS"):
                release.validate_manifest(encoded(data))

    def test_oversized_manifest_and_invalid_utf8(self):
        for raw in (b"x" * 4097, b"\xff", b"[]", b"null", b'{"size":NaN}'):
            with self.subTest(raw=raw[:20]), self.assertRaises(release.ReleaseError):
                release.validate_manifest(raw)

    def test_stale_version_rejected(self):
        for current in (2, 3):
            with self.subTest(current=current), self.assertRaisesRegex(release.ReleaseError, "VERSION"):
                release.validate_manifest(encoded(self.manifest), current_version_code=current)

    def test_image_corruption_or_length(self):
        changed = bytearray(self.image)
        changed[-1] ^= 1
        for image in (self.image[:-1], self.image + b"x", bytes(changed)):
            with self.subTest(size=len(image)), self.assertRaises(release.ReleaseError):
                release.verify_image(image, self.manifest)

    def test_descriptor_version_conflict(self):
        value = {**self.manifest, "version": "3.0.0"}
        with self.assertRaisesRegex(release.ReleaseError, "DESCRIPTOR"):
            release.verify_image(self.image, value)

    def test_wrong_chip_or_project_even_when_hash_matches(self):
        image = bytearray(self.image)
        struct.pack_into("<H", image, 12, 0)
        data = {**self.manifest, "sha256": hashlib.sha256(image).hexdigest()}
        with self.assertRaisesRegex(release.ReleaseError, "TARGET"):
            release.verify_image(bytes(image), data)
        image = bytearray(self.image)
        project = b"unrelated_product"
        image[80:112] = project + bytes(32 - len(project))
        data = {**self.manifest, "sha256": hashlib.sha256(image).hexdigest()}
        with self.assertRaisesRegex(release.ReleaseError, "PROJECT"):
            release.verify_image(bytes(image), data)

    def test_string_bounds(self):
        for field, value in (("version", "x" * 32), ("release", "x" * 64), ("version", "2.0.0\n"),
                             ("release", ""), ("url", "x" * 513)):
            with self.subTest(field=field), self.assertRaises(release.ReleaseError):
                release.validate_manifest(encoded({**self.manifest, field: value}))

    def test_der_and_pem_public_import(self):
        with tempfile.TemporaryDirectory() as directory:
            for fmt in (serialization.Encoding.PEM, serialization.Encoding.DER):
                public_format = (serialization.PublicFormat.SubjectPublicKeyInfo if fmt == serialization.Encoding.PEM
                                 else serialization.PublicFormat.PKCS1)
                path = Path(directory) / "key"
                path.write_bytes(self.key.public_key().public_bytes(fmt, public_format))
                self.assertEqual(release.load_public(path).key_size, 3072)


if __name__ == "__main__":
    unittest.main(verbosity=2)
