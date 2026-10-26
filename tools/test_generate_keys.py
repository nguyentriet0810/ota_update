"""Key custody tests use fresh temporary paths and never touch provisioned keys."""
import hashlib
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization

import generate_keys


class KeyGenerationTests(unittest.TestCase):
    def test_private_outside_project_and_no_implicit_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            private = base / "private"
            project = base / "project"
            public = project / "docs" / "public-keys"
            embedded = project / "main" / "manifest_public.der"
            fingerprints = generate_keys.generate(private, public, embedded)
            first = (private / "app-signing.pem").read_bytes()
            self.assertEqual(serialization.load_pem_private_key(first, None).key_size, 3072)
            self.assertEqual(fingerprints["manifest_public_pkcs1_der_sha256"],
                             hashlib.sha256(embedded.read_bytes()).hexdigest())
            self.assertEqual(embedded.read_bytes(), (public / "manifest-public.der").read_bytes())
            with self.assertRaisesRegex(ValueError, "refusing overwrite"):
                generate_keys.generate(private, public, embedded)
            self.assertEqual(first, (private / "app-signing.pem").read_bytes())
            with self.assertRaisesRegex(ValueError, "outside"):
                generate_keys.generate(project / "secrets", public, embedded)


if __name__ == "__main__":
    unittest.main(verbosity=2)
