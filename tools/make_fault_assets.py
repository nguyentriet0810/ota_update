"""Prepare a signed local-TLS fault fixture that deliberately cannot activate."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import release


def create(args):
    version_code = getattr(args, 'version_code', 6)
    if not 1 <= version_code <= 2147483647:
        raise release.ReleaseError('VERSION_CODE_BOUNDS')
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
        raise release.ReleaseError("SOURCE_COMMIT_REQUIRED")
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise release.ReleaseError("OUTPUT_NOT_EMPTY")
    image = args.image.read_bytes()
    descriptor = release.image_descriptor(image)
    release.verify_native(args.image, args.app_public_key)
    if descriptor["version"] == "9.9.9":
        raise release.ReleaseError("fixture must deliberately mismatch version9.9.9")
    private = serialization.load_pem_private_key(args.manifest_key.read_bytes(), None)
    if not isinstance(private, rsa.RSAPrivateKey) or private.key_size != 3072:
        raise release.ReleaseError("MANIFEST_KEY_NOT_RSA3072")
    manifest = {**release.PROFILE, "release": "lab-fault-v6", "version": "9.9.9",
                "version_code": version_code, "secure_version": 0, "config_schema": 2,
                "min_updater_version": 1, "size": len(image),
                "sha256": hashlib.sha256(image).hexdigest(),
                "url": "https://192.168.137.1:8443/releases/download/lab-fault-v6/app.bin"}
    # Host production validator must still reject this local URL. Its clone with
    # a GitHub origin proves all remaining production schema/type/bounds checks.
    clone = {**manifest, "url": "https://github.com/nguyentriet0810/ota_update/releases/download/lab-fault-v6/app.bin"}
    release.validate_manifest(json.dumps(clone).encode())
    try:
        release.validate_manifest(json.dumps(manifest).encode())
    except release.ReleaseError as exc:
        if str(exc) != "URL_POLICY":
            raise
    else:
        raise release.ReleaseError("PRODUCTION_URL_POLICY_UNEXPECTEDLY_ACCEPTS_LOCAL_HOST")
    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    signature = private.sign(raw, release.PSS, hashes.SHA256())
    private.public_key().verify(signature, raw, release.PSS, hashes.SHA256())
    output.mkdir(parents=True, exist_ok=True)
    (output / "app.bin").write_bytes(image)
    (output / "manifest.json").write_bytes(raw)
    (output / "manifest.sig").write_bytes(signature)
    report = {"purpose": "isolated fault-profile only", "activation_expected": "REJECT_DESCRIPTOR_VERSION",
              "native_image_version": descriptor["version"], "manifest_version": "9.9.9",
              "version_code": version_code, "config_schema": 2, "size": len(image),
              "file_sha256": manifest["sha256"], "release_id": hashlib.sha256(raw).hexdigest(),
              "manifest_url": "https://192.168.137.1:8443/releases/download/lab-fault-v6/manifest.json",
              "signature_url": "https://192.168.137.1:8443/releases/download/lab-fault-v6/manifest.sig",
              "source_commit": args.source_commit,
              "native_host_verification": "PASS", "raw_manifest_signature_host": "PASS",
              "production_local_url_policy": "REJECT_AS_EXPECTED",
              "safety_guard": "manifest version differs from native app descriptor",
              "endpoint_pairs": {
                  "trusted_ip": {"manifest_url": "https://192.168.137.1:8443/releases/download/lab-fault-v6/manifest.json",
                                 "signature_url": "https://192.168.137.1:8443/releases/download/lab-fault-v6/manifest.sig"},
                  "untrusted_ca": {"manifest_url": "https://192.168.137.1:8444/releases/download/lab-fault-v6/manifest.json",
                                   "signature_url": "https://192.168.137.1:8443/releases/download/lab-fault-v6/manifest.sig"},
                  "trusted_wrong_hostname": {"manifest_url": "https://192.168.137.1:8445/releases/download/lab-fault-v6/manifest.json",
                                             "signature_url": "https://192.168.137.1:8443/releases/download/lab-fault-v6/manifest.sig"}},
              "asset_hashes": {path.name: {"size": path.stat().st_size,
                                           "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                               for path in sorted(output.iterdir()) if path.is_file()},
              "board_result": "NOT RUN"}
    (output / "index.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("image", "manifest-key", "app-public-key", "output"):
        parser.add_argument("--" + option, type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--version-code", type=int, default=6,
                        help="Must exceed the compiled policy code of the test profile")
    args = parser.parse_args()
    try:
        print(json.dumps(create(args), indent=2))
    except (OSError, ValueError) as exc:
        parser.exit(1, f"REJECT: {exc}\n")


if __name__ == "__main__":
    main()
