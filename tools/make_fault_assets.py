"""Prepare a signed local-TLS fault fixture that deliberately cannot activate."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import release


def create(args):
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
                "version_code": 6, "secure_version": 0, "config_schema": 2,
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
              "version_code": 6, "config_schema": 2, "size": len(image),
              "file_sha256": manifest["sha256"], "release_id": hashlib.sha256(raw).hexdigest(),
              "manifest_url": "https://192.168.137.1:8443/releases/download/lab-fault-v6/manifest.json",
              "signature_url": "https://192.168.137.1:8443/releases/download/lab-fault-v6/manifest.sig",
              "native_host_verification": "PASS", "board_result": "NOT RUN"}
    (output / "index.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("image", "manifest-key", "app-public-key", "output"):
        parser.add_argument("--" + option, type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(create(args), indent=2))
    except (OSError, ValueError) as exc:
        parser.exit(1, f"REJECT: {exc}\n")


if __name__ == "__main__":
    main()
