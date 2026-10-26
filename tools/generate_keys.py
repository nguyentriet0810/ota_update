"""Generate separate disposable lab keys; never place private keys in the project."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate(private_dir: Path, public_dir: Path, embedded_der: Path, *, rotate: bool = False) -> dict:
    private_dir = private_dir.resolve()
    public_dir = public_dir.resolve()
    project_root = embedded_der.resolve().parent.parent
    if private_dir == public_dir or public_dir in private_dir.parents or private_dir == project_root or project_root in private_dir.parents:
        raise ValueError("private keys must be outside the public project")
    private_paths = [private_dir / f"{name}-signing.pem" for name in ("manifest", "app")]
    existing_public = any((public_dir / f"{name}-public.pem").exists() for name in ("manifest", "app"))
    if (any(path.exists() for path in private_paths) or existing_public or embedded_der.exists()) and not rotate:
        raise ValueError("keys/public trust anchor already exist; refusing overwrite (explicit --rotate required)")
    private_dir.mkdir(parents=True, exist_ok=True)
    public_dir.mkdir(parents=True, exist_ok=True)
    if rotate:
        archive = private_dir / ("before-rotation-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
        for path in private_paths:
            if path.exists():
                archive.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, archive / path.name)
    fingerprints = {}
    for name in ("manifest", "app"):
        private_path = private_dir / f"{name}-signing.pem"
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        with private_path.open("wb" if rotate else "xb") as handle:
            handle.write(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
        public = key.public_key()
        der = public.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.PKCS1)
        pem = public.public_bytes(serialization.Encoding.PEM,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
        (public_dir / f"{name}-public.pem").write_bytes(pem)
        (public_dir / f"{name}-public.der").write_bytes(der)
        fingerprints[f"{name}_public_pkcs1_der_sha256"] = hashlib.sha256(der).hexdigest()
        if name == "manifest":
            embedded_der.parent.mkdir(parents=True, exist_ok=True)
            embedded_der.write_bytes(der)
    (public_dir / "fingerprints.json").write_text(
        json.dumps(fingerprints, indent=2) + "\n", encoding="utf-8")
    return fingerprints


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-dir", type=Path, required=True)
    parser.add_argument("--public-dir", type=Path, required=True)
    parser.add_argument("--embedded-der", type=Path, required=True)
    parser.add_argument("--rotate", action="store_true", help="Explicitly replace trust anchors; archive old private keys first")
    args = parser.parse_args()
    try:
        print(json.dumps(generate(args.private_dir, args.public_dir, args.embedded_der, rotate=args.rotate), indent=2))
    except (ValueError, OSError) as exc:
        parser.exit(1, f"REJECT: {exc}\n")


if __name__ == "__main__":
    main()
