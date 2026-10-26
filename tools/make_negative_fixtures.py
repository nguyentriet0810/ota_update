"""Make deliberately invalid authenticated metadata fixtures for E03/E08 tests."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import release


def create(source: Path, output: Path, private_path: Path) -> list[dict]:
    if output.exists() and any(output.iterdir()):
        raise release.ReleaseError("fixture output must be empty")
    raw = source.read_bytes()
    original = release.validate_manifest(raw)
    key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 3072:
        raise release.ReleaseError("manifest key must be RSA3072")
    cases = []
    def save(name, data, reason, *, signature=None):
        folder = output / name
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "manifest.json").write_bytes(data)
        (folder / "manifest.sig").write_bytes(signature or key.sign(data, release.PSS, hashes.SHA256()))
        cases.append({"fixture": name, "expected": "REJECT", "reason": reason,
                      "scope": "metadata", "result_on_board": "NOT RUN"})
    for name, field, value, reason in (
        ("A01-wrong-board", "board", "esp32-wrong-board", "PROFILE:board"),
        ("A01-wrong-chip", "chip", "esp32", "PROFILE:chip"),
        ("A01-wrong-layout", "layout_id", "s3-8m-other", "PROFILE:layout_id"),
        ("A02-negative-size", "size", -1, "INTEGER_BOUND:size"),
        ("A02-fraction-size", "size", 4.5, "INTEGER_BOUND:size"),
        ("A02-oversize", "size", release.MAX_IMAGE + 1, "INTEGER_BOUND:size"),
        ("A06-version-conflict", "version", "9.9.9", "DESCRIPTOR_POLICY after download"),
        ("A08-unknown-schema", "schema_version", 2, "INTEGER_BOUND:schema_version")):
        data = {**original, field: value}
        save(name, json.dumps(data, sort_keys=True, separators=(",", ":")).encode(), reason)
    signature = key.sign(raw, release.PSS, hashes.SHA256())
    save("A03-raw-newline-tamper", raw + b"\n", "MANIFEST_SIGNATURE", signature=signature)
    bad_signature = bytearray(signature)
    bad_signature[0] ^= 1
    save("A03-signature-bitflip", raw, "MANIFEST_SIGNATURE", signature=bytes(bad_signature))
    save("A08-duplicate-size", raw[:-1] + b',"size":17}', "DUPLICATE_KEY:size")
    save("A08-unknown-field", raw[:-1] + b',"unexpected":true}', "MANIFEST_FIELDS")
    (output / "fixture-index.json").write_text(json.dumps(cases, indent=2) + "\n", encoding="utf-8")
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(create(args.manifest, args.output, args.manifest_key), indent=2))
    except (OSError, ValueError) as exc:
        parser.exit(1, f"REJECT: {exc}\n")


if __name__ == "__main__":
    main()
