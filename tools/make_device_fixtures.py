"""Prepare deliberately invalid GitHub OTA assets; never publishes or opens COM."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import release


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def create(args):
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise release.ReleaseError("OUTPUT_NOT_EMPTY")
    original_raw = args.manifest.read_bytes()
    original = release.validate_manifest(original_raw)
    signed_image = args.signed_image.read_bytes()
    release.verify_image(signed_image, original)
    release.verify_native(args.signed_image, args.app_public_key)
    manifest_key = serialization.load_pem_private_key(args.manifest_key.read_bytes(), None)
    if not isinstance(manifest_key, rsa.RSAPrivateKey) or manifest_key.key_size != 3072:
        raise release.ReleaseError("MANIFEST_KEY_NOT_RSA3072")
    output.mkdir(parents=True)
    base = f"https://github.com/{args.repo}/releases/download/{args.tag}"
    entries = []

    def save(name, data, test_id, gate, allow_writer, *, signature=None, image_name=None):
        raw = data if isinstance(data, bytes) else encode(data)
        if len(raw) > release.MAX_MANIFEST:
            raise release.ReleaseError("FIXTURE_TOO_LARGE")
        signature = signature if signature is not None else manifest_key.sign(raw, release.PSS, hashes.SHA256())
        (output / f"{name}.json").write_bytes(raw)
        (output / f"{name}.sig").write_bytes(signature)
        assets = [f"{name}.json", f"{name}.sig"] + ([image_name] if image_name else [])
        entry = {"name": name, "test_id": test_id, "expectedgate": gate,
                 "manifest_url": f"{base}/{name}.json", "signature_url": f"{base}/{name}.sig",
                 "allow_writer": allow_writer, "assetnames": assets, "result_on_board": "NOT RUN"}
        entries.append(entry)

    for name, field, value, test_id, gate, writes in (
        ("A01-wrong-board", "board", "esp32-wrong-board", "A01", "manifest compatibility before erase", False),
        ("A01-wrong-chip", "chip", "esp32", "A01", "manifest compatibility before erase", False),
        ("A01-wrong-layout", "layout_id", "s3-8m-other", "A01", "manifest compatibility before erase", False),
        ("A02-negative-size", "size", -1, "A02", "manifest integer bound before erase", False),
        ("A02-fraction-size", "size", 4.5, "A02", "manifest integer type before erase", False),
        ("A02-oversize", "size", release.MAX_IMAGE + 1, "A02", "manifest slot bound before erase", False),
        ("A06-version-conflict", "version", "9.9.9", "A06", "file descriptor differs from authenticated manifest", True),
        ("A08-unknown-schema", "schema_version", 2, "A08", "manifest schema before erase", False)):
        save(name, {**original, field: value}, test_id, gate, writes)
    original_signature = manifest_key.sign(original_raw, release.PSS, hashes.SHA256())
    save("A03-raw-newline-tamper", original_raw + b"\n", "A03", "raw manifest signature before parse", False,
         signature=original_signature)
    bad_signature = bytearray(original_signature)
    bad_signature[0] ^= 1
    save("A03-signature-bitflip", original_raw, "A03", "raw manifest signature before parse", False,
         signature=bytes(bad_signature))
    save("A08-duplicate-size", original_raw[:-1] + b',"size":17}', "A08", "duplicate key before erase", False)
    save("A08-unknown-field", original_raw[:-1] + b',"unexpected":true}', "A08", "unknown field before erase", False)

    def asset_manifest(name, image, *, expected_original=False):
        image_name = f"{name}.bin"
        (output / image_name).write_bytes(image)
        data = {**original, "url": f"{base}/{image_name}"}
        if not expected_original:
            data["size"] = len(image)
            data["sha256"] = hashlib.sha256(image).hexdigest()
        release.validate_manifest(encode(data))
        return data, image_name

    unsigned = args.unsigned_image.read_bytes()
    release.image_descriptor(unsigned)
    data, name = asset_manifest("A04-unsigned-native", unsigned)
    save("A04-unsigned-native", data, "A04", "SDK native app signature validation", True, image_name=name)
    try:
        release.verify_native(output / name, args.app_public_key)
    except release.ReleaseError:
        pass
    else:
        raise release.ReleaseError("UNSIGNED_FIXTURE_UNEXPECTEDLY_VERIFIES")

    wrong_key_path = args.wrong_app_key.resolve()
    if output == wrong_key_path.parent or output in wrong_key_path.parents:
        raise release.ReleaseError("WRONG_KEY_MUST_BE_PRIVATE_OUTSIDE_ASSETS")
    wrong_key_path.parent.mkdir(parents=True, exist_ok=True)
    if wrong_key_path.exists():
        wrong = serialization.load_pem_private_key(wrong_key_path.read_bytes(), None)
        if not isinstance(wrong, rsa.RSAPrivateKey) or wrong.key_size != 3072:
            raise release.ReleaseError("WRONG_FIXTURE_KEY_INVALID")
    else:
        wrong = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        with wrong_key_path.open("xb") as handle:
            handle.write(wrong.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    wrong_path = output / "A04-wrong-native-key.bin"
    result = subprocess.run([sys.executable, "-m", "espsecure", "sign-data", "--version", "2", "--keyfile",
                             str(wrong_key_path), "--output", str(wrong_path), str(args.unsigned_image.resolve())],
                            check=False, capture_output=True, text=True)
    if result.returncode:
        raise release.ReleaseError("WRONG_KEY_SIGN_FAILED:" + result.stdout + result.stderr)
    data, name = asset_manifest("A04-wrong-native-key", wrong_path.read_bytes())
    save("A04-wrong-native-key", data, "A04", "SDK native app trusted-key mismatch", True, image_name=name)
    try:
        release.verify_native(wrong_path, args.app_public_key)
    except release.ReleaseError:
        pass
    else:
        raise release.ReleaseError("WRONG_KEY_FIXTURE_UNEXPECTEDLY_VERIFIES")

    # Change an unused trailing byte of the signature sector, outside its CRC/
    # signature block. Native signature stays valid; final full-file hash must fail.
    tampered = bytearray(signed_image)
    tampered[-1] ^= 1
    data, name = asset_manifest("A05-final-file-digest", bytes(tampered), expected_original=True)
    release.verify_native(output / name, args.app_public_key)
    save("A05-final-file-digest", data, "A05", "VERIFY_FILE full signed-file SHA256 mismatch", True, image_name=name)

    data, name = asset_manifest("A07-truncated-file", signed_image[:-4096], expected_original=True)
    save("A07-truncated-file", data, "A07", "HTTP length contract before writer", False, image_name=name)
    index = {"fixture_release_tag": args.tag, "repo": args.repo, "source_release": original["release"],
             "source_version_code": original["version_code"], "fixtures": entries,
             "asset_hashes": {path.name: {"size": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                              for path in sorted(output.iterdir()) if path.is_file()}}
    (output / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    return index


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("manifest", "signed-image", "unsigned-image", "manifest-key", "app-public-key", "wrong-app-key", "output"):
        parser.add_argument("--" + option, type=Path, required=True)
    parser.add_argument("--repo", default="nguyentriet0810/ota_update")
    parser.add_argument("--tag", default="lab-negative-v2")
    args = parser.parse_args()
    try:
        index = create(args)
        print(json.dumps({"output": str(args.output.resolve()), "fixtures": len(index["fixtures"]),
                          "assets": len(index["asset_hashes"]) + 1, "result_on_board": "NOT RUN"}, indent=2))
    except (OSError, ValueError) as exc:
        parser.exit(1, f"REJECT: {exc}\n")


if __name__ == "__main__":
    main()
