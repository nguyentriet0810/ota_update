"""Package and verify E03/E08 raw-byte signed OTA releases. Requires cryptography."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

MAX_MANIFEST = 4096
MAX_IMAGE = 0x300000
PROJECT_NAME = "studybook_ota_lab"
EXPECTED = {"schema_version", "product", "board", "chip", "layout_id", "release",
            "version", "version_code", "secure_version", "config_schema",
            "min_updater_version", "manifest_key_id", "size", "sha256", "url"}
PROFILE = {"schema_version": 1, "product": "esp32s3-ota-lab",
           "board": "esp32s3-n16r8-lab", "chip": "esp32s3",
           "layout_id": "s3-16m-2x3m-v1", "manifest_key_id": "manifest-1"}
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


class ReleaseError(ValueError):
    """Fail-closed release validation error."""


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError(f"DUPLICATE_KEY:{key}")
        result[key] = value
    return result


def _integer(data: dict, name: str, low: int, high: int) -> None:
    value = data[name]
    if type(value) is not int or not low <= value <= high:
        raise ReleaseError(f"INTEGER_BOUND:{name}")


def _ascii(value, name: str, limit: int) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > limit:
        raise ReleaseError(f"STRING_BOUND:{name}")
    if any(ord(char) < 0x21 or ord(char) > 0x7E for char in value):
        raise ReleaseError(f"STRING_CHAR:{name}")
    return value


def validate_manifest(raw: bytes, *, current_version_code: int | None = None) -> dict:
    """Structural/policy check only; callers must verify authenticity before parsing."""
    if not 0 < len(raw) <= MAX_MANIFEST:
        raise ReleaseError("MANIFEST_BOUND")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ReleaseError("NONFINITE")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("JSON_UTF8") from exc
    if not isinstance(data, dict) or set(data) != EXPECTED:
        raise ReleaseError("MANIFEST_FIELDS")
    _integer(data, "schema_version", 1, 1)
    for name, expected in PROFILE.items():
        if data[name] != expected:
            raise ReleaseError(f"PROFILE:{name}")
    for name, low, high in (("version_code", 1, 0x7FFFFFFF), ("secure_version", 0, 0),
                             ("config_schema", 1, 2), ("min_updater_version", 1, 1),
                             ("size", 1, MAX_IMAGE)):
        _integer(data, name, low, high)
    _ascii(data["release"], "release", 63)
    _ascii(data["version"], "version", 31)
    if not isinstance(data["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", data["sha256"]):
        raise ReleaseError("DIGEST_FORMAT")
    url = _ascii(data["url"], "url", 512)
    try:
        split = urlsplit(url)
        port = split.port
    except ValueError as exc:
        raise ReleaseError("URL") from exc
    if (split.scheme != "https" or split.hostname != "github.com" or port not in (None, 443)
            or split.username is not None or split.password is not None or split.query or split.fragment
            or not re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/download/[^/]+/[^/]+", split.path)
            or "%0" in url.lower()):
        raise ReleaseError("URL_POLICY")
    if current_version_code is not None and data["version_code"] <= current_version_code:
        raise ReleaseError("VERSION_NOT_NEWER")
    return data


def load_public(path: Path):
    raw = path.read_bytes()
    try:
        key = serialization.load_pem_public_key(raw) if raw.startswith(b"-----") else serialization.load_der_public_key(raw)
    except ValueError as exc:
        raise ReleaseError("PUBLIC_KEY") from exc
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 3072:
        raise ReleaseError("KEY_NOT_RSA3072")
    return key


def verify_manifest(raw: bytes, signature: bytes, public_key, **policy) -> dict:
    if not 0 < len(raw) <= MAX_MANIFEST or len(signature) != 384:
        raise ReleaseError("AUTH_BOUND")
    try:
        public_key.verify(signature, raw, PSS, hashes.SHA256())
    except InvalidSignature as exc:
        raise ReleaseError("MANIFEST_SIGNATURE") from exc
    return validate_manifest(raw, **policy)


def image_descriptor(image: bytes) -> dict:
    """Read fixed ESP image header + first-segment esp_app_desc (not a signature check)."""
    if not 256 <= len(image) <= MAX_IMAGE or image[0] != 0xE9:
        raise ReleaseError("APP_IMAGE_FORMAT")
    chip_id = struct.unpack_from("<H", image, 12)[0]
    magic, secure_version = struct.unpack_from("<II", image, 32)
    if chip_id != 9 or magic != 0xABCD5432:
        raise ReleaseError("APP_IMAGE_TARGET_OR_DESCRIPTOR")
    def cstring(offset):
        field = image[offset:offset + 32]
        if b"\0" not in field:
            raise ReleaseError("APP_DESCRIPTOR_STRING")
        try:
            return field.split(b"\0", 1)[0].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ReleaseError("APP_DESCRIPTOR_STRING") from exc
    descriptor = {"version": cstring(48), "project_name": cstring(80),
                  "secure_version": secure_version, "chip_id": chip_id}
    if descriptor["project_name"] != PROJECT_NAME:
        raise ReleaseError("APP_PROJECT_POLICY")
    return descriptor


def verify_image(image: bytes, manifest: dict) -> dict:
    if len(image) != manifest["size"]:
        raise ReleaseError("IMAGE_LENGTH")
    if hashlib.sha256(image).hexdigest() != manifest["sha256"]:
        raise ReleaseError("IMAGE_DIGEST")
    desc = image_descriptor(image)
    if desc["version"] != manifest["version"] or desc["secure_version"] != manifest["secure_version"]:
        raise ReleaseError("DESCRIPTOR_POLICY")
    return desc


def verify_native(image_path: Path, public_path: Path, espsecure: Path | None = None) -> None:
    prefix = [sys.executable, str(espsecure)] if espsecure else [sys.executable, "-m", "espsecure"]
    result = subprocess.run(prefix + ["verify_signature", "--version", "2", "--keyfile",
                            str(public_path.resolve()), str(image_path.resolve())],
                            capture_output=True, text=True, check=False)
    if result.returncode:
        raise ReleaseError("NATIVE_APP_SIGNATURE:" + (result.stdout + result.stderr).strip())


def build_release(args) -> dict:
    image = args.image.read_bytes()
    desc = image_descriptor(image)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo):
        raise ReleaseError("REPO")
    if args.output.exists() and any(args.output.iterdir()):
        raise ReleaseError("OUTPUT_NOT_EMPTY")
    name = f"esp32s3-ota-lab-{args.release}.bin"
    data = {**PROFILE, "release": args.release, "version": desc["version"],
            "version_code": args.version_code, "secure_version": desc["secure_version"],
            "config_schema": args.config_schema, "min_updater_version": 1,
            "size": len(image), "sha256": hashlib.sha256(image).hexdigest(),
            "url": f"https://github.com/{args.repo}/releases/download/{quote(args.release, safe='')}/{quote(name, safe='')}"}
    raw = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    validate_manifest(raw)
    verify_native(args.image, args.app_public_key, args.espsecure)
    private = serialization.load_pem_private_key(args.manifest_key.read_bytes(), password=None)
    if not isinstance(private, rsa.RSAPrivateKey) or private.key_size != 3072:
        raise ReleaseError("KEY_NOT_RSA3072")
    signature = private.sign(raw, PSS, hashes.SHA256())
    verify_manifest(raw, signature, private.public_key())
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / name).write_bytes(image)
    (args.output / "manifest.json").write_bytes(raw)
    (args.output / "manifest.sig").write_bytes(signature)
    report = {"release_id": hashlib.sha256(raw).hexdigest(), "file_sha256": data["sha256"],
              "file_size": len(image), "version": desc["version"], "version_code": args.version_code,
              "config_schema": args.config_schema, "native_signature": "VERIFIED_HOST",
              "source_commit": args.source_commit, "asset_name": name}
    (args.output / "release-info.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    make = sub.add_parser("make")
    make.add_argument("--image", type=Path, required=True)
    make.add_argument("--manifest-key", type=Path, required=True)
    make.add_argument("--app-public-key", type=Path, required=True)
    make.add_argument("--repo", required=True)
    make.add_argument("--release", required=True)
    make.add_argument("--version-code", type=int, required=True)
    make.add_argument("--config-schema", type=int, choices=(1, 2), default=1)
    make.add_argument("--source-commit", required=True)
    make.add_argument("--output", type=Path, required=True)
    make.add_argument("--espsecure", type=Path)
    verify = sub.add_parser("verify")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--signature", type=Path, required=True)
    verify.add_argument("--manifest-public-key", type=Path, required=True)
    verify.add_argument("--image", type=Path, required=True)
    verify.add_argument("--app-public-key", type=Path, required=True)
    verify.add_argument("--current-version-code", type=int)
    verify.add_argument("--espsecure", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "make":
            result = build_release(args)
        else:
            raw = args.manifest.read_bytes()
            manifest = verify_manifest(raw, args.signature.read_bytes(), load_public(args.manifest_public_key),
                                       current_version_code=args.current_version_code)
            desc = verify_image(args.image.read_bytes(), manifest)
            verify_native(args.image, args.app_public_key, args.espsecure)
            result = {"result": "VERIFIED_HOST", "release_id": hashlib.sha256(raw).hexdigest(), **desc}
        print(json.dumps(result, indent=2))
    except (ReleaseError, OSError, ValueError) as exc:
        parser.exit(1, f"REJECT: {exc}\n")


if __name__ == "__main__":
    main()
