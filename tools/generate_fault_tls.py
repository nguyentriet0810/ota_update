"""Create isolated lab TLS fixtures; private material stays outside public source."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def generate(private_dir: Path, public_ca: Path):
    private_dir = private_dir.resolve()
    public_ca = public_ca.resolve()
    if private_dir == public_ca.parent or public_ca.parent in private_dir.parents:
        raise ValueError("private TLS directory must be outside public source")
    private_dir.mkdir(parents=True, exist_ok=True)
    names = ["ca.key.pem", "ca.cert.pem", "good.key.pem", "good.cert.pem", "good.chain.pem",
             "untrusted.key.pem", "untrusted.cert.pem", "wrong-host.key.pem", "wrong-host.cert.pem", "wrong-host.chain.pem"]
    if any((private_dir / name).exists() for name in names) or public_ca.exists():
        raise ValueError("refusing to overwrite existing lab TLS trust material")
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    end = datetime(2036, 1, 1, tzinfo=timezone.utc)
    def key():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    def save_key(name, value):
        with (private_dir / f"{name}.key.pem").open("xb") as handle:
            handle.write(value.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    ca_key = key()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "StudyBook OTA isolated lab CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(start).not_valid_after(end)
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
              data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
              encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    save_key("ca", ca_key)
    ca_pem = ca.public_bytes(serialization.Encoding.PEM)
    (private_dir / "ca.cert.pem").write_bytes(ca_pem)
    for name, common, san, trusted in (
        ("good", "192.168.137.1", x509.IPAddress(ip_address("192.168.137.1")), True),
        ("wrong-host", "wrong.lab.invalid", x509.DNSName("wrong.lab.invalid"), True),
        ("untrusted", "Untrusted lab self-signed", x509.IPAddress(ip_address("192.168.137.1")), False)):
        leaf_key = key()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])
        leaf = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name if trusted else subject)
                .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(start).not_valid_after(end)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName([san]), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
                    data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False), critical=True)
                .sign(ca_key if trusted else leaf_key, hashes.SHA256()))
        save_key(name, leaf_key)
        pem = leaf.public_bytes(serialization.Encoding.PEM)
        (private_dir / f"{name}.cert.pem").write_bytes(pem)
        if trusted:
            (private_dir / f"{name}.chain.pem").write_bytes(pem + ca_pem)
    public_ca.parent.mkdir(parents=True, exist_ok=True)
    public_ca.write_bytes(ca_pem)
    return {"public_ca": str(public_ca), "ca_cert_der_sha256": hashlib.sha256(ca.public_bytes(serialization.Encoding.DER)).hexdigest(),
            "valid_from": "2026-01-01", "valid_until": "2036-01-01", "good": "192.168.137.1:8443",
            "untrusted": "192.168.137.1:8444", "trusted_wrong_hostname": "192.168.137.1:8445"}


def main():
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-dir", type=Path, required=True)
    parser.add_argument("--public-ca", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(generate(args.private_dir, args.public_ca), indent=2))
    except (OSError, ValueError) as exc:
        parser.exit(1, f"REJECT: {exc}\n")


if __name__ == "__main__":
    main()
