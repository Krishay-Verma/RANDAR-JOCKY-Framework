"""
RSA key pair generator for JOCKY investigators.

Usage:
    python -m jocky.api.key_gen

Generates an RSA-2048 key pair and writes:
  - jocky_investigator.key  (private key — keep secret, never upload)
  - jocky_investigator.pub  (public key — register with the API)

Security notes:
  - Private key is written with mode 0o600 on POSIX systems.
  - On Windows, restrict access manually via file properties.
  - Never upload the .key file anywhere.
"""

import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_key_pair(
    private_path: Path,
    public_path: Path,
) -> None:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)

    # Restrict private key permissions on POSIX.
    if os.name != "nt":
        os.chmod(private_path, 0o600)

    separator = "─" * 60
    print(separator)
    print("JOCKY Investigator Key Pair")
    print(separator)
    print()
    print(f"Private key  →  {private_path}")
    print("  Keep this secret. Never upload it.")
    print()
    print(f"Public key   →  {public_path}")
    print("  Register this with the API via POST /api/keys/register")
    print()
    print(separator)


def main() -> None:
    private_path = Path("jocky_investigator.key")
    public_path = Path("jocky_investigator.pub")

    if private_path.exists() or public_path.exists():
        print("Key files already exist. Delete them first to regenerate.")
        sys.exit(1)

    generate_key_pair(private_path, public_path)


if __name__ == "__main__":
    main()