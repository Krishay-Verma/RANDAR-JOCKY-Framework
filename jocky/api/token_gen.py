"""
Bearer token generator for the JOCKY API.

Usage:
    python -m jocky.api.token_gen

Generates a cryptographically random URL-safe token (256 bits of entropy)
and prints its SHA-256 digest to add to your .env file.

The plaintext token is displayed ONCE. Store it in a password manager.
Never commit the plaintext token — only the digest goes in .env.
"""

import hashlib
import secrets
import sys


def generate() -> tuple[str, str]:
    """
    Return (plaintext_token, sha256_hex_digest).

    32 bytes = 256 bits from the OS CSPRNG. URL-safe base64 encoding
    gives ~43 characters with no padding ambiguity.
    """
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, digest


def main() -> None:
    token, digest = generate()
    separator = "─" * 60
    print(separator)
    print("JOCKY API Token")
    print(separator)
    print()
    print("Bearer token  (store in password manager — shown only once)")
    print(f"  {token}")
    print()
    print("Add this line to your .env file")
    print(f"  JOCKY_API_TOKEN_HASH={digest}")
    print()
    print(separator)
    print("WARNING: If you lose the bearer token, generate a new one.")
    print("The server only stores the hash and cannot reverse it.")
    print(separator)


if __name__ == "__main__":
    main()
    sys.exit(0)