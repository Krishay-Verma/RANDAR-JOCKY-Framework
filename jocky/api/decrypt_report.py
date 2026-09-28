"""
CLI decryption tool for JOCKY encrypted reports.

Usage:
    python -m jocky.api.decrypt_report \\
        --key jocky_investigator.key \\
        --input jocky_report_1.enc \\
        --output jocky_report_1.json
"""

import argparse
import sys
from pathlib import Path

from jocky.reports.encryptor import decrypt_report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Decrypt a JOCKY encrypted report."
    )
    parser.add_argument(
        "--key", required=True,
        help="Path to the RSA private key file (jocky_investigator.key)",
    )
    parser.add_argument(
        "--input", required=True,
        help="Path to the encrypted report file (.enc)",
    )
    parser.add_argument(
        "--output", required=True,
        help="Path to write the decrypted JSON report",
    )
    args = parser.parse_args()

    key_path = Path(args.key)
    input_path = Path(args.input)
    output_path = Path(args.output)

    if not key_path.exists():
        print(f"Error: private key not found: {key_path}", file=sys.stderr)
        sys.exit(1)

    if not input_path.exists():
        print(f"Error: encrypted report not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    try:
        plaintext = decrypt_report(
            blob=input_path.read_bytes(),
            private_key_pem=key_path.read_bytes(),
        )
    except ValueError as exc:
        print(f"Decryption failed: {exc}", file=sys.stderr)
        sys.exit(1)

    output_path.write_bytes(plaintext)
    print(f"Decrypted report written to: {output_path}")


if __name__ == "__main__":
    main()