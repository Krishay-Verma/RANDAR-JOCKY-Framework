"""
Report encryption for JOCKY.

Strategy: hybrid encryption.
  1. Generate a random 256-bit AES key.
  2. Encrypt the report with AES-256-GCM (authenticated encryption).
  3. Wrap the AES key with the investigator's RSA-2048 public key
     using OAEP+SHA-256 padding.

Only the holder of the matching RSA private key can unwrap the AES key
and therefore decrypt the report. The server never sees or stores the
private key.

Wire format (all concatenated, lengths are fixed):
  [12 bytes IV][16 bytes GCM tag][2 bytes wrapped-key length big-endian]
  [N bytes RSA-wrapped AES key][remaining bytes: ciphertext]

Threat surface closed:
  - Key and ciphertext no longer travel together unprotected
  - GCM tag prevents silent ciphertext tampering (AEAD)
  - OAEP padding closes RSA padding oracle attacks
  - SHA-256 in OAEP closes legacy SHA-1 weaknesses
"""

import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ── AES-GCM constants ──────────────────────────────────────────────────────────
_AES_KEY_BYTES = 32   # 256-bit key
_GCM_NONCE_BYTES = 12  # 96-bit nonce — GCM standard


def encrypt_report_for_key(
    plaintext: bytes,
    public_key: RSAPublicKey,
) -> bytes:
    """
    Encrypt `plaintext` for `public_key`.

    Returns the wire-format blob described in the module docstring.
    The AES key is never returned to the caller — it is wrapped inside
    the blob and recoverable only with the matching private key.
    """
    # 1. Fresh random AES key and nonce for every report.
    #    Never reuse a nonce with the same key under GCM.
    aes_key = os.urandom(_AES_KEY_BYTES)
    nonce = os.urandom(_GCM_NONCE_BYTES)

    # 2. Encrypt the report body.
    #    AESGCM.encrypt() appends the 16-byte GCM authentication tag
    #    to the ciphertext automatically.
    aesgcm = AESGCM(aes_key)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    # ct_and_tag = ciphertext || tag (tag is last 16 bytes)
    tag = ct_and_tag[-16:]
    ciphertext = ct_and_tag[:-16]

    # 3. Wrap the AES key with the investigator's RSA public key.
    wrapped_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 4. Pack into wire format.
    #    2-byte big-endian length prefix for the wrapped key so the
    #    decryptor knows exactly how many bytes to read.
    wrapped_key_len = struct.pack(">H", len(wrapped_key))

    return nonce + tag + wrapped_key_len + wrapped_key + ciphertext


def decrypt_report(blob: bytes, private_key_pem: bytes) -> bytes:
    """
    Decrypt a blob produced by encrypt_report_for_key().

    `private_key_pem` — PEM-encoded PKCS8 private key (no passphrase).

    Raises ValueError on any structural or cryptographic failure so the
    caller gets one clean error type regardless of failure mode.
    This prevents error-oracle attacks where different exceptions leak
    information about which stage failed.
    """
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem, password=None
        )
        if not isinstance(private_key, RSAPrivateKey):
            raise ValueError("Key is not an RSA private key.")

        # Unpack wire format.
        offset = 0
        nonce = blob[offset: offset + _GCM_NONCE_BYTES]
        offset += _GCM_NONCE_BYTES

        tag = blob[offset: offset + 16]
        offset += 16

        (wrapped_key_len,) = struct.unpack(">H", blob[offset: offset + 2])
        offset += 2

        wrapped_key = blob[offset: offset + wrapped_key_len]
        offset += wrapped_key_len

        ciphertext = blob[offset:]

        # Unwrap the AES key.
        aes_key = private_key.decrypt(
            wrapped_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Decrypt and verify the GCM tag.
        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(nonce, ciphertext + tag, associated_data=None)

    except Exception as exc:
        # Collapse all failure modes into one type.
        raise ValueError(f"Decryption failed: {exc}") from exc


def load_public_key_pem(pem: bytes) -> RSAPublicKey:
    """
    Load and validate a PEM-encoded RSA public key.

    Raises ValueError if the PEM is malformed or not an RSA key.
    """
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey as _RSAPub

    try:
        key = serialization.load_pem_public_key(pem)
    except Exception as exc:
        raise ValueError(f"Invalid public key PEM: {exc}") from exc

    if not isinstance(key, _RSAPub):
        raise ValueError("Public key is not an RSA key.")

    key_size = key.key_size
    if key_size < 2048:
        raise ValueError(
            f"RSA key too small ({key_size} bits). Minimum 2048 required."
        )

    return key
