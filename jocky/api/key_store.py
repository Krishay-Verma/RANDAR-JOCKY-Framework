"""
In-process public key store for the JOCKY API.

Investigators register their RSA public key once per session. The server
holds it in memory only — it is never written to disk or the database,
so a database breach cannot expose investigator public keys.

In a production multi-operator deployment this would be backed by a
proper key-management service. For this prototype, one active key per
process is sufficient.

Threat surface closed:
  - Public keys are validated on registration, not at encryption time
  - Key size minimum enforced (2048-bit floor)
  - No key material ever written to SQLite or log output
"""

import threading
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from jocky.reports.encryptor import load_public_key_pem

# One lock + one key slot. Thread-safe for the synchronous FastAPI model.
_lock = threading.Lock()
_active_key: Optional[RSAPublicKey] = None


def register_key(pem: bytes) -> None:
    """
    Validate and store a PEM-encoded RSA public key.

    Raises ValueError (from load_public_key_pem) if the key is invalid.
    Replaces any previously registered key.
    """
    key = load_public_key_pem(pem)
    with _lock:
        global _active_key
        _active_key = key


def get_active_key() -> Optional[RSAPublicKey]:
    """Return the currently registered public key, or None."""
    with _lock:
        return _active_key


def has_active_key() -> bool:
    """True if an investigator key is registered."""
    with _lock:
        return _active_key is not None


def clear_key() -> None:
    """Deregister the current key. Call on session end."""
    with _lock:
        global _active_key
        _active_key = None