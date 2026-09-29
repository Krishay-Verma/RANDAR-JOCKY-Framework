"""
Authentication for the JOCKY API.

Strategy: single-operator bearer token. The server never stores the
plaintext token — only its SHA-256 digest lives in the environment.
All comparisons use hmac.compare_digest to close timing-oracle attacks.

Threat surface closed:
  - Unauthenticated access to investigation routes
  - Timing-based token enumeration
  - Plaintext credentials in configuration
  - Silent auth bypass when env var is missing
"""

import hashlib
import hmac
import os
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# Environment variable that holds the SHA-256 hex digest of the bearer token.
# The plaintext token is NEVER stored anywhere — only this digest.
_TOKEN_DIGEST_ENV = "RANDAR_API_TOKEN_HASH"
_TOKEN_DIGEST_LEGACY_ENV = "JOCKY_API_TOKEN_HASH"

# Reusable scheme instance. auto_error=False so we can return a clean 401
# rather than FastAPI's default 403 when the header is absent entirely.
_bearer = HTTPBearer(auto_error=False)


def _load_expected_digest() -> str:
    """
    Load the token digest from the environment.

    Raises RuntimeError (not HTTPException) so the server startup check
    can catch it and abort before binding to a port.
    """
    digest = os.environ.get(_TOKEN_DIGEST_ENV, os.environ.get(_TOKEN_DIGEST_LEGACY_ENV, "")).strip()
    if not digest:
        raise RuntimeError(
            f"RANDAR_API_TOKEN_HASH is not set (JOCKY_API_TOKEN_HASH is accepted for backward compatibility). "
            "Run `python -m jocky.api.token_gen` to create a token."
        )
    if len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest.lower()):
        raise RuntimeError(
            "RANDAR_API_TOKEN_HASH is malformed — expected a 64-character hex string. "
            "Re-run `python -m jocky.api.token_gen`."
        )
    return digest.lower()


def _hash_token(token: str) -> str:
    """SHA-256 digest of a bearer token string."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_token(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(_bearer),
    ] = None,
) -> None:
    """
    FastAPI dependency — inject this to protect any route.

    Raises HTTP 401 for:
      - Missing Authorization header
      - Wrong scheme (not Bearer)
      - Invalid token

    Raises HTTP 503 if the server is misconfigured (env var missing) —
    deliberately does not leak the reason to the caller.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        expected_digest = _load_expected_digest()
    except RuntimeError:
        # Misconfiguration: don't leak server internals.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication subsystem unavailable.",
        )

    provided_digest = _hash_token(credentials.credentials)

    # Constant-time comparison. Regular == would short-circuit on the first
    # differing byte, leaking information about how many characters matched.
    if not hmac.compare_digest(provided_digest, expected_digest):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


def assert_auth_configured() -> None:
    """
    Call at server startup. Aborts with RuntimeError if auth is not
    properly configured, preventing the API from binding without auth.
    """
    _load_expected_digest()