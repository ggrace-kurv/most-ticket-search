"""Symmetric encryption for at-rest credential storage.

Specifically: encrypt the user's MOST2 password before writing it into the
flask-session filesystem store, so a disk-only attacker (someone who can
read the session files but not the running process) sees ciphertext, not
plaintext.

Threat model — what this protects against:
  * Backup files, snapshot images, /tmp leakage, lost laptops.
  * Process A (eg. a misconfigured nightly job) that can read
    SESSION_FILE_DIR but not the running app's memory.
  * Operator screenshots / `cat session-id` accidents.

Threat model — what it does NOT protect against:
  * An attacker who can read SECRET_KEY (eg. from .env) AND the session
    file together. The key derivation is deterministic from SECRET_KEY,
    so possession of both equals possession of the plaintext.
  * An attacker who can read the running process's memory: NTLM
    authentication requires the live password to compute every
    challenge response, so any session-based proxy of an NTLM service
    must hold the plaintext in memory while servicing requests. This
    is the unavoidable cost of being a credential-delegating proxy
    and cannot be fixed without changing protocols upstream.

The Fernet token is bound to the current SECRET_KEY. Rotating SECRET_KEY
invalidates every session: stale ciphertexts raise InvalidToken on
decrypt, which the caller treats as "session expired, send the user back
to /login". That's the same UX as expiring a signed cookie, which is the
existing rotation behaviour for SECRET_KEY anyway.
"""
import base64
import functools
import hashlib

from cryptography.fernet import Fernet, InvalidToken

import config

__all__ = ["encrypt_password", "decrypt_password", "InvalidToken"]


@functools.lru_cache(maxsize=1)
def _fernet() -> Fernet:
    """Derive a Fernet key from SECRET_KEY.

    SECRET_KEY is already required to be high-entropy (see
    config._resolve_secret_key — startup refuses placeholder values in
    non-debug mode), so a SHA-256 of it is a reasonable Fernet key.
    Cached so we don't re-derive on every encrypt/decrypt call.
    """
    digest = hashlib.sha256(config.SECRET_KEY.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_password(plaintext: str) -> str:
    """Encrypt a password for storage in the flask-session file.

    Returns a URL-safe ASCII string suitable for stashing in
    `session["..."]`. Roundtrip with decrypt_password().
    """
    if not isinstance(plaintext, str):
        raise TypeError("plaintext password must be a str")
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_password(token: str) -> str:
    """Reverse of encrypt_password.

    Raises cryptography.fernet.InvalidToken if the ciphertext is
    tampered, malformed, or was encrypted under a different SECRET_KEY
    (eg. after a key rotation). Callers should treat that as "session
    no longer valid, force re-login".
    """
    if not isinstance(token, str):
        raise InvalidToken("ciphertext must be a str")
    return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
