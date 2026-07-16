"""
apps/api/services/voice_embedding_crypto.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Real, reversible at-rest encryption for Trusted Voice Profile embeddings
(database/models/voice.py::VoiceIdentityProfile.embedding_encrypted) using
the `cryptography` package's Fernet (AES-128-CBC + HMAC, authenticated,
tamper-evident). This is the ONLY place a real embedding vector is ever
decrypted -- apps/api/routes/voice.py's embedding-enroll/verify routes call
into this module and never return the plaintext embedding in any API
response.

Key source: WILLIAM_VOICE_EMBEDDING_KEY (a real Fernet key -- 32 url-safe
base64-encoded bytes, e.g. from `Fernet.generate_key()`) if set; otherwise
a per-process ephemeral key is generated once and a clear warning is
logged. Ephemeral means embeddings enrolled before a process restart
become undecryptable after one -- an honest dev-only convenience, never
acceptable in production (set WILLIAM_VOICE_EMBEDDING_KEY there).

Never stores or accepts raw audio -- only a numeric embedding vector the
caller (a local speaker-embedding provider) already computed.
"""

from __future__ import annotations

import json
import logging
import os
from typing import List, Optional

logger = logging.getLogger("william.api.services.voice_embedding_crypto")

try:
    from cryptography.fernet import Fernet, InvalidToken  # type: ignore
except Exception:  # pragma: no cover - import-safe fallback
    Fernet = None  # type: ignore
    InvalidToken = Exception  # type: ignore

_EPHEMERAL_KEY: Optional[bytes] = None
_WARNED_EPHEMERAL = False


def is_available() -> bool:
    return Fernet is not None


def _resolve_key() -> Optional[bytes]:
    global _EPHEMERAL_KEY, _WARNED_EPHEMERAL

    if Fernet is None:
        return None

    configured = os.getenv("WILLIAM_VOICE_EMBEDDING_KEY", "").strip()
    if configured:
        return configured.encode("utf-8")

    if _EPHEMERAL_KEY is None:
        _EPHEMERAL_KEY = Fernet.generate_key()
    if not _WARNED_EPHEMERAL:
        logger.warning(
            "WILLIAM_VOICE_EMBEDDING_KEY is not set -- using a per-process "
            "ephemeral encryption key for Trusted Voice Profile embeddings. "
            "Enrolled profiles will need re-enrollment after a restart. Set "
            "WILLIAM_VOICE_EMBEDDING_KEY explicitly in production."
        )
        _WARNED_EPHEMERAL = True
    return _EPHEMERAL_KEY


def encrypt_embedding(values: List[float]) -> Optional[str]:
    """Returns an opaque encrypted token, or None if the `cryptography`
    package is unavailable -- the caller must treat None as
    dependency_required, never silently store the plaintext instead."""
    key = _resolve_key()
    if key is None:
        return None
    fernet = Fernet(key)
    payload = json.dumps([float(v) for v in values]).encode("utf-8")
    return fernet.encrypt(payload).decode("utf-8")


def decrypt_embedding(token: str) -> Optional[List[float]]:
    """Returns the real embedding vector, or None if decryption fails
    (wrong/rotated key, corrupted token, or the package is unavailable) --
    never raises past this boundary, so one bad row can't crash speaker
    verification for the rest of the workspace."""
    key = _resolve_key()
    if key is None or not token:
        return None
    fernet = Fernet(key)
    try:
        payload = fernet.decrypt(token.encode("utf-8"))
        return [float(v) for v in json.loads(payload)]
    except (InvalidToken, ValueError, TypeError) as exc:
        logger.warning("Could not decrypt a voice embedding: %s", exc)
        return None


__all__ = ["is_available", "encrypt_embedding", "decrypt_embedding"]
