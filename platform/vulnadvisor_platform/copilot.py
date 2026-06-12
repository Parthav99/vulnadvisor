"""Triage-copilot support (Task 15.1): BYO-key encryption at rest + the per-org daily cap.

The org's Anthropic API key is encrypted with Fernet (AES-128-CBC + HMAC) under a key derived
from ``SECRET_KEY`` — the same secret that already guards sessions, so there is no second secret
to rotate. Only the ciphertext and a ``…last4`` hint are stored; the plaintext is returned solely
by the service-token-guarded grant endpoint (see :mod:`vulnadvisor_platform.routers.copilot`),
never by any user-reachable endpoint.

The daily cap is a simple per-(org, UTC-day) counter consumed at grant time. The read-modify-write
is not race-proof under concurrent grants, which is acceptable for a soft abuse cap (the worst
case is a handful of extra requests, never a silent under-count that hides usage).
"""

import base64
import hashlib
import uuid

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vulnadvisor_platform.db import utcnow
from vulnadvisor_platform.models import CopilotUsage

_KEY_PREFIX = "sk-ant-"
_MIN_KEY_LEN = 16
_MAX_KEY_LEN = 512


class CopilotKeyError(Exception):
    """A stored copilot key could not be decrypted (e.g. ``SECRET_KEY`` changed)."""


class CopilotCapExceeded(Exception):
    """The org has used all of today's copilot grants."""

    def __init__(self, cap: int) -> None:
        """Record the cap that was hit, for the error message and callers."""
        super().__init__(f"copilot daily cap of {cap} requests reached")
        self.cap = cap


def _fernet(secret_key: str) -> Fernet:
    """Fernet instance keyed by a SHA-256 derivation of the platform ``SECRET_KEY``."""
    digest = hashlib.sha256(secret_key.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def validate_anthropic_key(api_key: str) -> str:
    """Return the stripped key if it looks like an Anthropic API key, else raise ``ValueError``."""
    candidate = api_key.strip()
    if not candidate.startswith(_KEY_PREFIX):
        raise ValueError(f"an Anthropic API key starts with '{_KEY_PREFIX}'")
    if not _MIN_KEY_LEN <= len(candidate) <= _MAX_KEY_LEN:
        raise ValueError(f"key length must be {_MIN_KEY_LEN}-{_MAX_KEY_LEN} characters")
    if any(ch.isspace() for ch in candidate):
        raise ValueError("key must not contain whitespace")
    return candidate


def encrypt_api_key(secret_key: str, api_key: str) -> str:
    """Encrypt ``api_key`` for storage; returns the Fernet token as ASCII text."""
    return _fernet(secret_key).encrypt(api_key.encode("utf-8")).decode("ascii")


def decrypt_api_key(secret_key: str, ciphertext: str) -> str:
    """Decrypt a stored key, raising :class:`CopilotKeyError` on tampered/unreadable data."""
    try:
        return _fernet(secret_key).decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError, ValueError) as exc:
        raise CopilotKeyError(
            "stored copilot key cannot be decrypted (SECRET_KEY changed?); re-save the key"
        ) from exc


def key_hint(api_key: str) -> str:
    """The non-secret display hint stored alongside the ciphertext (last 4 characters)."""
    return f"…{api_key[-4:]}"


def today() -> str:
    """The current UTC day as ``YYYY-MM-DD`` (the cap's bucketing key)."""
    return utcnow().date().isoformat()


async def used_today(session: AsyncSession, org_id: uuid.UUID) -> int:
    """How many copilot grants the org has consumed today."""
    row = (
        await session.execute(
            select(CopilotUsage).where(CopilotUsage.org_id == org_id, CopilotUsage.day == today())
        )
    ).scalar_one_or_none()
    return row.count if row is not None else 0


async def consume_grant(session: AsyncSession, org_id: uuid.UUID, cap: int) -> int:
    """Consume one grant from today's budget; returns the remaining count.

    Raises :class:`CopilotCapExceeded` when the budget is exhausted. Does not commit — the
    caller owns the transaction so a failed grant never burns budget.
    """
    day = today()
    row = (
        await session.execute(
            select(CopilotUsage).where(CopilotUsage.org_id == org_id, CopilotUsage.day == day)
        )
    ).scalar_one_or_none()
    if row is None:
        row = CopilotUsage(org_id=org_id, day=day, count=0)
        session.add(row)
    if row.count >= cap:
        raise CopilotCapExceeded(cap)
    row.count += 1
    return cap - row.count
