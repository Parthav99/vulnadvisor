# File: platform/vulnadvisor_platform/github_secrets.py
"""GitHub Actions repository-secret writer (one-click setup, Task A).

So the setup PR is truly zero-config, the platform writes the workflow's authentication secret
(``VULNADVISOR_API_KEY``) for the user instead of asking them to add it by hand. GitHub requires
a secret value be encrypted client-side with the repo's Actions public key using libsodium's
sealed box (``crypto_box_seal``); PyNaCl provides exactly that.

The encryption is a pure function (:func:`encrypt_secret`) so it is unit-tested without network or
credentials; the two-call REST dance (fetch public key -> PUT encrypted value) lives in
:class:`GitHubSecrets` and is exercised against an ``httpx.MockTransport`` fake. Writing a secret
needs only the ``repo`` scope the setup-PR OAuth token already carries — no new permission.
"""

import base64
from dataclasses import dataclass
from typing import Annotated, Any

import httpx
from fastapi import Depends
from nacl import encoding, public

_API = "https://api.github.com"


class GitHubSecretsError(RuntimeError):
    """Raised when GitHub rejects a secrets request or returns a malformed response."""


@dataclass(frozen=True)
class RepoPublicKey:
    """A repo's Actions public key: the base64 key plus the ``key_id`` the PUT must echo back."""

    key_id: str
    key: str


@dataclass(frozen=True)
class SecretResult:
    """Outcome of writing a repo secret: ``created`` (HTTP 201) vs updated in place (HTTP 204)."""

    secret_name: str
    created: bool


def encrypt_secret(public_key_b64: str, value: str) -> str:
    """Encrypt ``value`` for a repo Actions secret using GitHub's libsodium sealed box.

    Returns the base64-encoded ciphertext GitHub's ``PUT .../actions/secrets/{name}`` expects.
    Pure — no I/O — so it is unit-tested by decrypting with the matching private key. A malformed
    public key (wrong length / not base64) raises :class:`GitHubSecretsError` rather than a raw
    crypto error.
    """
    try:
        key = public.PublicKey(public_key_b64.encode("ascii"), encoding.Base64Encoder)
    except (ValueError, TypeError) as exc:
        raise GitHubSecretsError(f"malformed repository public key: {exc}") from exc
    sealed = public.SealedBox(key).encrypt(value.encode("utf-8"))
    return base64.b64encode(sealed).decode("ascii")


def _detail(response: httpx.Response) -> str:
    """GitHub's human-readable ``message`` in parens, or ``""`` — defensive, never raises.

    Surfaces the real reason (e.g. "Resource not accessible by integration" when the token lacks
    secrets write) so an opaque failure becomes actionable, mirroring :mod:`github_app`.
    """
    try:
        body = response.json()
    except ValueError:
        return ""
    if isinstance(body, dict):
        message = body.get("message")
        if isinstance(message, str) and message:
            return f" ({message})"
    return ""


def _public_key(response: httpx.Response) -> RepoPublicKey:
    """Parse the Actions public-key response, raising :class:`GitHubSecretsError` on any anomaly."""
    if response.status_code >= 400:
        raise GitHubSecretsError(
            f"fetching the repo public key: GitHub returned "
            f"{response.status_code}{_detail(response)}"
        )
    try:
        data: Any = response.json()
    except ValueError as exc:
        raise GitHubSecretsError(
            "fetching the repo public key: GitHub returned a non-JSON body"
        ) from exc
    key_id = data.get("key_id") if isinstance(data, dict) else None
    key = data.get("key") if isinstance(data, dict) else None
    if not isinstance(key_id, str) or not key_id or not isinstance(key, str) or not key:
        raise GitHubSecretsError("GitHub returned a malformed Actions public key")
    return RepoPublicKey(key_id=key_id, key=key)


class GitHubSecrets:
    """Reads a repo's Actions public key and writes encrypted repository secrets via REST."""

    async def put_repo_secret(
        self, *, token: str, repo_full_name: str, secret_name: str, value: str
    ) -> SecretResult:
        """Create or update repository Actions secret ``secret_name`` with ``value``.

        Two calls under the caller's ``token`` (a ``repo``-scoped OAuth token or an installation
        token with ``secrets: write``): fetch the repo's public key, then PUT the sealed-box
        ciphertext. Idempotent — GitHub returns 201 the first time and 204 on overwrite, both
        success. Any non-2xx (404 unknown repo, 403 missing permission) raises a contextual
        :class:`GitHubSecretsError` carrying GitHub's own message.
        """
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
        async with httpx.AsyncClient(timeout=10.0) as client:
            key_response = await client.get(
                f"{_API}/repos/{repo_full_name}/actions/secrets/public-key", headers=headers
            )
            key = _public_key(key_response)
            encrypted = encrypt_secret(key.key, value)
            put = await client.put(
                f"{_API}/repos/{repo_full_name}/actions/secrets/{secret_name}",
                headers=headers,
                json={"encrypted_value": encrypted, "key_id": key.key_id},
            )
        if put.status_code not in (201, 204):
            raise GitHubSecretsError(
                f"writing secret {secret_name!r}: GitHub returned {put.status_code}{_detail(put)}"
            )
        return SecretResult(secret_name=secret_name, created=put.status_code == 201)


def get_github_secrets() -> GitHubSecrets:
    """FastAPI dependency providing the GitHub secrets client (override in tests)."""
    return GitHubSecrets()


GitHubSecretsDep = Annotated[GitHubSecrets, Depends(get_github_secrets)]
