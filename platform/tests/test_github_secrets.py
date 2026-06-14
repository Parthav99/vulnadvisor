"""Task A — encrypted repository-secret writing for one-click setup.

:func:`encrypt_secret` is pure, so it is proven by decrypting with the matching private key (and
by rejecting a malformed key). The two-call REST dance runs against a small stateful fake of the
GitHub Actions secrets endpoints via ``httpx.MockTransport``: the fake holds a real libsodium
keypair so a test can decrypt what the client PUT, proving the value is genuinely encrypted with
the repo's key — and that 201/204 map to created/updated while 4xx surface GitHub's reason.
"""

import base64
import json
import re
from typing import Any

import httpx
import pytest
from nacl import encoding, public

from vulnadvisor_platform import github_secrets as gs
from vulnadvisor_platform.github_secrets import (
    GitHubSecrets,
    GitHubSecretsError,
    encrypt_secret,
)

# --- encrypt_secret (pure) ------------------------------------------------------------------------


def test_encrypt_secret_roundtrips_and_is_not_plaintext() -> None:
    private = public.PrivateKey.generate()
    public_b64 = private.public_key.encode(encoding.Base64Encoder).decode("ascii")

    encrypted = encrypt_secret(public_b64, "s3cret-value")

    # The wire value is base64 and not the plaintext...
    raw = base64.b64decode(encrypted)
    assert b"s3cret-value" not in raw
    # ...and decrypts back to the original with the matching private key.
    assert public.SealedBox(private).decrypt(raw).decode("utf-8") == "s3cret-value"


def test_encrypt_secret_fresh_ciphertext_each_call() -> None:
    # Sealed boxes use an ephemeral keypair per encryption, so identical input -> distinct output.
    private = public.PrivateKey.generate()
    public_b64 = private.public_key.encode(encoding.Base64Encoder).decode("ascii")
    assert encrypt_secret(public_b64, "x") != encrypt_secret(public_b64, "x")


@pytest.mark.parametrize("bad_key", ["not-base64-!!!", "", base64.b64encode(b"too-short").decode()])
def test_encrypt_secret_rejects_malformed_public_key(bad_key: str) -> None:
    with pytest.raises(GitHubSecretsError, match="malformed repository public key"):
        encrypt_secret(bad_key, "value")


# --- put_repo_secret against a stateful fake GitHub ----------------------------------------------


class _FakeSecretsGitHub:
    """A minimal stateful double for the Actions secrets endpoints, holding a real keypair."""

    def __init__(self) -> None:
        self._private = public.PrivateKey.generate()
        encoded = self._private.public_key.encode(encoding.Base64Encoder)
        self.public_key_b64 = encoded.decode("ascii")
        self.key_id = "key-123"
        self.public_key_status = 200
        self.public_key_body: Any = None  # override to forge a malformed key response
        self.put_status = 201
        self.put_secret_name: str | None = None
        self.put_body: dict[str, Any] | None = None

    def decrypt(self, encrypted_value: str) -> str:
        return public.SealedBox(self._private).decrypt(base64.b64decode(encrypted_value)).decode()

    def handler(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method

        if method == "GET" and path.endswith("/actions/secrets/public-key"):
            if self.public_key_status >= 400:
                return httpx.Response(self.public_key_status, json={"message": "Not Found"})
            body = (
                self.public_key_body
                if self.public_key_body is not None
                else {"key_id": self.key_id, "key": self.public_key_b64}
            )
            return httpx.Response(200, json=body)

        if method == "PUT" and (m := re.match(r"^/repos/[^/]+/[^/]+/actions/secrets/(.+)$", path)):
            self.put_secret_name = m.group(1)
            self.put_body = json.loads(request.content)
            if self.put_status >= 400:
                return httpx.Response(
                    self.put_status, json={"message": "Resource not accessible by integration"}
                )
            return httpx.Response(self.put_status)

        return httpx.Response(500, json={"unhandled": f"{method} {path}"})


def _patched_client(monkeypatch: Any, fake: _FakeSecretsGitHub) -> GitHubSecrets:
    real_async_client = httpx.AsyncClient
    monkeypatch.setattr(
        gs.httpx,
        "AsyncClient",
        lambda **kw: real_async_client(transport=httpx.MockTransport(fake.handler)),
    )
    return GitHubSecrets()


async def _put(client: GitHubSecrets, value: str = "vad_live_secret") -> Any:
    return await client.put_repo_secret(
        token="gho_test",
        repo_full_name="acme/web",
        secret_name="VULNADVISOR_API_KEY",
        value=value,
    )


async def test_put_repo_secret_encrypts_with_repo_key_and_reports_created(monkeypatch: Any) -> None:
    fake = _FakeSecretsGitHub()
    client = _patched_client(monkeypatch, fake)

    result = await _put(client)

    assert result.created is True
    assert result.secret_name == "VULNADVISOR_API_KEY"
    # The PUT went to the right secret, echoed the key_id, and carried a value that decrypts back
    # to the plaintext using the repo's private key — proving real end-to-end encryption.
    assert fake.put_secret_name == "VULNADVISOR_API_KEY"
    assert fake.put_body is not None
    assert fake.put_body["key_id"] == fake.key_id
    assert fake.decrypt(fake.put_body["encrypted_value"]) == "vad_live_secret"


async def test_put_repo_secret_update_in_place_reports_not_created(monkeypatch: Any) -> None:
    fake = _FakeSecretsGitHub()
    fake.put_status = 204  # GitHub returns 204 when overwriting an existing secret
    client = _patched_client(monkeypatch, fake)

    result = await _put(client)

    assert result.created is False
    assert result.secret_name == "VULNADVISOR_API_KEY"


async def test_put_repo_secret_public_key_404_raises(monkeypatch: Any) -> None:
    fake = _FakeSecretsGitHub()
    fake.public_key_status = 404
    client = _patched_client(monkeypatch, fake)

    with pytest.raises(GitHubSecretsError, match="public key: GitHub returned 404"):
        await _put(client)
    assert fake.put_body is None  # never attempted the PUT without a key


async def test_put_repo_secret_malformed_public_key_raises(monkeypatch: Any) -> None:
    fake = _FakeSecretsGitHub()
    fake.public_key_body = {"key_id": "", "key": ""}
    client = _patched_client(monkeypatch, fake)

    with pytest.raises(GitHubSecretsError, match="malformed Actions public key"):
        await _put(client)
    assert fake.put_body is None


async def test_put_repo_secret_forbidden_surfaces_github_message(monkeypatch: Any) -> None:
    fake = _FakeSecretsGitHub()
    fake.put_status = 403
    client = _patched_client(monkeypatch, fake)

    with pytest.raises(GitHubSecretsError, match="Resource not accessible by integration"):
        await _put(client)
