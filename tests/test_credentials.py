"""Unit tests for the local credentials store (``output/credentials.py``)."""

import json
import os
import stat
from pathlib import Path

import pytest

from vulnadvisor.output.credentials import (
    Credentials,
    default_credentials_path,
    delete_credentials,
    load_credentials,
    save_credentials,
)

_CREDS = Credentials(api_url="https://api.example.com", api_key="va_x.secret", org_slug="acme")


def test_save_load_round_trip(tmp_path: Path) -> None:
    target = tmp_path / "vulnadvisor" / "credentials"
    written = save_credentials(_CREDS, target)
    assert written == target
    assert load_credentials(target) == _CREDS


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_credentials_file_is_0600(tmp_path: Path) -> None:
    target = save_credentials(_CREDS, tmp_path / "credentials")
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_save_overwrites_existing_file(tmp_path: Path) -> None:
    target = tmp_path / "credentials"
    save_credentials(_CREDS, target)
    updated = Credentials(api_url="https://api.example.com", api_key="va_y.other", org_slug="org2")
    save_credentials(updated, target)
    assert load_credentials(target) == updated


def test_load_missing_file_returns_none(tmp_path: Path) -> None:
    assert load_credentials(tmp_path / "nope") is None


@pytest.mark.parametrize("content", ["{not json", "[]", '"a string"', "{}", '{"api_url": ""}'])
def test_load_malformed_returns_none(tmp_path: Path, content: str) -> None:
    target = tmp_path / "credentials"
    target.write_text(content, encoding="utf-8")
    assert load_credentials(target) is None


def test_load_tolerates_missing_org_slug(tmp_path: Path) -> None:
    target = tmp_path / "credentials"
    target.write_text(
        json.dumps({"api_url": "https://api.example.com", "api_key": "k"}), encoding="utf-8"
    )
    loaded = load_credentials(target)
    assert loaded is not None
    assert loaded.api_key == "k" and loaded.org_slug == ""


def test_delete_credentials(tmp_path: Path) -> None:
    target = save_credentials(_CREDS, tmp_path / "credentials")
    assert delete_credentials(target) is True
    assert not target.exists()
    assert delete_credentials(target) is False  # idempotent


def test_default_path_honors_xdg_config_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert default_credentials_path() == tmp_path / "vulnadvisor" / "credentials"
    monkeypatch.delenv("XDG_CONFIG_HOME")
    assert default_credentials_path() == Path.home() / ".config" / "vulnadvisor" / "credentials"
