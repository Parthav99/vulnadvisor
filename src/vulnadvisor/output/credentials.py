"""Local credential storage for ``vulnadvisor login`` (Task 14.1).

Stores the device-flow-minted API key in ``~/.config/vulnadvisor/credentials`` (a small JSON
file created with owner-only ``0600`` permissions; ``XDG_CONFIG_HOME`` is honored). Stdlib-only —
the published CLI wheel gains no dependency. Reads are defensive: a missing or malformed file
yields ``None``, never a crash, so ``scan --upload`` degrades to its explicit flag/env path.
"""

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

__all__ = [
    "Credentials",
    "default_credentials_path",
    "delete_credentials",
    "load_credentials",
    "save_credentials",
]

_FILE_MODE = 0o600
_DIR_MODE = 0o700


@dataclass(frozen=True)
class Credentials:
    """A stored login: where to upload, the org-scoped key, and which org it belongs to."""

    api_url: str
    api_key: str
    org_slug: str


def default_credentials_path() -> Path:
    """``$XDG_CONFIG_HOME/vulnadvisor/credentials``, defaulting to ``~/.config``."""
    config_home = os.environ.get("XDG_CONFIG_HOME")
    base = Path(config_home) if config_home else Path.home() / ".config"
    return base / "vulnadvisor" / "credentials"


def save_credentials(credentials: Credentials, path: Path | None = None) -> Path:
    """Write the credentials file with owner-only permissions; returns the path written.

    The file is created via ``os.open`` with mode ``0600`` (and re-``chmod``-ed in case it
    already existed with wider permissions). The parent directory is created ``0700``.
    """
    target = path if path is not None else default_credentials_path()
    target.parent.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
    payload = json.dumps(asdict(credentials), indent=2) + "\n"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _FILE_MODE)
    try:
        os.write(fd, payload.encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(target, _FILE_MODE)
    return target


def load_credentials(path: Path | None = None) -> Credentials | None:
    """Read stored credentials, or ``None`` when absent/unreadable/malformed (never raises)."""
    target = path if path is not None else default_credentials_path()
    try:
        raw = target.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    api_url = data.get("api_url")
    api_key = data.get("api_key")
    org_slug = data.get("org_slug")
    if not (isinstance(api_url, str) and api_url and isinstance(api_key, str) and api_key):
        return None
    return Credentials(
        api_url=api_url,
        api_key=api_key,
        org_slug=org_slug if isinstance(org_slug, str) else "",
    )


def delete_credentials(path: Path | None = None) -> bool:
    """Remove the credentials file; returns whether a file existed. Never raises on absence."""
    target = path if path is not None else default_credentials_path()
    try:
        target.unlink()
    except FileNotFoundError:
        return False
    return True
