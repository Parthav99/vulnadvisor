"""Upload a JSON scan report to a VulnAdvisor platform instance.

Used by ``scan --upload``. Deliberately depends only on the standard library (``urllib``) so the
published CLI wheel gains no runtime dependency. Defensive throughout (CLAUDE.md): network and
protocol failures raise a typed :class:`UploadError` with context rather than leaking tracebacks,
and the server response is parsed without trusting its shape.

Only the JSON report is sent — never source code.
"""

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

__all__ = ["UploadError", "UploadResult", "upload_report"]

_ENDPOINT = "/v1/scans"
_MAX_ERROR_BODY = 500


class UploadError(RuntimeError):
    """Raised when an upload cannot be completed (network, auth, or a malformed response)."""


@dataclass(frozen=True)
class UploadResult:
    """The outcome of a successful upload."""

    scan_id: str
    introduced: int
    fixed: int
    unchanged: int


def _coerce_int(value: Any) -> int:
    """Best-effort non-negative int from untrusted JSON; 0 on anything unexpected."""
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def upload_report(
    report: dict[str, Any],
    *,
    api_url: str,
    api_key: str,
    repo: str,
    ref: str | None = None,
    commit_sha: str | None = None,
    timeout: float = 30.0,
) -> UploadResult:
    """POST ``report`` to ``{api_url}/v1/scans`` authenticated with ``api_key``.

    ``ref``/``commit_sha`` are sent as JSON ``null`` when unknown — never a placeholder value —
    so the dashboard can label the upload a local scan instead of rendering fake provenance.

    Raises :class:`UploadError` on a missing URL/key, an unreachable server, a non-2xx response, or
    a response that is not the expected JSON object.
    """
    if not api_url:
        raise UploadError("no API URL: pass --api-url or set the API_URL environment variable")
    if not api_key:
        raise UploadError(
            "no API key: run 'vulnadvisor login', pass --api-key, "
            "or set the VULNADVISOR_API_KEY variable"
        )

    url = api_url.rstrip("/") + _ENDPOINT
    payload = json.dumps(
        {"repo": repo, "ref": ref, "commit_sha": commit_sha, "report": report}
    ).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - scheme is the user's configured API URL
        url,
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            raw = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:_MAX_ERROR_BODY].strip()
        hint = f": {detail}" if detail else ""
        raise UploadError(f"server rejected the upload (HTTP {exc.code}){hint}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise UploadError(f"could not reach {url}: {exc}") from exc

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        raise UploadError("server returned a non-JSON response") from exc
    if not isinstance(data, dict):
        raise UploadError("server response was not a JSON object")

    scan_id = data.get("scan_id")
    if not isinstance(scan_id, str) or not scan_id:
        raise UploadError("server response did not include a scan id")
    diff = data.get("diff_summary")
    diff = diff if isinstance(diff, dict) else {}
    return UploadResult(
        scan_id=scan_id,
        introduced=_coerce_int(diff.get("introduced")),
        fixed=_coerce_int(diff.get("fixed")),
        unchanged=_coerce_int(diff.get("unchanged")),
    )
