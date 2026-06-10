"""The unauthenticated health probe."""

from httpx import AsyncClient

from vulnadvisor_platform import __version__


async def test_healthz_ok(client: AsyncClient) -> None:
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"status": "ok", "version": __version__}
