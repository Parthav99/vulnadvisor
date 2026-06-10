"""Model round-trip + API-key hashing/revocation behavior."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vulnadvisor_platform.models import ApiKey, Finding, Org, Scan, ScanSource, ScanStatus
from vulnadvisor_platform.security import generate_api_key, hash_key


def test_generate_api_key_is_hashed_and_prefixed() -> None:
    full, prefix, digest = generate_api_key()
    assert full.startswith(f"{prefix}.")  # prefix identifies the key; body stays secret
    assert prefix.startswith("va_")
    assert digest == hash_key(full)
    assert len(digest) == 64  # sha-256 hex
    # A different key hashes differently (no fixed salt collision).
    assert generate_api_key()[2] != digest


async def test_org_and_jsonb_columns_round_trip(
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    async with sessionmaker() as session:
        org = Org(slug="acme", name="Acme")
        session.add(org)
        await session.flush()
        repo_scan = Scan(
            repo_id=org.id,  # not an FK target here; we only exercise column storage
            commit_sha="abc123",
            ref="refs/heads/main",
            source=ScanSource.CI.value,
            tool_version="1.0.3",
            status=ScanStatus.COMPLETE.value,
            degraded_sources=["OSV"],
            summary={"total": 2, "by_band": {"critical": 1, "low": 1}},
        )
        session.add(repo_scan)
        await session.flush()
        session.add(
            Finding(
                scan_id=repo_scan.id,
                advisory_id="GHSA-xxxx",
                package="jinja2",
                version="2.10",
                tier="imported",
                band="critical",
                priority=91.9,
                payload={"dependency": {"name": "jinja2"}, "score": {"priority": 91.9}},
            )
        )
        await session.commit()

    async with sessionmaker() as session:
        stored = (await session.execute(select(Scan))).scalar_one()
        assert stored.degraded_sources == ["OSV"]
        assert stored.summary["by_band"]["critical"] == 1
        finding = (await session.execute(select(Finding))).scalar_one()
        assert finding.payload["dependency"]["name"] == "jinja2"
        assert finding.priority == 91.9


async def test_revoked_key_is_filtered_out(
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    from vulnadvisor_platform.db import utcnow

    _, prefix, digest = generate_api_key()
    async with sessionmaker() as session:
        org = Org(slug="acme", name="Acme")
        session.add(org)
        await session.flush()
        session.add(
            ApiKey(
                org_id=org.id,
                name="revoked",
                hash=digest,
                prefix=prefix,
                revoked_at=utcnow(),
            )
        )
        await session.commit()

    async with sessionmaker() as session:
        active = (
            await session.execute(
                select(ApiKey).where(ApiKey.hash == digest, ApiKey.revoked_at.is_(None))
            )
        ).scalar_one_or_none()
        assert active is None  # a revoked key must never authenticate
