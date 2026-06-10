"""FastAPI application: health + ``/v1/me`` (Task 11.2 skeleton).

The app is intentionally thin here — it establishes the service, DB session wiring, and the
API-key auth round-trip. Ingest, read, and GitHub-App routes arrive in Tasks 11.3–11.6.
"""

from fastapi import FastAPI
from sqlalchemy import select

from vulnadvisor_platform import __version__
from vulnadvisor_platform.db import SessionDep
from vulnadvisor_platform.models import Membership, Org
from vulnadvisor_platform.routers import auth, github, ingest, keys, read
from vulnadvisor_platform.schemas import HealthResponse, MeResponse, OrgMembershipOut
from vulnadvisor_platform.security import CurrentUser

app = FastAPI(
    title="VulnAdvisor Platform",
    version=__version__,
    summary="Reachability-first vulnerability triage for teams.",
)
app.include_router(auth.router)
app.include_router(github.router)
app.include_router(ingest.router)
app.include_router(keys.router)
app.include_router(read.router)


@app.get("/healthz", response_model=HealthResponse, tags=["meta"])
async def healthz() -> HealthResponse:
    """Liveness probe; no authentication."""
    return HealthResponse(status="ok", version=__version__)


@app.get("/v1/me", response_model=MeResponse, tags=["meta"])
async def me(user: CurrentUser, session: SessionDep) -> MeResponse:
    """Return the authenticated user and the orgs/roles they belong to."""
    memberships = (
        (await session.execute(select(Membership).where(Membership.user_id == user.id)))
        .scalars()
        .all()
    )
    orgs: list[OrgMembershipOut] = []
    for membership in memberships:
        org = await session.get(Org, membership.org_id)
        if org is not None:
            orgs.append(
                OrgMembershipOut(org_slug=org.slug, org_name=org.name, role=membership.role)
            )

    return MeResponse(
        id=user.id,
        login=user.login,
        email=user.email,
        avatar_url=user.avatar_url,
        orgs=orgs,
    )
