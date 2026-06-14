"""Server-side LLM proxy for ``vulnadvisor suggest`` (Task D).

The CLI's suggest loop runs the model call *here* instead of with a local model-key secret: it
authenticates with the org API key (the same ``VULNADVISOR_API_KEY`` the CLI uploads scans with)
and the platform performs the call using the org's BYO copilot key, under the same per-org daily
cap. So a CI workflow needs no ``OPENROUTER_/OPENAI_/ANTHROPIC_API_KEY`` secret at all.

Key selection: the caller org's own BYO copilot key when it has one, else the platform's configured
fallback key (``COPILOT_FALLBACK_API_KEY`` — so suggest works zero-config without every org first
saving a key). When neither is set the response is a graceful ``available=False``.

Trust + soundness shape (mirrors :mod:`vulnadvisor_platform.routers.copilot`):

* The decrypted BYO key never leaves the platform — only the model's text output is returned.
* No key available → a graceful ``available=False`` (no grant consumed); the CLI posts nothing and
  never fails the build.
* The daily cap is consumed **only when the model call succeeds** (the session commits last), so a
  spent cap (429) or an upstream model failure (502) never burns budget. The CLI's fix loop treats
  both as a failed attempt and moves on, keeping the build green.
"""

from fastapi import APIRouter, HTTPException, status
from fastapi.concurrency import run_in_threadpool

from vulnadvisor.llm.client import LLMError, build_fix_client_for_key
from vulnadvisor_platform.config import SettingsDep
from vulnadvisor_platform.copilot import (
    CopilotCapExceeded,
    CopilotKeyError,
    consume_grant,
    decrypt_api_key,
)
from vulnadvisor_platform.db import SessionDep
from vulnadvisor_platform.models import Org
from vulnadvisor_platform.schemas import LlmCompleteRequest, LlmCompleteResponse
from vulnadvisor_platform.security import CurrentApiKey

router = APIRouter(tags=["llm"])


@router.post("/v1/llm/complete", response_model=LlmCompleteResponse)
async def llm_complete(
    body: LlmCompleteRequest,
    api_key: CurrentApiKey,
    session: SessionDep,
    settings: SettingsDep,
) -> LlmCompleteResponse:
    """Run one suggest-loop model call server-side using the caller org's key, or the fallback.

    Authenticated by the org API key. Uses the org's BYO copilot key when set, else the platform's
    configured fallback key; when neither exists the response is a graceful ``available=False`` and
    no grant is consumed. Otherwise one daily-cap slot is consumed and the key performs the call —
    the cap is committed only after the call succeeds.
    """
    org = await session.get(Org, api_key.org_id)
    if org is None:
        return LlmCompleteResponse(available=False)

    # The org's own key wins; the model is detected from the decrypted key downstream. The platform
    # fallback key carries its own configured model (a no-credit key needs an explicit free model).
    model = body.model
    if org.copilot_key_ciphertext is not None:
        try:
            api_secret = decrypt_api_key(settings.secret_key, org.copilot_key_ciphertext)
        except CopilotKeyError as exc:
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(exc)) from exc
    elif settings.copilot_fallback_api_key:
        api_secret = settings.copilot_fallback_api_key
        model = body.model or settings.copilot_fallback_model or None
    else:
        # No org key and no platform fallback -> nothing to call with. Graceful no-op, no grant.
        return LlmCompleteResponse(available=False)

    try:
        remaining = await consume_grant(session, org.id, settings.copilot_daily_cap)
    except CopilotCapExceeded as exc:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, str(exc)) from exc

    client = build_fix_client_for_key(api_secret, model=model)
    try:
        # The dependency-free clients use a blocking urllib transport; keep it off the event loop.
        text = await run_in_threadpool(client.complete, system=body.system, user=body.user)
    except LLMError as exc:
        # The org's own model call failed; leave the grant unconsumed (no commit).
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"model call failed: {exc}") from exc

    await session.commit()  # the grant is consumed only when the response succeeds
    return LlmCompleteResponse(available=True, text=text, remaining_today=remaining)
