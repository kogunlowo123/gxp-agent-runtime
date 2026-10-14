"""HTTP routes.

Human endpoints authenticate enterprise OIDC tokens and check roles. Agent
endpoints authenticate agent credentials through the identity fabric (or
offline against its JWKS) and are authorized per action. Endpoints readable
by both decide the caller type from the token issuer, then verify the token
with that issuer's keys.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from gxp_agent_runtime.api.schemas import (
    ActionCatalog,
    DefinitionList,
    RequestList,
    SignatureList,
    SystemList,
)
from gxp_agent_runtime.application.commands import (
    ActionPreview,
    ApplySignature,
    AuditVerification,
    ChallengeView,
    CreateChallenge,
    GenerateReview,
    RecordVerification,
    RegisterDefinition,
    RegisterSystem,
    RequestView,
    SignatureOutcome,
    SubmitAction,
)
from gxp_agent_runtime.domain.models import (
    ActionDefinition,
    ExecutionRecord,
    PeriodicReview,
    RecordType,
    RequestStatus,
    Role,
    ValidatedSystem,
    ValidationStatus,
)
from gxp_agent_runtime.runtime.container import Container
from gxp_agent_runtime.security.agents import AgentPrincipal, bearer_token
from gxp_agent_runtime.security.humans import HumanPrincipal, require_role
from gxp_agent_runtime.security.jwks import unverified_issuer

ALL_ROLES = (Role.SYSTEM_OWNER, Role.APPROVER, Role.QUALITY, Role.AUDITOR)

router = APIRouter()


def container(request: Request) -> Container:
    value: Container = request.app.state.container
    return value


Deps = Annotated[Container, Depends(container)]


async def human(c: Deps, authorization: Annotated[str | None, Header()] = None) -> HumanPrincipal:
    return await c.humans.authenticate(authorization)


async def agent(c: Deps, authorization: Annotated[str | None, Header()] = None) -> AgentPrincipal:
    principal = await c.runtime.agents.authenticate(authorization)
    return principal


async def caller(
    c: Deps, authorization: Annotated[str | None, Header()] = None
) -> HumanPrincipal | AgentPrincipal:
    token = bearer_token(authorization)
    if unverified_issuer(token) == c.humans.issuer:
        return await c.humans.authenticate(authorization)
    return await c.runtime.agents.authenticate(authorization)


Human = Annotated[HumanPrincipal, Depends(human)]
Agent = Annotated[AgentPrincipal, Depends(agent)]
Caller = Annotated[HumanPrincipal | AgentPrincipal, Depends(caller)]


# ----------------------------------------------------------------- discovery


@router.get("/.well-known/jwks.json", tags=["discovery"])
async def jwks(c: Deps) -> dict[str, object]:
    """Public keys that verify e-signature manifests, execution records and audit chains."""
    return {"keys": [c.signer.jwk("records"), c.audit_signer.jwk("audit")]}


# ------------------------------------------------------------------- systems


@router.post("/v1/systems", status_code=201, tags=["registry"])
async def register_system(body: RegisterSystem, c: Deps, who: Human) -> ValidatedSystem:
    return await c.runtime.register_system(body, who=who)


@router.get("/v1/systems", tags=["registry"])
async def list_systems(c: Deps, who: Human) -> SystemList:
    require_role(who, *ALL_ROLES)
    return SystemList(items=list(await c.runtime.list_systems()))


@router.get("/v1/systems/{system_id}", tags=["registry"])
async def get_system(system_id: str, c: Deps, who: Human) -> ValidatedSystem:
    require_role(who, *ALL_ROLES)
    return await c.runtime.get_system(system_id)


# --------------------------------------------------------------- definitions


@router.post("/v1/action-definitions", status_code=201, tags=["registry"])
async def register_definition(body: RegisterDefinition, c: Deps, who: Human) -> ActionDefinition:
    return await c.runtime.register_definition(body, who=who)


@router.get("/v1/action-definitions", tags=["registry"])
async def list_definitions(
    c: Deps, who: Human, status: ValidationStatus | None = None
) -> DefinitionList:
    require_role(who, *ALL_ROLES)
    return DefinitionList(items=list(await c.runtime.list_definitions(status=status)))


@router.get("/v1/action-definitions/{action_id}/{version}", tags=["registry"])
async def get_definition(action_id: str, version: str, c: Deps, who: Human) -> ActionDefinition:
    require_role(who, *ALL_ROLES)
    return await c.runtime.get_definition(action_id, version)


# ---------------------------------------------------------------- agent API


@router.get("/v1/actions", tags=["agents"])
async def catalog(c: Deps, principal: Agent) -> ActionCatalog:
    c.metrics.channel_calls.labels("rest", "catalog").inc()
    return ActionCatalog(items=await c.runtime.catalog(principal))


@router.post("/v1/actions/assess", tags=["agents"])
async def assess(body: SubmitAction, c: Deps, principal: Agent) -> ActionPreview:
    c.metrics.channel_calls.labels("rest", "assess").inc()
    return await c.runtime.preview(principal, body)


@router.post("/v1/action-requests", status_code=201, tags=["agents"])
async def submit(body: SubmitAction, c: Deps, principal: Agent) -> RequestView:
    c.metrics.channel_calls.labels("rest", "submit").inc()
    return await c.runtime.submit(principal, body)


@router.get("/v1/action-requests", tags=["approvals"])
async def list_requests(
    *,
    c: Deps,
    who: Human,
    status: RequestStatus | None = None,
    system_id: Annotated[str | None, Query(max_length=64)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> RequestList:
    require_role(who, *ALL_ROLES)
    items = await c.runtime.list_requests(
        status=status, system_id=system_id, limit=limit, offset=offset
    )
    return RequestList(items=items, limit=limit, offset=offset)


@router.get("/v1/action-requests/{request_id}", tags=["approvals"])
async def get_request(request_id: str, c: Deps, who: Caller) -> RequestView:
    if isinstance(who, AgentPrincipal):
        await c.runtime.authorize_read(who)
        return await c.runtime.agent_request(who, request_id)
    require_role(who, *ALL_ROLES)
    return await c.runtime.request_view(await c.runtime.get_request(request_id))


# ---------------------------------------------------------------- signatures


@router.post("/v1/signatures/challenges", status_code=201, tags=["signatures"])
async def create_challenge(body: CreateChallenge, c: Deps, who: Human) -> ChallengeView:
    return await c.runtime.create_challenge(body, who=who)


@router.post("/v1/signatures", status_code=201, tags=["signatures"])
async def apply_signature(body: ApplySignature, c: Deps, who: Human) -> SignatureOutcome:
    return await c.runtime.sign(
        who=who,
        challenge_id=body.challenge_id,
        reauthentication_token=body.reauthentication_token,
        reason=body.reason,
    )


@router.get("/v1/signatures", tags=["signatures"])
async def list_signatures(
    *,
    c: Deps,
    who: Human,
    record_type: RecordType,
    record_id: Annotated[str, Query(min_length=1, max_length=160)],
) -> SignatureList:
    require_role(who, *ALL_ROLES)
    return SignatureList(items=list(await c.runtime.list_signatures(record_type, record_id)))


# --------------------------------------------------------- execution records


@router.get("/v1/execution-records/{record_id}", tags=["records"])
async def get_record(record_id: str, c: Deps, who: Caller) -> ExecutionRecord:
    if isinstance(who, AgentPrincipal):
        await c.runtime.authorize_read(who)
        return await c.runtime.agent_record(who, record_id)
    require_role(who, *ALL_ROLES)
    return await c.runtime.get_record(record_id)


@router.get("/v1/execution-records/{record_id}/verification", tags=["records"])
async def verify_record(record_id: str, c: Deps, who: Human) -> RecordVerification:
    require_role(who, Role.QUALITY, Role.AUDITOR)
    return await c.runtime.verify_record(record_id)


# ------------------------------------------------------------ periodic review


@router.post("/v1/periodic-reviews", status_code=201, tags=["reviews"])
async def generate_review(body: GenerateReview, c: Deps, who: Human) -> PeriodicReview:
    return await c.runtime.generate_review(body, who=who)


@router.get("/v1/periodic-reviews/{review_id}", tags=["reviews"])
async def get_review(review_id: str, c: Deps, who: Human) -> PeriodicReview:
    require_role(who, *ALL_ROLES)
    return await c.runtime.get_review(review_id)


@router.get("/v1/audit/verification", tags=["reviews"])
async def verify_audit(c: Deps, who: Human) -> AuditVerification:
    require_role(who, Role.QUALITY, Role.AUDITOR)
    return await c.runtime.verify_audit()


# ---------------------------------------------------------------- operations


@router.get("/healthz", tags=["operations"], include_in_schema=False)
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz", tags=["operations"], include_in_schema=False)
async def readyz(c: Deps, response: Response) -> dict[str, str]:
    try:
        async with c.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        response.status_code = 503
        return {"status": "database unavailable"}
    return {"status": "ready"}


@router.get("/metrics", tags=["operations"], include_in_schema=False)
async def metrics(c: Deps) -> Response:
    return Response(generate_latest(c.metrics.registry), media_type=CONTENT_TYPE_LATEST)
