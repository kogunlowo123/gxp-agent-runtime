"""Composition root: builds every collaborator once per process from Settings."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from datetime import timedelta

import httpx
from agentic_core.audit import AuditLog
from agentic_core.domain.identifiers import new_id
from agentic_core.policy import PolicyEngine, PolicySet
from sqlalchemy.ext.asyncio import AsyncEngine

from gxp_agent_runtime.application.runtime import GxpRuntime
from gxp_agent_runtime.application.signatures import SignatureService
from gxp_agent_runtime.config import Settings
from gxp_agent_runtime.domain.alcoa import AlcoaChecker
from gxp_agent_runtime.domain.ports import Clock
from gxp_agent_runtime.infrastructure.connectors import HttpActionConnector
from gxp_agent_runtime.infrastructure.database import (
    SqlAuditReader,
    SqlAuditSink,
    SqlChallengeRepository,
    SqlDefinitionRepository,
    SqlRecordRepository,
    SqlRequestRepository,
    SqlReviewRepository,
    SqlSignatureRepository,
    SqlSystemRepository,
    SystemClock,
    create_schema,
    make_engine,
)
from gxp_agent_runtime.integrations.identity_fabric import IdentityFabricClient, RuntimeCredentials
from gxp_agent_runtime.observability.metrics import RuntimeMetrics
from gxp_agent_runtime.security.agents import AgentGateway, FabricAgentGateway, LocalAgentGateway
from gxp_agent_runtime.security.humans import HumanAuthenticator
from gxp_agent_runtime.security.jwks import KeyResolver, RemoteJwks
from gxp_agent_runtime.security.keys import RecordSigner, SignatureVerifier


@dataclass
class Container:
    settings: Settings
    runtime: GxpRuntime
    humans: HumanAuthenticator
    metrics: RuntimeMetrics
    engine: AsyncEngine
    http: httpx.AsyncClient
    signer: RecordSigner
    audit_signer: RecordSigner
    chain_id: str
    extra_clients: list[httpx.AsyncClient] = field(default_factory=list)

    async def aclose(self) -> None:
        for client in self.extra_clients:
            await client.aclose()
        await self.http.aclose()
        await self.engine.dispose()


def _keys(settings: Settings) -> tuple[RecordSigner, RecordSigner]:
    if settings.dev_ephemeral_keys:
        return RecordSigner.ephemeral("records-ephemeral"), RecordSigner.ephemeral(
            "audit-ephemeral"
        )
    if settings.signing_key_file is None or settings.audit_key_file is None:
        raise ValueError("signing keys are not configured")  # pragma: no cover - validated
    return (
        RecordSigner.from_file(settings.signing_key_file),
        RecordSigner.from_file(settings.audit_key_file),
    )


async def build_container(
    settings: Settings,
    *,
    signer_resolver: KeyResolver | None = None,
    agent_resolver: KeyResolver | None = None,
    clock: Clock | None = None,
    http: httpx.AsyncClient | None = None,
    connector_transport: httpx.AsyncBaseTransport | None = None,
    fabric_transport: httpx.AsyncBaseTransport | None = None,
) -> Container:
    clock = clock or SystemClock()
    http = http or httpx.AsyncClient(timeout=httpx.Timeout(5.0))
    signer, audit_signer = _keys(settings)
    retired = (
        SignatureVerifier.from_directory(settings.trusted_public_keys_dir)
        if settings.trusted_public_keys_dir
        else {}
    )
    verifier = SignatureVerifier({**retired, signer.key_id: signer.public_key})
    audit_keys = SignatureVerifier({**retired, audit_signer.key_id: audit_signer.public_key})

    engine = make_engine(settings.database_url)
    await create_schema(engine)
    chain_id = f"{settings.instance_id or socket.gethostname()}-{new_id()[:12]}"
    audit = AuditLog(SqlAuditSink(engine, chain_id), audit_signer, key_id=audit_signer.key_id)

    humans = HumanAuthenticator(
        signer_resolver or RemoteJwks(settings.signer_jwks_url, client=http),
        issuer=settings.signer_issuer,
        audience=settings.signer_audience,
        clock=clock,
        roles_claim=settings.signer_roles_claim,
        name_claim=settings.signer_name_claim,
        reauth_max_age=timedelta(seconds=settings.reauth_max_age_seconds),
    )

    fabric_http = (
        httpx.AsyncClient(transport=fabric_transport, timeout=httpx.Timeout(5.0))
        if fabric_transport is not None
        else http
    )
    agents: AgentGateway
    credentials: RuntimeCredentials | None = None
    if settings.fabric_url:
        fabric = IdentityFabricClient(settings.fabric_url, client=fabric_http)
        agents = FabricAgentGateway(fabric)
        if settings.runtime_client_id and settings.workload_token_file:
            credentials = RuntimeCredentials(
                fabric,
                client_id=settings.runtime_client_id,
                workload_token_file=settings.workload_token_file,
                clock=clock,
            )
    else:
        if settings.agent_issuer is None or settings.agent_jwks_url is None:
            raise ValueError("agent verification is not configured")  # pragma: no cover
        agents = LocalAgentGateway(
            agent_resolver or RemoteJwks(settings.agent_jwks_url, client=http),
            issuer=settings.agent_issuer,
            audience=settings.agent_audience,
            clock=clock,
        )

    connector_http = httpx.AsyncClient(
        transport=connector_transport,
        timeout=httpx.Timeout(settings.connector_timeout_seconds),
        follow_redirects=False,
    )
    metrics = RuntimeMetrics()
    signature_store = SqlSignatureRepository(engine)
    runtime = GxpRuntime(
        systems=SqlSystemRepository(engine),
        definitions=SqlDefinitionRepository(engine),
        requests=SqlRequestRepository(engine),
        signature_store=signature_store,
        records=SqlRecordRepository(engine),
        reviews=SqlReviewRepository(engine),
        audit_reader=SqlAuditReader(engine),
        signatures=SignatureService(
            challenges=SqlChallengeRepository(engine),
            signatures=signature_store,
            humans=humans,
            signer=signer,
            verifier=verifier,
            clock=clock,
            challenge_ttl=timedelta(seconds=settings.challenge_ttl_seconds),
        ),
        agents=agents,
        connector=HttpActionConnector(connector_http, clock=clock, credentials=credentials),
        policy=PolicyEngine(PolicySet.from_file(settings.policy_file)),
        audit=audit,
        signer=signer,
        verifier=verifier,
        audit_keys=audit_keys,
        clock=clock,
        metrics=metrics,
        alcoa=AlcoaChecker(
            max_clock_skew=timedelta(seconds=settings.max_clock_skew_seconds),
            max_activity_age=timedelta(seconds=settings.max_activity_age_seconds),
        ),
        approval_ttl=settings.approval_ttl,
        environment=settings.environment,
    )
    return Container(
        settings=settings,
        runtime=runtime,
        humans=humans,
        metrics=metrics,
        engine=engine,
        http=http,
        signer=signer,
        audit_signer=audit_signer,
        chain_id=chain_id,
        extra_clients=[c for c in (connector_http, fabric_http) if c is not http],
    )
