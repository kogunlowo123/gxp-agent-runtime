"""Shared fixtures: in-process enterprise IdP, agent credential issuer, a validated LIMS
speaking its recorded wire shapes, and a runtime wired to SQLite."""

from __future__ import annotations

import json
import os
import time
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from gxp_agent_runtime.api.app import create_app
from gxp_agent_runtime.application.commands import (
    CreateChallenge,
    RegisterDefinition,
    RegisterSystem,
    SignatureOutcome,
    SubmitAction,
)
from gxp_agent_runtime.application.runtime import GxpRuntime
from gxp_agent_runtime.config import Settings
from gxp_agent_runtime.domain.models import (
    ActionSpec,
    GampCategory,
    GxpImpact,
    HttpBinding,
    Level,
    RecordType,
    SignatureMeaning,
    SourceRecord,
)
from gxp_agent_runtime.runtime.container import Container, build_container
from gxp_agent_runtime.security.agents import AgentPrincipal
from gxp_agent_runtime.security.humans import HumanPrincipal
from gxp_agent_runtime.security.jwks import StaticJwks

ROOT = Path(__file__).resolve().parents[1]
HUMAN_ISSUER = "https://login.corp.test/tenant"
HUMAN_AUDIENCE = "gxp-agent-runtime"
AGENT_ISSUER = "https://identity.corp.test"
AGENT_AUDIENCE = "agent-platform"
PUBLIC_URL = "https://gxp-runtime.corp.test"
LIMS_URL = "https://lims.corp.test"
AGENT = "spiffe://agents.corp.test/agent/qc/release-assistant"
SOURCE = SourceRecord(uri="lims://samples/S-1001/results/assay-7", digest="sha256:" + "b" * 64)

OWNER = ("olivia@corp.test", "Olivia Owner", ("gxp-system-owner",))
APPROVER = ("adam@corp.test", "Adam Approver", ("gxp-approver",))
QA = ("quinn@corp.test", "Quinn Quality", ("gxp-qa",))
QA2 = ("quincy@corp.test", "Quincy Quality", ("gxp-qa",))
AUDITOR = ("aude@corp.test", "Aude Auditor", ("gxp-auditor",))


@dataclass
class FakeClock:
    current: datetime = field(default_factory=lambda: datetime.now(UTC).replace(microsecond=0))

    def now(self) -> datetime:
        return self.current

    def advance(self, **delta: float) -> None:
        self.current += timedelta(**delta)


@dataclass
class FakeIdp:
    """Enterprise OIDC provider: ES256 access tokens and re-authentication ID tokens."""

    issuer: str = HUMAN_ISSUER
    kid: str = "idp-1"
    clock: FakeClock | None = None
    key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )

    def jwks(self) -> dict[str, Any]:
        jwk = jwt.algorithms.ECAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        jwk.update({"kid": self.kid, "alg": "ES256", "use": "sig"})
        return {"keys": [jwk]}

    def _now(self) -> int:
        return int(self.clock.now().timestamp()) if self.clock else int(time.time())

    def mint(self, *, sub: str, aud: str = HUMAN_AUDIENCE, ttl: int = 600, **extra: Any) -> str:
        now = self._now()
        claims: dict[str, Any] = {"iss": self.issuer, "sub": sub, "aud": aud, "iat": now}
        claims["exp"] = now + ttl
        claims.update(extra)
        return jwt.encode(claims, self.key, algorithm="ES256", headers={"kid": self.kid})

    def user(self, who: tuple[str, str, tuple[str, ...]]) -> str:
        sub, name, roles = who
        return self.mint(sub=sub, name=name, roles=list(roles))

    def reauth(
        self,
        who: tuple[str, str, tuple[str, ...]],
        nonce: str,
        *,
        auth_age: int = 5,
        amr: tuple[str, ...] = ("pwd", "mfa"),
    ) -> str:
        sub, name, _ = who
        return self.mint(
            sub=sub, name=name, nonce=nonce, auth_time=self._now() - auth_age, amr=list(amr)
        )

    def principal(self, who: tuple[str, str, tuple[str, ...]]) -> HumanPrincipal:
        sub, name, roles = who
        return HumanPrincipal(subject=sub, name=name, roles=frozenset(roles))


@dataclass
class FakeAgentIssuer:
    """Stands in for agent-identity-fabric: EdDSA agent credentials and JWKS."""

    issuer: str = AGENT_ISSUER
    kid: str = "2026-10"
    clock: FakeClock | None = None
    key: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)

    def jwks(self) -> dict[str, Any]:
        jwk = jwt.algorithms.OKPAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        jwk.update({"kid": self.kid, "alg": "EdDSA", "use": "sig"})
        return {"keys": [jwk]}

    def token(
        self,
        *,
        sub: str = AGENT,
        scopes: tuple[str, ...] = ("gxp:read", "gxp:execute:lims.*"),
        act: dict[str, Any] | None = None,
        ttl: int = 600,
    ) -> str:
        now = int(self.clock.now().timestamp()) if self.clock else int(time.time())
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": sub,
            "aud": AGENT_AUDIENCE,
            "iat": now,
            "exp": now + ttl,
            "jti": f"jti-{now}-{sub[-6:]}",
            "scope": " ".join(scopes),
        }
        if act:
            claims["act"] = act
        return jwt.encode(claims, self.key, algorithm="EdDSA", headers={"kid": self.kid})


@dataclass
class FakeLims:
    """Validated LIMS integration API (recorded request/response shapes)."""

    calls: list[httpx.Request] = field(default_factory=list)
    unavailable: int = 0
    reject_with: int | None = None
    malformed_output: bool = False
    released: dict[str, str] = field(default_factory=dict)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if self.unavailable > 0:
            self.unavailable -= 1
            return httpx.Response(503, json={"error": "maintenance"})
        if self.reject_with is not None:
            return httpx.Response(self.reject_with, json={"error": "rejected by LIMS"})
        path = request.url.path
        if request.method == "GET" and path.startswith("/api/v1/samples/"):
            sample = path.rsplit("/", 1)[-1]
            return httpx.Response(
                200,
                json={"sample_id": sample, "status": self.released.get(sample, "in-review")},
            )
        if request.method == "POST" and path.endswith("/release"):
            sample = path.split("/")[-2]
            body = json.loads(request.content)
            if self.malformed_output:
                return httpx.Response(200, json={"sample_id": sample})
            self.released[sample] = "released"
            return httpx.Response(
                201,
                json={
                    "sample_id": sample,
                    "status": "released",
                    "result_version": 2,
                    "disposition": body["disposition"],
                },
            )
        if request.method == "POST" and path.endswith("/comments"):
            return httpx.Response(201, json={"comment_id": "C-77", "status": "recorded"})
        return httpx.Response(404, json={"error": "unknown endpoint"})

    @property
    def idempotency_keys(self) -> list[str]:
        return [c.headers.get("idempotency-key", "") for c in self.calls]


def lims_system(system_id: str = "lims-prod", **overrides: Any) -> RegisterSystem:
    values: dict[str, Any] = {
        "system_id": system_id,
        "name": "LabWare LIMS (production)",
        "description": "Laboratory information management system for QC release testing.",
        "base_url": LIMS_URL,
        "gamp_category": GampCategory.CONFIGURED,
        "validation_reference": "VSR-LIMS-2026-03",
        "owner": "qc-systems",
        "review_interval_days": 365,
        "last_reviewed_at": datetime.now(UTC) - timedelta(days=30),
    }
    values.update(overrides)
    return RegisterSystem(**values)


def read_status_spec(version: str = "1.0.0", system_id: str = "lims-prod") -> ActionSpec:
    return ActionSpec(
        action_id="lims.sample.read-status",
        version=version,
        system_id=system_id,
        title="Read sample status",
        description="Read the current review status of a QC sample from the LIMS.",
        gamp_category=GampCategory.CONFIGURED,
        impact=GxpImpact(
            patient_safety=Level.LOW, product_quality=Level.LOW, data_integrity=Level.LOW
        ),
        detectability=Level.HIGH,
        reversible=True,
        creates_gxp_record=False,
        input_schema={
            "type": "object",
            "properties": {"sample_id": {"type": "string", "pattern": "^S-[0-9]{4}$"}},
            "required": ["sample_id"],
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "properties": {"sample_id": {"type": "string"}, "status": {"type": "string"}},
            "required": ["sample_id", "status"],
        },
        binding=HttpBinding(method="GET", path="/api/v1/samples/{sample_id}"),
    )


def release_spec(version: str = "1.0.0") -> ActionSpec:
    return ActionSpec(
        action_id="lims.result.release",
        version=version,
        system_id="lims-prod",
        title="Release QC test result",
        description="Release a reviewed QC result so it can be used for batch disposition.",
        gamp_category=GampCategory.CONFIGURED,
        impact=GxpImpact(
            patient_safety=Level.HIGH, product_quality=Level.HIGH, data_integrity=Level.HIGH
        ),
        detectability=Level.MEDIUM,
        reversible=False,
        creates_gxp_record=True,
        requires_source_record=True,
        input_schema={
            "type": "object",
            "properties": {
                "sample_id": {"type": "string", "pattern": "^S-[0-9]{4}$"},
                "disposition": {"enum": ["conforming", "non-conforming"]},
                "batch_id": {"type": "string"},
            },
            "required": ["sample_id", "disposition", "batch_id"],
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "properties": {
                "sample_id": {"type": "string"},
                "status": {"const": "released"},
                "result_version": {"type": "integer"},
                "disposition": {"type": "string"},
            },
            "required": ["sample_id", "status", "result_version"],
        },
        binding=HttpBinding(method="POST", path="/api/v1/results/{sample_id}/release"),
    )


def comment_spec() -> ActionSpec:
    return ActionSpec(
        action_id="lims.result.comment",
        version="1.0.0",
        system_id="lims-prod",
        title="Add reviewer comment",
        description="Attach an investigation comment to a QC result in the LIMS.",
        gamp_category=GampCategory.CONFIGURED,
        impact=GxpImpact(
            patient_safety=Level.LOW, product_quality=Level.MEDIUM, data_integrity=Level.MEDIUM
        ),
        detectability=Level.MEDIUM,
        reversible=True,
        creates_gxp_record=False,
        input_schema={
            "type": "object",
            "properties": {
                "sample_id": {"type": "string"},
                "comment": {"type": "string", "minLength": 5},
            },
            "required": ["sample_id", "comment"],
        },
        output_schema={
            "type": "object",
            "properties": {"comment_id": {"type": "string"}},
            "required": ["comment_id"],
        },
        binding=HttpBinding(method="POST", path="/api/v1/results/{sample_id}/comments"),
    )


def submission(
    clock: FakeClock, action_id: str = "lims.sample.read-status", **overrides: Any
) -> SubmitAction:
    inputs: dict[str, Any] = {
        "lims.sample.read-status": {"sample_id": "S-1001"},
        "lims.result.release": {
            "sample_id": "S-1001",
            "disposition": "conforming",
            "batch_id": "B-2026-0042",
        },
        "lims.result.comment": {"sample_id": "S-1001", "comment": "OOS investigation opened"},
    }[action_id]
    values: dict[str, Any] = {
        "action_id": action_id,
        "inputs": inputs,
        "justification": "Assay results reviewed against specification SPEC-114 rev 6.",
        "context": {"batch_id": "B-2026-0042"} if action_id == "lims.result.release" else {},
        "source_records": (SOURCE,) if action_id == "lims.result.release" else (),
        "performed_at": clock.now() - timedelta(seconds=10),
    }
    values.update(overrides)
    return SubmitAction(**values)


def agent_principal(
    sub: str = AGENT,
    scopes: tuple[str, ...] = ("gxp:read", "gxp:execute:lims.*"),
    chain: tuple[str, ...] = (),
) -> AgentPrincipal:
    return AgentPrincipal(agent_id=sub, scopes=frozenset(scopes), delegation_chain=chain, token="t")


async def sign(
    runtime: GxpRuntime,
    idp: FakeIdp,
    who: tuple[str, str, tuple[str, ...]],
    record_type: RecordType,
    record_id: str,
    meaning: SignatureMeaning,
    reason: str = "Reviewed and approved per SOP-QA-021.",
) -> SignatureOutcome:
    principal = idp.principal(who)
    challenge = await runtime.create_challenge(
        CreateChallenge(record_type=record_type, record_id=record_id, meaning=meaning),
        who=principal,
    )
    return await runtime.sign(
        who=principal,
        challenge_id=challenge.challenge_id,
        reauthentication_token=idp.reauth(who, challenge.nonce),
        reason=reason,
    )


async def provision(runtime: GxpRuntime, idp: FakeIdp) -> None:
    """Register the LIMS and validate three action definitions through QA signatures."""
    owner = idp.principal(OWNER)
    await runtime.register_system(lims_system(), who=owner)
    for spec in (read_status_spec(), release_spec(), comment_spec()):
        await runtime.register_definition(
            RegisterDefinition(spec=spec, validation_reference=f"OQ-{spec.action_id}"),
            who=owner,
        )
        await sign(
            runtime,
            idp,
            QA,
            RecordType.ACTION_DEFINITION,
            spec.key,
            SignatureMeaning.VALIDATION_APPROVAL,
        )


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def idp(clock: FakeClock) -> FakeIdp:
    return FakeIdp(clock=clock)


@pytest.fixture
def issuer(clock: FakeClock) -> FakeAgentIssuer:
    return FakeAgentIssuer(clock=clock)


@pytest.fixture
def lims() -> FakeLims:
    return FakeLims()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    db = os.environ.get("GXP_TEST_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'gxp.db'}")
    return Settings(
        environment="test",
        public_url=PUBLIC_URL,
        database_url=db,
        dev_ephemeral_keys=True,
        signer_issuer=HUMAN_ISSUER,
        signer_audience=HUMAN_AUDIENCE,
        signer_jwks_url=f"{HUMAN_ISSUER}/discovery/keys",
        agent_issuer=AGENT_ISSUER,
        agent_audience=AGENT_AUDIENCE,
        agent_jwks_url=f"{AGENT_ISSUER}/.well-known/jwks.json",
        policy_file=ROOT / "policies" / "gxp-runtime.yaml",
        instance_id="test",
    )


async def make_container(
    settings: Settings, idp: FakeIdp, issuer: FakeAgentIssuer, clock: FakeClock, lims: FakeLims
) -> Container:
    return await build_container(
        settings,
        signer_resolver=StaticJwks(idp.jwks()),
        agent_resolver=StaticJwks(issuer.jwks()),
        clock=clock,
        connector_transport=httpx.MockTransport(lims),
    )


@pytest.fixture
async def container(
    settings: Settings, idp: FakeIdp, issuer: FakeAgentIssuer, clock: FakeClock, lims: FakeLims
) -> AsyncIterator[Container]:
    built = await make_container(settings, idp, issuer, clock, lims)
    yield built
    await built.aclose()


@pytest.fixture
def runtime(container: Container) -> GxpRuntime:
    return container.runtime


@pytest.fixture
async def provisioned(runtime: GxpRuntime, idp: FakeIdp) -> GxpRuntime:
    await provision(runtime, idp)
    return runtime


@pytest.fixture
def client(
    settings: Settings, idp: FakeIdp, issuer: FakeAgentIssuer, clock: FakeClock, lims: FakeLims
) -> Iterator[TestClient]:
    """App whose container is built inside the app's own event loop by its lifespan."""

    async def factory() -> Container:
        return await make_container(settings, idp, issuer, clock, lims)

    app = create_app(factory, mcp_allowed_hosts=settings.mcp_hosts)
    with TestClient(app, base_url=PUBLIC_URL) as test_client:
        yield test_client


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
