"""Configuration, composition root, persistence adapters, published contracts."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from gxp_agent_runtime.api.app import expire_pending_forever
from gxp_agent_runtime.config import Settings
from gxp_agent_runtime.contracts import main as contracts_main
from gxp_agent_runtime.domain.errors import ConflictError, NotFoundError
from gxp_agent_runtime.domain.models import (
    PeriodicReview,
    RecordType,
    ReviewMetrics,
    ReviewStatus,
    SignatureMeaning,
    SigningChallenge,
)
from gxp_agent_runtime.infrastructure.database import (
    SqlChallengeRepository,
    SqlDefinitionRepository,
    SqlRecordRepository,
    SqlRequestRepository,
    SqlReviewRepository,
    SqlSystemRepository,
)
from gxp_agent_runtime.runtime.container import Container, build_container
from gxp_agent_runtime.security.agents import FabricAgentGateway, LocalAgentGateway
from gxp_agent_runtime.security.keys import RecordSigner, SignatureVerifier
from tests.conftest import (
    HUMAN_ISSUER,
    PUBLIC_URL,
    ROOT,
    FakeClock,
    FakeIdp,
    agent_principal,
    submission,
)

BASE: dict[str, Any] = {
    "environment": "test",
    "public_url": PUBLIC_URL,
    "database_url": "sqlite+aiosqlite:///:memory:",
    "signer_issuer": HUMAN_ISSUER,
    "signer_audience": "gxp-agent-runtime",
    "signer_jwks_url": f"{HUMAN_ISSUER}/keys",
    "fabric_url": "https://identity.corp.test",
    "policy_file": ROOT / "policies" / "gxp-runtime.yaml",
}


def write_key(path: Path) -> Path:
    key = Ed25519PrivateKey.generate()
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return path


class TestSettings:
    def test_production_refuses_ephemeral_keys_and_plain_http(self) -> None:
        with pytest.raises(ValidationError, match="production"):
            Settings(**{**BASE, "environment": "production", "dev_ephemeral_keys": True})
        with pytest.raises(ValidationError, match="https"):
            Settings(
                **{**BASE, "environment": "production", "public_url": "http://gxp.corp.test"},
                dev_ephemeral_keys=False,
                signing_key_file="a.pem",
                audit_key_file="b.pem",
            )
        with pytest.raises(ValidationError, match="absolute URL"):
            Settings(**{**BASE, "public_url": "gxp.corp.test", "dev_ephemeral_keys": True})

    def test_keys_and_agent_verification_are_required(self) -> None:
        with pytest.raises(ValidationError, match="signing configuration incomplete"):
            Settings(**BASE)
        no_agents = {k: v for k, v in BASE.items() if k != "fabric_url"}
        with pytest.raises(ValidationError, match="GXP_FABRIC_URL"):
            Settings(**no_agents, dev_ephemeral_keys=True)
        with pytest.raises(ValidationError, match="go together"):
            Settings(**BASE, dev_ephemeral_keys=True, runtime_client_id="spiffe://a/agent/b/c")
        with pytest.raises(ValidationError, match="require GXP_FABRIC_URL"):
            Settings(
                **no_agents,
                dev_ephemeral_keys=True,
                agent_issuer="https://identity.corp.test",
                agent_jwks_url="https://identity.corp.test/jwks",
                runtime_client_id="spiffe://a/agent/b/c",
                workload_token_file="/var/run/token",
            )

    def test_derived_values(self) -> None:
        settings = Settings(**BASE, dev_ephemeral_keys=True, mcp_allowed_hosts=["gxp.svc:80"])
        assert settings.mcp_hosts == ["gxp-runtime.corp.test", "gxp.svc:80"]
        assert settings.public_base == PUBLIC_URL
        assert settings.approval_ttl == timedelta(hours=72)


async def test_container_with_key_files_and_fabric(tmp_path: Path) -> None:
    signing = write_key(tmp_path / "records-2026-10.pem")
    audit = write_key(tmp_path / "audit-2026-10.pem")
    retired_dir = tmp_path / "retired"
    retired_dir.mkdir()
    retired = Ed25519PrivateKey.generate().public_key()
    (retired_dir / "records-2026-04.pem").write_bytes(
        retired.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    token = tmp_path / "token"
    token.write_text("sa-token", encoding="utf-8")
    settings = Settings(
        **{**BASE, "database_url": f"sqlite+aiosqlite:///{tmp_path / 'c.db'}"},
        signing_key_file=signing,
        audit_key_file=audit,
        trusted_public_keys_dir=retired_dir,
        runtime_client_id="spiffe://agents.corp.test/agent/platform/gxp-runtime",
        workload_token_file=token,
    )
    container = await build_container(
        settings, fabric_transport=httpx.MockTransport(lambda _: httpx.Response(503))
    )
    try:
        assert container.signer.key_id == "records-2026-10"
        assert container.audit_signer.key_id == "audit-2026-10"
        assert isinstance(container.runtime.agents, FabricAgentGateway)
        assert set(container.runtime._verifier.keys) == {"records-2026-10", "records-2026-04"}
        assert container.signer.jwk("records")["kid"] == "records-2026-10"
    finally:
        await container.aclose()


def test_key_loading_rejects_wrong_key_types(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives.asymmetric import ec

    path = tmp_path / "ec.pem"
    path.write_bytes(
        ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(ValueError, match="Ed25519 private"):
        RecordSigner.from_file(path)
    public_dir = tmp_path / "pub"
    public_dir.mkdir()
    (public_dir / "k.pem").write_bytes(
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    with pytest.raises(ValueError, match="Ed25519 public"):
        SignatureVerifier.from_directory(public_dir)
    signer = RecordSigner.ephemeral("k1")
    verifier = SignatureVerifier({"k1": signer.public_key})
    signature = signer.sign_document({"a": 1})
    assert verifier.verify_document("k1", {"a": 1}, signature)
    assert not verifier.verify_document("k1", {"a": 2}, signature)
    assert not verifier.verify_document("k2", {"a": 1}, signature)
    assert not verifier.verify_document("k1", {"a": 1}, "!!notbase64")


async def test_local_gateway_selected_without_fabric(container: Container) -> None:
    assert isinstance(container.runtime.agents, LocalAgentGateway)
    assert container.chain_id.startswith("test-")


async def test_repositories_guard_against_lost_updates(
    container: Container, idp: FakeIdp, clock: FakeClock
) -> None:
    from tests.conftest import provision

    engine = container.engine
    await provision(container.runtime, idp)
    view = await container.runtime.submit(
        agent_principal(), submission(clock, "lims.result.release")
    )
    requests = SqlRequestRepository(engine)
    stored = await requests.get(view.request_id)
    assert stored is not None
    await requests.replace(stored.model_copy(update={"revision": 1}), expected_revision=0)
    with pytest.raises(ConflictError, match="concurrently"):
        await requests.replace(stored.model_copy(update={"revision": 1}), expected_revision=0)

    systems = SqlSystemRepository(engine)
    system = await systems.get("lims-prod")
    assert system is not None
    with pytest.raises(NotFoundError):
        await systems.update(system.model_copy(update={"system_id": "ghost"}))
    definitions = SqlDefinitionRepository(engine)
    definition = await definitions.get("lims.result.release", "1.0.0")
    assert definition is not None
    with pytest.raises(ConflictError):
        await definitions.add(definition)
    with pytest.raises(NotFoundError):
        await definitions.update(
            definition.model_copy(
                update={"spec": definition.spec.model_copy(update={"version": "9.0.0"})}
            )
        )
    records = SqlRecordRepository(engine)
    completed = await container.runtime.submit(agent_principal(), submission(clock))
    record = await records.get(completed.request_id)
    assert record is not None
    with pytest.raises(ConflictError):
        await records.add(record)
    assert await records.recent_outcomes("lims.sample.read-status", 5) == ["completed"]
    reviews = SqlReviewRepository(engine)
    ghost = PeriodicReview(
        review_id="ghost",
        system_id="lims-prod",
        period_start=clock.now(),
        period_end=clock.now(),
        generated_at=clock.now(),
        generated_by="x",
        metrics=ReviewMetrics(
            requests_by_status={},
            executions_completed=0,
            executions_failed=0,
            failure_rate=0,
            signatures_by_meaning={},
            alcoa_failures=0,
            definitions_validated=(),
            definitions_retired=(),
            audit_events_verified=0,
            audit_chains_verified=0,
            audit_integrity=True,
        ),
        findings=(),
        conclusion="remains-validated",
        status=ReviewStatus.DRAFT,
    )
    with pytest.raises(NotFoundError):
        await reviews.update(ghost)
    challenges = SqlChallengeRepository(engine)
    challenge = SigningChallenge(
        challenge_id="c-1",
        nonce="n",
        record_type=RecordType.ACTION_REQUEST,
        record_id="r",
        record_digest="d",
        meaning=SignatureMeaning.APPROVAL,
        subject="s",
        created_at=clock.now(),
        expires_at=clock.now(),
    )
    await challenges.add(challenge)
    assert await challenges.consume("c-1", clock.now())
    assert not await challenges.consume("c-1", clock.now())
    used = await challenges.get("c-1")
    assert used is not None
    assert used.used_at is not None
    assert await challenges.get("missing") is None


async def test_expiry_sweeper_survives_errors(container: Container) -> None:
    calls = 0

    async def failing() -> int:
        nonlocal calls
        calls += 1
        raise RuntimeError("database blip")

    container.runtime.expire_pending = failing  # type: ignore[method-assign]

    async def sleep(_: float) -> None:
        if calls >= 2:
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await expire_pending_forever(container, 0.01, sleep=sleep)
    assert calls == 2


def test_committed_contracts_are_current() -> None:
    assert contracts_main(["--check"], root=ROOT) == 0


def test_contract_export_round_trip(tmp_path: Path) -> None:
    assert contracts_main(["--check"], root=tmp_path) == 1
    assert contracts_main([], root=tmp_path) == 0
    assert contracts_main(["--check"], root=tmp_path) == 0
    assert (tmp_path / "schemas" / "execution-record.schema.json").is_file()
    assert (tmp_path / "docs" / "api" / "openapi.json").is_file()


def test_linkedin_article_length_is_within_publishing_limits() -> None:
    article = (ROOT / "docs" / "linkedin-article.md").read_text(encoding="utf-8").strip()
    assert 2000 <= len(article) <= 2500
    assert "https://github.com/kogunlowo123/gxp-agent-runtime" in article
