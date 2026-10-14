"""Runtime use cases: request -> risk classification -> approval -> execution record."""

from __future__ import annotations

from datetime import timedelta

import pytest

from gxp_agent_runtime.application.commands import (
    CreateChallenge,
    GenerateReview,
    RegisterDefinition,
)
from gxp_agent_runtime.application.runtime import GxpRuntime
from gxp_agent_runtime.domain.errors import (
    ConflictError,
    ForbiddenError,
    InvalidStateError,
    NotFoundError,
    SignatureError,
    ValidationFailedError,
)
from gxp_agent_runtime.domain.models import (
    Level,
    RecordType,
    RequestStatus,
    ReviewStatus,
    SignatureMeaning,
    SystemStatus,
    ValidationStatus,
)
from tests.conftest import (
    AGENT,
    APPROVER,
    AUDITOR,
    OWNER,
    QA,
    QA2,
    FakeClock,
    FakeIdp,
    FakeLims,
    agent_principal,
    lims_system,
    read_status_spec,
    release_spec,
    sign,
    submission,
)


@pytest.mark.urs("URS-001", "URS-005", "URS-009")
async def test_low_risk_action_executes_autonomously(
    provisioned: GxpRuntime, clock: FakeClock, lims: FakeLims
) -> None:
    view = await provisioned.submit(agent_principal(), submission(clock))
    assert view.status == "completed"
    assert view.risk.priority is Level.LOW
    assert view.policy.matched_rules == ("allow-scoped-low-risk",)
    assert view.execution_record_id == view.request_id
    record = await provisioned.get_record(view.request_id)
    assert record.status == "completed"
    assert record.outputs == {"sample_id": "S-1001", "status": "in-review"}
    assert record.alcoa.passed
    assert lims.idempotency_keys == [view.request_id]
    assert lims.calls[0].url.path == "/api/v1/samples/S-1001"
    verification = await provisioned.verify_record(view.request_id)
    assert verification.verified
    assert {c.principle.value for c in verification.alcoa.checks} >= {"enduring", "available"}


@pytest.mark.urs("URS-002", "URS-003", "URS-004", "URS-006", "URS-009")
async def test_high_risk_action_needs_two_part11_signatures(
    provisioned: GxpRuntime, idp: FakeIdp, clock: FakeClock, lims: FakeLims
) -> None:
    view = await provisioned.submit(agent_principal(), submission(clock, "lims.result.release"))
    assert view.status == "pending_approval"
    assert view.risk.priority is Level.HIGH
    assert view.risk.risk_class == 1
    assert [s.meaning for s in view.outstanding_signatures] == [
        SignatureMeaning.APPROVAL,
        SignatureMeaning.QUALITY_APPROVAL,
    ]
    assert not lims.calls

    first = await sign(
        provisioned,
        idp,
        APPROVER,
        RecordType.ACTION_REQUEST,
        view.request_id,
        SignatureMeaning.APPROVAL,
    )
    assert first.record_status == "pending_approval"
    assert first.signature.signer_name == "Adam Approver"
    assert first.signature.record_digest == view.record_digest
    pending = await provisioned.request_view(await provisioned.get_request(view.request_id))
    assert [s.meaning for s in pending.outstanding_signatures] == [
        SignatureMeaning.QUALITY_APPROVAL
    ]

    second = await sign(
        provisioned,
        idp,
        QA,
        RecordType.ACTION_REQUEST,
        view.request_id,
        SignatureMeaning.QUALITY_APPROVAL,
    )
    assert second.record_status == "completed"
    assert second.execution_record_id == view.request_id
    record = await provisioned.get_record(view.request_id)
    assert [s.meaning for s in record.signatures] == [
        SignatureMeaning.APPROVAL,
        SignatureMeaning.QUALITY_APPROVAL,
    ]
    assert record.outputs is not None
    assert record.outputs["status"] == "released"
    assert lims.calls[0].headers["x-gxp-agent"] == AGENT
    verification = await provisioned.verify_record(view.request_id)
    assert verification.verified
    assert all(s.linked_to_record for s in verification.signatures)


@pytest.mark.urs("URS-006")
async def test_medium_risk_needs_quality_approval_only(
    provisioned: GxpRuntime, idp: FakeIdp, clock: FakeClock
) -> None:
    view = await provisioned.submit(agent_principal(), submission(clock, "lims.result.comment"))
    assert view.risk.priority is Level.MEDIUM
    assert [s.meaning for s in view.outstanding_signatures] == [SignatureMeaning.QUALITY_APPROVAL]
    with pytest.raises(InvalidStateError, match="no outstanding approval"):
        await provisioned.create_challenge(
            CreateChallenge(
                record_type=RecordType.ACTION_REQUEST,
                record_id=view.request_id,
                meaning=SignatureMeaning.APPROVAL,
            ),
            who=idp.principal(APPROVER),
        )
    done = await sign(
        provisioned,
        idp,
        QA,
        RecordType.ACTION_REQUEST,
        view.request_id,
        SignatureMeaning.QUALITY_APPROVAL,
    )
    assert done.record_status == "completed"


@pytest.mark.urs("URS-007")
async def test_rejection_stops_execution(
    provisioned: GxpRuntime, idp: FakeIdp, clock: FakeClock, lims: FakeLims
) -> None:
    view = await provisioned.submit(agent_principal(), submission(clock, "lims.result.release"))
    outcome = await sign(
        provisioned,
        idp,
        QA,
        RecordType.ACTION_REQUEST,
        view.request_id,
        SignatureMeaning.REJECTION,
        reason="Chromatogram integration not reviewed.",
    )
    assert outcome.record_status == "rejected"
    request = await provisioned.get_request(view.request_id)
    assert request.status_reason is not None
    assert "Quinn Quality" in request.status_reason
    assert not lims.calls
    with pytest.raises(InvalidStateError, match="rejected"):
        await sign(
            provisioned,
            idp,
            APPROVER,
            RecordType.ACTION_REQUEST,
            view.request_id,
            SignatureMeaning.APPROVAL,
        )


@pytest.mark.urs("URS-008")
async def test_separation_of_duties(
    provisioned: GxpRuntime, idp: FakeIdp, clock: FakeClock
) -> None:
    view = await provisioned.submit(agent_principal(), submission(clock, "lims.result.release"))
    both = ("dana@corp.test", "Dana Dual", ("gxp-approver", "gxp-qa"))
    await sign(
        provisioned,
        idp,
        both,
        RecordType.ACTION_REQUEST,
        view.request_id,
        SignatureMeaning.APPROVAL,
    )
    with pytest.raises(SignatureError, match="another person"):
        await sign(
            provisioned,
            idp,
            both,
            RecordType.ACTION_REQUEST,
            view.request_id,
            SignatureMeaning.QUALITY_APPROVAL,
        )
    with pytest.raises(ForbiddenError):
        await sign(
            provisioned,
            idp,
            AUDITOR,
            RecordType.ACTION_REQUEST,
            view.request_id,
            SignatureMeaning.QUALITY_APPROVAL,
        )


@pytest.mark.urs("URS-010")
async def test_pending_requests_expire(
    provisioned: GxpRuntime, idp: FakeIdp, clock: FakeClock
) -> None:
    view = await provisioned.submit(agent_principal(), submission(clock, "lims.result.release"))
    clock.advance(hours=73)
    with pytest.raises(InvalidStateError, match="window has elapsed"):
        await sign(
            provisioned,
            idp,
            APPROVER,
            RecordType.ACTION_REQUEST,
            view.request_id,
            SignatureMeaning.APPROVAL,
        )
    assert await provisioned.expire_pending() == 1
    assert (await provisioned.get_request(view.request_id)).status is RequestStatus.EXPIRED
    assert await provisioned.expire_pending() == 0


@pytest.mark.urs("URS-011")
async def test_definition_lifecycle(runtime: GxpRuntime, idp: FakeIdp, clock: FakeClock) -> None:
    owner = idp.principal(OWNER)
    await runtime.register_system(lims_system(), who=owner)
    draft = await runtime.register_definition(
        RegisterDefinition(spec=read_status_spec(), validation_reference="OQ-READ-1"), who=owner
    )
    assert draft.status is ValidationStatus.DRAFT
    with pytest.raises(NotFoundError, match="no validated version"):
        await runtime.submit(agent_principal(), submission(clock))
    denied = await runtime.submit(agent_principal(), submission(clock, version="1.0.0"))
    assert denied.status == "denied"
    assert "deny-unvalidated-definition" in denied.policy.matched_rules

    with pytest.raises(ConflictError, match="greater than"):
        await runtime.register_definition(
            RegisterDefinition(spec=read_status_spec("1.0.0"), validation_reference="OQ-READ-1"),
            who=owner,
        )
    author_qa = (OWNER[0], OWNER[1], ("gxp-system-owner", "gxp-qa"))
    with pytest.raises(SignatureError, match="author"):
        await sign(
            runtime,
            idp,
            author_qa,
            RecordType.ACTION_DEFINITION,
            draft.key,
            SignatureMeaning.VALIDATION_APPROVAL,
        )
    validated = await sign(
        runtime,
        idp,
        QA,
        RecordType.ACTION_DEFINITION,
        draft.key,
        SignatureMeaning.VALIDATION_APPROVAL,
    )
    assert validated.record_status == "validated"

    await runtime.register_definition(
        RegisterDefinition(spec=read_status_spec("1.1.0"), validation_reference="OQ-READ-2"),
        who=owner,
    )
    await sign(
        runtime,
        idp,
        QA2,
        RecordType.ACTION_DEFINITION,
        "lims.sample.read-status@1.1.0",
        SignatureMeaning.VALIDATION_APPROVAL,
    )
    latest = await runtime.submit(agent_principal(), submission(clock))
    assert latest.action_key == "lims.sample.read-status@1.1.0"

    retired = await sign(
        runtime,
        idp,
        QA,
        RecordType.ACTION_DEFINITION,
        "lims.sample.read-status@1.1.0",
        SignatureMeaning.RETIREMENT,
    )
    assert retired.record_status == "retired"
    fallback = await runtime.submit(agent_principal(), submission(clock))
    assert fallback.action_key == "lims.sample.read-status@1.0.0"
    with pytest.raises(InvalidStateError, match="retired"):
        await sign(
            runtime,
            idp,
            QA2,
            RecordType.ACTION_DEFINITION,
            "lims.sample.read-status@1.1.0",
            SignatureMeaning.RETIREMENT,
        )
    other = lims_system("eln-prod", name="Electronic lab notebook")
    await runtime.register_system(other, who=owner)
    with pytest.raises(ConflictError, match="another system"):
        await runtime.register_definition(
            RegisterDefinition(
                spec=read_status_spec("2.0.0", system_id="eln-prod"), validation_reference="OQ-X"
            ),
            who=owner,
        )
    assert len(await runtime.list_definitions(status=ValidationStatus.VALIDATED)) == 1


@pytest.mark.urs("URS-012")
async def test_overdue_periodic_review_blocks_execution(
    runtime: GxpRuntime, idp: FakeIdp, clock: FakeClock
) -> None:
    owner = idp.principal(OWNER)
    await runtime.register_system(
        lims_system(last_reviewed_at=clock.now() - timedelta(days=400)), who=owner
    )
    await runtime.register_definition(
        RegisterDefinition(spec=read_status_spec(), validation_reference="OQ-1"), who=owner
    )
    await sign(
        runtime,
        idp,
        QA,
        RecordType.ACTION_DEFINITION,
        read_status_spec().key,
        SignatureMeaning.VALIDATION_APPROVAL,
    )
    view = await runtime.submit(agent_principal(), submission(clock))
    assert view.status == "denied"
    assert "deny-periodic-review-overdue" in view.policy.matched_rules
    systems = await runtime.list_systems()
    assert systems[0].review_overdue(clock.now())


@pytest.mark.urs("URS-005")
async def test_alcoa_failures_are_denied_and_recorded(
    provisioned: GxpRuntime, clock: FakeClock
) -> None:
    late = submission(clock, performed_at=clock.now() - timedelta(hours=2))
    view = await provisioned.submit(agent_principal(), late)
    assert view.status == "denied"
    assert "deny-data-integrity-failure" in view.policy.matched_rules
    assert "contemporaneous" in view.policy.reason
    bad = submission(clock, inputs={"sample_id": "nope"})
    accurate = await provisioned.submit(agent_principal(), bad)
    assert [c.principle.value for c in accurate.alcoa.failures] == ["accurate"]
    no_source = submission(clock, "lims.result.release", source_records=())
    original = await provisioned.submit(agent_principal(), no_source)
    assert [c.principle.value for c in original.alcoa.failures] == ["original"]


@pytest.mark.urs("URS-013")
async def test_scope_and_delegation_rules(provisioned: GxpRuntime, clock: FakeClock) -> None:
    narrow = agent_principal(scopes=("gxp:read",))
    view = await provisioned.submit(narrow, submission(clock))
    assert view.status == "denied"
    assert "deny-out-of-scope" in view.policy.matched_rules
    assert await provisioned.catalog(narrow) == []
    with pytest.raises(ForbiddenError):
        await provisioned.catalog(agent_principal(scopes=("gxp:execute:*",)))

    delegated = agent_principal(chain=("spiffe://agents.corp.test/agent/qc/orchestrator",))
    pending = await provisioned.submit(delegated, submission(clock))
    assert pending.status == "pending_approval"
    assert [s.meaning for s in pending.outstanding_signatures] == [SignatureMeaning.APPROVAL]
    deep = agent_principal(chain=("spiffe://a/agent/x/one", "spiffe://a/agent/x/two"))
    assert (await provisioned.submit(deep, submission(clock))).status == "denied"
    catalog = await provisioned.catalog(agent_principal())
    assert {c.action_id for c in catalog} == {
        "lims.sample.read-status",
        "lims.result.release",
        "lims.result.comment",
    }


@pytest.mark.urs("URS-014")
async def test_credentials_never_enter_gxp_records(
    provisioned: GxpRuntime, clock: FakeClock
) -> None:
    leaked = submission(clock, justification="use key AKIAABCDEFGHIJKLMNOP to read it")
    with pytest.raises(ValidationFailedError, match="credential"):
        await provisioned.submit(agent_principal(), leaked)


@pytest.mark.urs("URS-009")
async def test_nonconforming_output_and_rejected_call_fail_the_record(
    provisioned: GxpRuntime, idp: FakeIdp, clock: FakeClock, lims: FakeLims
) -> None:
    lims.malformed_output = True
    view = await provisioned.submit(agent_principal(), submission(clock, "lims.result.release"))
    for who, meaning in (
        (APPROVER, SignatureMeaning.APPROVAL),
        (QA, SignatureMeaning.QUALITY_APPROVAL),
    ):
        outcome = await sign(
            provisioned, idp, who, RecordType.ACTION_REQUEST, view.request_id, meaning
        )
    assert outcome.record_status == "failed"
    record = await provisioned.get_record(view.request_id)
    assert record.error is not None
    assert "output schema" in record.error
    assert [c.principle.value for c in record.alcoa.failures] == ["accurate"]

    lims.malformed_output = False
    lims.reject_with = 409
    rejected = await provisioned.submit(agent_principal(), submission(clock))
    assert rejected.status == "failed"
    assert (await provisioned.get_record(rejected.request_id)).http_status == 409


@pytest.mark.urs("URS-015")
async def test_periodic_review_cycle(
    provisioned: GxpRuntime, idp: FakeIdp, clock: FakeClock, lims: FakeLims
) -> None:
    start = clock.now() - timedelta(days=1)
    await provisioned.submit(agent_principal(), submission(clock))
    lims.reject_with = 500
    await provisioned.submit(agent_principal(), submission(clock))
    lims.reject_with = None
    clock.advance(minutes=5)
    review = await provisioned.generate_review(
        GenerateReview(system_id="lims-prod", period_start=start, period_end=clock.now()),
        who=idp.principal(OWNER),
    )
    assert review.metrics.executions_completed == 1
    assert review.metrics.executions_failed == 1
    assert review.metrics.audit_integrity
    assert set(review.metrics.definitions_validated) == {
        "lims.sample.read-status@1.0.0",
        "lims.result.release@1.0.0",
        "lims.result.comment@1.0.0",
    }
    assert review.conclusion == "remediation-required"
    assert any("failure rate" in f for f in review.findings)

    approved = await sign(
        provisioned,
        idp,
        QA,
        RecordType.PERIODIC_REVIEW,
        review.review_id,
        SignatureMeaning.REVIEW,
    )
    assert approved.record_status == "approved"
    system = await provisioned.get_system("lims-prod")
    assert system.status is SystemStatus.SUSPENDED
    assert system.last_reviewed_at == clock.now()
    blocked = await provisioned.submit(agent_principal(), submission(clock))
    assert "deny-system-not-validated" in blocked.policy.matched_rules

    clock.advance(minutes=1)
    clean = await provisioned.generate_review(
        GenerateReview(
            system_id="lims-prod",
            period_start=clock.now() - timedelta(seconds=30),
            period_end=clock.now(),
        ),
        who=idp.principal(QA),
    )
    assert clean.conclusion == "remains-validated"
    with pytest.raises(SignatureError, match="generated"):
        await sign(
            provisioned,
            idp,
            QA,
            RecordType.PERIODIC_REVIEW,
            clean.review_id,
            SignatureMeaning.REVIEW,
        )
    await sign(
        provisioned,
        idp,
        QA2,
        RecordType.PERIODIC_REVIEW,
        clean.review_id,
        SignatureMeaning.REVIEW,
    )
    assert (await provisioned.get_system("lims-prod")).status is SystemStatus.VALIDATED
    assert (await provisioned.get_review(clean.review_id)).status is ReviewStatus.APPROVED
    with pytest.raises(InvalidStateError, match="already approved"):
        await provisioned.create_challenge(
            CreateChallenge(
                record_type=RecordType.PERIODIC_REVIEW,
                record_id=clean.review_id,
                meaning=SignatureMeaning.REVIEW,
            ),
            who=idp.principal(QA2),
        )


async def test_review_input_validation(
    provisioned: GxpRuntime, idp: FakeIdp, clock: FakeClock
) -> None:
    owner = idp.principal(OWNER)
    with pytest.raises(ValidationFailedError, match="after"):
        await provisioned.generate_review(
            GenerateReview(system_id="lims-prod", period_start=clock.now(), period_end=clock.now()),
            who=owner,
        )
    with pytest.raises(ValidationFailedError, match="future"):
        await provisioned.generate_review(
            GenerateReview(
                system_id="lims-prod",
                period_start=clock.now(),
                period_end=clock.now() + timedelta(days=1),
            ),
            who=owner,
        )
    with pytest.raises(ForbiddenError):
        await provisioned.generate_review(
            GenerateReview(
                system_id="lims-prod",
                period_start=clock.now() - timedelta(days=1),
                period_end=clock.now(),
            ),
            who=idp.principal(APPROVER),
        )


async def test_registry_guards(runtime: GxpRuntime, idp: FakeIdp, clock: FakeClock) -> None:
    owner = idp.principal(OWNER)
    with pytest.raises(ForbiddenError):
        await runtime.register_system(lims_system(), who=idp.principal(QA))
    with pytest.raises(ValidationFailedError, match="future"):
        await runtime.register_system(
            lims_system(last_reviewed_at=clock.now() + timedelta(days=2)), who=owner
        )
    await runtime.register_system(lims_system(), who=owner)
    with pytest.raises(ConflictError):
        await runtime.register_system(lims_system(), who=owner)
    with pytest.raises(NotFoundError):
        await runtime.get_system("missing")
    with pytest.raises(NotFoundError):
        await runtime.register_definition(
            RegisterDefinition(
                spec=read_status_spec(system_id="eln"), validation_reference="OQ-ELN"
            ),
            who=owner,
        )
    with pytest.raises(NotFoundError):
        await runtime.get_definition("lims.result.release", "9.9.9")
    with pytest.raises(NotFoundError):
        await runtime.get_request("missing")
    with pytest.raises(NotFoundError):
        await runtime.get_record("missing")
    with pytest.raises(NotFoundError):
        await runtime.get_review("missing")
    with pytest.raises(ValidationFailedError, match="does not apply"):
        await runtime.create_challenge(
            CreateChallenge(
                record_type=RecordType.ACTION_DEFINITION,
                record_id=release_spec().key,
                meaning=SignatureMeaning.APPROVAL,
            ),
            who=idp.principal(QA),
        )


async def test_agents_only_see_their_own_requests(
    provisioned: GxpRuntime, clock: FakeClock
) -> None:
    view = await provisioned.submit(agent_principal(), submission(clock))
    other = agent_principal(sub="spiffe://agents.corp.test/agent/qc/other")
    with pytest.raises(NotFoundError):
        await provisioned.agent_request(other, view.request_id)
    with pytest.raises(NotFoundError):
        await provisioned.agent_record(other, view.request_id)
    assert (await provisioned.agent_request(agent_principal(), view.request_id)).status == (
        "completed"
    )
    assert (await provisioned.agent_record(agent_principal(), view.request_id)).agent_id == AGENT
    listed = await provisioned.list_requests(status=RequestStatus.COMPLETED, system_id="lims-prod")
    assert [r.request_id for r in listed] == [view.request_id]
    preview = await provisioned.preview(agent_principal(), submission(clock, "lims.result.release"))
    assert not preview.would_execute_immediately
    assert len(preview.required_signatures) == 2
    signatures = await provisioned.list_signatures(RecordType.ACTION_DEFINITION, release_spec().key)
    assert [s.meaning for s in signatures] == [SignatureMeaning.VALIDATION_APPROVAL]
