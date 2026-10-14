"""Domain rules: GAMP 5 risk method, ALCOA+ checks, registry model validation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from gxp_agent_runtime.domain.alcoa import AlcoaChecker, schema_errors
from gxp_agent_runtime.domain.models import (
    AlcoaAssessment,
    ElectronicSignature,
    ExecutionRecord,
    GampCategory,
    GxpImpact,
    HttpBinding,
    Level,
    PolicyOutcome,
    RecordType,
    SignatureMeaning,
    SourceRecord,
    ValidatedSystem,
    digest_of,
)
from gxp_agent_runtime.domain.risk import (
    APPROVAL,
    QUALITY_APPROVAL,
    RISK_CLASS,
    RISK_PRIORITY,
    FailureHistory,
    RiskClassifier,
)
from tests.conftest import AGENT, SOURCE, comment_spec, read_status_spec, release_spec

H, M, L = Level.HIGH, Level.MEDIUM, Level.LOW


class TestRiskMethod:
    @pytest.mark.urs("URS-004")
    def test_risk_class_matrix_is_complete_and_monotonic(self) -> None:
        assert len(RISK_CLASS) == 9
        assert len(RISK_PRIORITY) == 9
        for severity in Level:
            classes = [RISK_CLASS[(severity, p)] for p in (L, M, H)]
            assert classes == sorted(classes, reverse=True)
        for risk_class in (1, 2, 3):
            ranks = [RISK_PRIORITY[(risk_class, d)].rank for d in (H, M, L)]
            assert ranks == sorted(ranks)

    @pytest.mark.urs("URS-004", "URS-006")
    @pytest.mark.parametrize(
        ("spec", "priority", "risk_class", "signatures"),
        [
            (read_status_spec(), L, 3, ()),
            (comment_spec(), M, 2, (QUALITY_APPROVAL,)),
            (release_spec(), H, 1, (APPROVAL, QUALITY_APPROVAL)),
        ],
    )
    def test_assessment(
        self, spec: Any, priority: Level, risk_class: int, signatures: tuple[Any, ...]
    ) -> None:
        assessment = RiskClassifier().assess(spec)
        assert assessment.priority is priority
        assert assessment.risk_class == risk_class
        assert assessment.required_signatures == signatures
        assert assessment.rationale[0].startswith("severity")

    @pytest.mark.urs("URS-004")
    def test_failure_history_raises_probability(self) -> None:
        classifier = RiskClassifier(elevated_failure_rate=0.05, minimum_history=20)
        spec = read_status_spec()
        calm = classifier.assess(spec, history=FailureHistory(executions=40, failures=1))
        assert calm.probability is M
        noisy = classifier.assess(spec, history=FailureHistory(executions=40, failures=4))
        assert noisy.probability is H
        assert any("observed failure rate" in r for r in noisy.rationale)
        sparse = classifier.assess(spec, history=FailureHistory(executions=5, failures=5))
        assert sparse.probability is M
        assert FailureHistory().rate == 0.0

    def test_low_priority_record_creation_needs_approval(self) -> None:
        spec = read_status_spec().model_copy(update={"creates_gxp_record": True})
        assert RiskClassifier.required_signatures(spec, L) == (APPROVAL,)
        irreversible = read_status_spec().model_copy(update={"reversible": False})
        assert RiskClassifier.required_signatures(irreversible, L) == (APPROVAL,)

    def test_classifier_rejects_bad_threshold(self) -> None:
        with pytest.raises(ValueError, match="between 0 and 1"):
            RiskClassifier(elevated_failure_rate=1.5)

    def test_level_helpers(self) -> None:
        assert Level.of_rank(0) is L
        assert Level.of_rank(9) is H
        assert GxpImpact(patient_safety=L, product_quality=H, data_integrity=M).severity is H


class TestAlcoa:
    checker = AlcoaChecker()
    now = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)

    def assess(self, **overrides: Any) -> AlcoaAssessment:
        values: dict[str, Any] = {
            "spec": release_spec(),
            "agent_id": AGENT,
            "inputs": {"sample_id": "S-1001", "disposition": "conforming", "batch_id": "B-1"},
            "justification": "Results meet specification SPEC-114.",
            "context": {"batch_id": "B-1"},
            "source_records": (SOURCE,),
            "performed_at": self.now - timedelta(seconds=30),
            "received_at": self.now,
        }
        values.update(overrides)
        return self.checker.assess_request(**values)

    def failed(self, **overrides: Any) -> list[str]:
        return [c.principle.value for c in self.assess(**overrides).failures]

    @pytest.mark.urs("URS-005")
    def test_clean_request_passes_every_principle(self) -> None:
        assessment = self.assess()
        assert assessment.passed
        assert len(assessment.checks) == 7

    @pytest.mark.urs("URS-005")
    @pytest.mark.parametrize(
        ("overrides", "principle"),
        [
            ({"agent_id": "release-bot"}, "attributable"),
            ({"justification": "ok\x07 bell"}, "legible"),
            ({"performed_at": datetime(2026, 10, 14, 13, 0, tzinfo=UTC)}, "contemporaneous"),
            ({"performed_at": datetime(2026, 10, 14, 9, 0, tzinfo=UTC)}, "contemporaneous"),
            ({"performed_at": datetime(2026, 10, 14, 11, 59)}, "contemporaneous"),
            ({"source_records": ()}, "original"),
            (
                {"inputs": {"sample_id": "S-1001", "disposition": "maybe", "batch_id": "B-1"}},
                "accurate",
            ),
            ({"justification": "short"}, "complete"),
            ({"context": {"batch_id": "B-2"}}, "consistent"),
        ],
    )
    def test_each_principle_detects_its_failure(
        self, overrides: dict[str, Any], principle: str
    ) -> None:
        assert principle in self.failed(**overrides)

    def test_nulls_are_incomplete(self) -> None:
        inputs = {"sample_id": "S-1001", "disposition": "conforming", "batch_id": None}
        assert "complete" in self.failed(inputs=inputs)
        nested = {"sample_id": "S-1001", "disposition": "conforming", "batch_id": "B", "x": [None]}
        assert "complete" in self.failed(inputs=nested)

    def test_schema_errors_are_reported_with_paths(self) -> None:
        errors = schema_errors(release_spec().input_schema, {"sample_id": 7})
        assert any(e.startswith("sample_id:") for e in errors)
        assert any(e.startswith("<root>:") for e in errors)

    def _record(self, **overrides: Any) -> ExecutionRecord:
        outputs = {"sample_id": "S-1", "status": "released", "result_version": 2}
        values: dict[str, Any] = {
            "record_id": "r1",
            "request_id": "r1",
            "action_key": "lims.result.release@1.0.0",
            "definition_digest": "sha256:" + "c" * 64,
            "system_id": "lims-prod",
            "agent_id": AGENT,
            "delegation_chain": (),
            "request_digest": "sha256:" + "d" * 64,
            "inputs_digest": "sha256:" + "e" * 64,
            "outputs": outputs,
            "outputs_digest": digest_of(outputs),
            "response_digest": "sha256:" + "f" * 64,
            "http_status": 201,
            "status": "completed",
            "error": None,
            "received_at": self.now,
            "started_at": self.now + timedelta(seconds=10),
            "completed_at": self.now + timedelta(seconds=11),
            "recorded_at": self.now + timedelta(seconds=11),
            "risk": RiskClassifier().assess(release_spec()),
            "policy": PolicyOutcome(
                decision="require_approval",
                matched_rules=(),
                policy_version="1",
                policy_digest="sha256:" + "0" * 64,
                reason="r",
            ),
            "signatures": (),
            "alcoa": AlcoaAssessment(checks=()),
        }
        values.update(overrides)
        return ExecutionRecord(**values)

    def _signature(self, meaning: SignatureMeaning, **overrides: Any) -> ElectronicSignature:
        values: dict[str, Any] = {
            "signature_id": f"s-{meaning.value}",
            "record_type": RecordType.ACTION_REQUEST,
            "record_id": "r1",
            "record_digest": "sha256:" + "d" * 64,
            "signer_subject": "adam@corp.test",
            "signer_name": "Adam",
            "meaning": meaning,
            "reason": "approved",
            "signed_at": self.now + timedelta(seconds=5),
            "auth_time": self.now,
            "auth_methods": ("pwd",),
            "challenge_id": "c1",
            "key_id": "k",
        }
        values.update(overrides)
        return ElectronicSignature(**values)

    def record_failures(
        self, record: ExecutionRecord, signatures: list[ElectronicSignature]
    ) -> list[str]:
        spec = release_spec()
        required = RiskClassifier().assess(spec).required_signatures
        assessment = self.checker.assess_record(
            record=record,
            output_schema=spec.output_schema,
            required=required,
            signatures=signatures,
        )
        return [c.principle.value for c in assessment.failures]

    @pytest.mark.urs("URS-009")
    def test_record_principles(self) -> None:
        good = [
            self._signature(SignatureMeaning.APPROVAL),
            self._signature(SignatureMeaning.QUALITY_APPROVAL, signature_id="s2"),
        ]
        assert self.record_failures(self._record(), good) == []
        assert "complete" in self.record_failures(self._record(), good[:1])
        unlinked = [
            *good[:1],
            self._signature(SignatureMeaning.QUALITY_APPROVAL, record_digest="x"),
        ]
        assert "consistent" in self.record_failures(self._record(), unlinked)
        late = [
            *good[:1],
            self._signature(
                SignatureMeaning.QUALITY_APPROVAL, signed_at=self.now + timedelta(minutes=5)
            ),
        ]
        assert "consistent" in self.record_failures(self._record(), late)
        assert "original" in self.record_failures(
            self._record(outputs_digest="sha256:" + "1" * 64), good
        )
        assert "original" in self.record_failures(self._record(response_digest=None), good)
        assert "accurate" in self.record_failures(
            self._record(outputs={"sample_id": "S"}, outputs_digest=digest_of({"sample_id": "S"})),
            good,
        )
        assert "contemporaneous" in self.record_failures(
            self._record(recorded_at=self.now + timedelta(minutes=10)), good
        )
        assert "legible" in self.record_failures(
            self._record(
                outputs={"sample_id": "S\x00", "status": "released", "result_version": 1},
                outputs_digest=digest_of(
                    {"sample_id": "S\x00", "status": "released", "result_version": 1}
                ),
            ),
            good,
        )
        assert "attributable" in self.record_failures(self._record(agent_id=""), good)
        unsigned = [self._signature(SignatureMeaning.APPROVAL, signer_subject=""), good[1]]
        assert "attributable" in self.record_failures(self._record(), unsigned)

    def test_storage_checks(self) -> None:
        record = self._record()
        ok = AlcoaChecker.assess_storage(record=record, audit_events=1, readback=record)
        assert ok.passed
        lost = AlcoaChecker.assess_storage(record=record, audit_events=0, readback=None)
        assert [c.principle.value for c in lost.failures] == ["enduring", "available"]
        altered = AlcoaChecker.assess_storage(
            record=record, audit_events=1, readback=self._record(error="edited")
        )
        assert [c.principle.value for c in altered.failures] == ["available"]


class TestModels:
    def test_system_requires_https_and_slug(self) -> None:
        base: dict[str, Any] = {
            "system_id": "lims-prod",
            "name": "LIMS",
            "description": "Laboratory system of record.",
            "base_url": "https://lims.corp.test/",
            "gamp_category": GampCategory.CONFIGURED,
            "validation_reference": "VSR-1",
            "owner": "qc",
            "review_interval_days": 365,
            "last_reviewed_at": datetime(2026, 1, 1, tzinfo=UTC),
            "registered_at": datetime(2026, 1, 1, tzinfo=UTC),
            "updated_at": datetime(2026, 1, 1, tzinfo=UTC),
        }
        system = ValidatedSystem(**base)
        assert system.base_url == "https://lims.corp.test"
        assert system.review_due_at == datetime(2027, 1, 1, tzinfo=UTC)
        assert not system.review_overdue(datetime(2026, 12, 31, tzinfo=UTC))
        for bad in ("http://lims.corp.test", "https://lims.corp.test/?x=1", "ftp://x"):
            with pytest.raises(ValidationError):
                ValidatedSystem(**{**base, "base_url": bad})
        with pytest.raises(ValidationError):
            ValidatedSystem(**{**base, "system_id": "LIMS PROD"})

    @pytest.mark.urs("URS-001")
    def test_action_spec_validation(self) -> None:
        spec = release_spec()
        assert spec.key == "lims.result.release@1.0.0"
        assert spec.version_tuple == (1, 0, 0)
        assert spec.digest == release_spec().digest
        assert spec.digest != release_spec("1.0.1").digest
        data = spec.model_dump()
        with pytest.raises(ValidationError, match="dotted"):
            type(spec).model_validate({**data, "action_id": "Release"})
        with pytest.raises(ValidationError, match="MAJOR"):
            type(spec).model_validate({**data, "version": "1.0"})
        with pytest.raises(ValidationError, match="slug"):
            type(spec).model_validate({**data, "system_id": "LIMS"})
        with pytest.raises(ValidationError, match="valid JSON Schema"):
            type(spec).model_validate({**data, "input_schema": {"type": 5}})
        with pytest.raises(ValidationError, match="object"):
            type(spec).model_validate({**data, "output_schema": {"type": "string"}})
        with pytest.raises(ValidationError, match="placeholder"):
            type(spec).model_validate(
                {**data, "binding": {"method": "POST", "path": "/api/{missing}"}}
            )

    def test_binding_rendering(self) -> None:
        binding = HttpBinding(method="POST", path="/api/v1/results/{sample_id}/release")
        assert binding.placeholders == ("sample_id",)
        rendered = binding.render_path({"sample_id": "../../admin?x=1"})
        assert rendered == "/api/v1/results/..%2F..%2Fadmin%3Fx%3D1/release"
        assert binding.body({"sample_id": "S", "disposition": "ok"}) == {"disposition": "ok"}
        assert HttpBinding(method="GET", path="/a").body({"x": 1}) is None
        for path in ("relative", "/a/../b", "/a?b", "/a#b"):
            with pytest.raises(ValidationError):
                HttpBinding(method="GET", path=path)
        for statuses in ((), (404,)):
            with pytest.raises(ValidationError):
                HttpBinding(method="GET", path="/a", success_statuses=statuses)

    def test_source_record_digest_format(self) -> None:
        with pytest.raises(ValidationError):
            SourceRecord(uri="lims://x", digest="md5:abc")

    def test_digest_is_canonical(self) -> None:
        assert digest_of({"a": 1, "b": 2}) == digest_of({"b": 2, "a": 1})
