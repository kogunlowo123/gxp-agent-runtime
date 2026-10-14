"""GxP runtime domain model.

Validated systems and versioned action definitions form the registry; agents
submit action requests that are risk-classified, approved with 21 CFR Part 11
electronic signatures where required, executed through the definition's
binding, and preserved as execution records.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from enum import IntEnum, StrEnum
from typing import Any, Literal
from urllib.parse import quote, urlsplit

from agentic_core.domain.provenance import canonical_json, content_digest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SLUG = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,62}[a-z0-9])?$")
ACTION_ID = re.compile(r"^[a-z0-9]+(?:[.\-][a-z0-9]+){1,7}$")
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)\}")


class Level(StrEnum):
    """Three-point scale used by GAMP 5 quality risk management."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"low": 1, "medium": 2, "high": 3}[self.value]

    @classmethod
    def of_rank(cls, rank: int) -> Level:
        return {1: cls.LOW, 2: cls.MEDIUM, 3: cls.HIGH}[max(1, min(3, rank))]


class GampCategory(IntEnum):
    """GAMP 5 (2nd edition) software categories. Category 2 was retired."""

    INFRASTRUCTURE = 1
    NON_CONFIGURED = 3
    CONFIGURED = 4
    CUSTOM = 5


class SystemStatus(StrEnum):
    VALIDATED = "validated"
    SUSPENDED = "suspended"
    RETIRED = "retired"


class ValidationStatus(StrEnum):
    DRAFT = "draft"
    VALIDATED = "validated"
    RETIRED = "retired"


class SignatureMeaning(StrEnum):
    """Meaning of an electronic signature (21 CFR 11.50(a)(3))."""

    APPROVAL = "approval"
    QUALITY_APPROVAL = "quality-approval"
    REJECTION = "rejection"
    VALIDATION_APPROVAL = "validation-approval"
    RETIREMENT = "retirement"
    REVIEW = "review"


class RecordType(StrEnum):
    ACTION_REQUEST = "action-request"
    ACTION_DEFINITION = "action-definition"
    PERIODIC_REVIEW = "periodic-review"


class Role(StrEnum):
    """Enterprise IdP roles of human users."""

    SYSTEM_OWNER = "gxp-system-owner"
    APPROVER = "gxp-approver"
    QUALITY = "gxp-qa"
    AUDITOR = "gxp-auditor"


class RequestStatus(StrEnum):
    PENDING_APPROVAL = "pending_approval"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"
    EXPIRED = "expired"
    DENIED = "denied"

    @property
    def terminal(self) -> bool:
        return self not in {RequestStatus.PENDING_APPROVAL, RequestStatus.EXECUTING}


class ReviewStatus(StrEnum):
    DRAFT = "draft"
    APPROVED = "approved"


def digest_of(value: Any) -> str:
    """sha256 over canonical JSON; the integrity primitive for every record."""
    return content_digest(canonical_json(value))


# --------------------------------------------------------------------- registry


class ValidatedSystem(BaseModel):
    """A computerized system in validated state that agent actions may touch."""

    model_config = ConfigDict(frozen=True)

    system_id: str
    name: str = Field(min_length=3, max_length=120)
    description: str = Field(min_length=10, max_length=2000)
    base_url: str = Field(description="HTTPS endpoint of the system's integration API")
    gamp_category: GampCategory
    validation_reference: str = Field(
        min_length=3, max_length=120, description="Validation summary report identifier"
    )
    owner: str = Field(min_length=2, max_length=200, description="Accountable system owner")
    review_interval_days: int = Field(ge=30, le=1095)
    status: SystemStatus = SystemStatus.VALIDATED
    last_reviewed_at: datetime
    registered_at: datetime
    updated_at: datetime

    @field_validator("system_id")
    @classmethod
    def _slug(cls, value: str) -> str:
        if not SLUG.fullmatch(value):
            raise ValueError("system_id must be a lowercase slug")
        return value

    @field_validator("base_url")
    @classmethod
    def _https(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme != "https" or not parts.hostname or parts.query or parts.fragment:
            raise ValueError("base_url must be an https URL without query or fragment")
        return value.rstrip("/")

    @property
    def review_due_at(self) -> datetime:
        return self.last_reviewed_at + timedelta(days=self.review_interval_days)

    def review_overdue(self, now: datetime) -> bool:
        return now > self.review_due_at


class GxpImpact(BaseModel):
    """Impact of a failed or wrong execution on the three GxP concerns."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    patient_safety: Level
    product_quality: Level
    data_integrity: Level

    @property
    def severity(self) -> Level:
        return max(
            (self.patient_safety, self.product_quality, self.data_integrity),
            key=lambda level: level.rank,
        )


class HttpBinding(BaseModel):
    """How the runtime invokes the action on the validated system."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    method: Literal["GET", "POST", "PUT", "PATCH"]
    path: str = Field(min_length=1, max_length=300)
    success_statuses: tuple[int, ...] = (200, 201, 202)

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        if not value.startswith("/") or ".." in value or "?" in value or "#" in value:
            raise ValueError("path must be absolute without '..', query or fragment")
        return value

    @field_validator("success_statuses")
    @classmethod
    def _statuses(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if not value or any(s < 200 or s > 299 for s in value):
            raise ValueError("success_statuses must be non-empty 2xx codes")
        return value

    @property
    def placeholders(self) -> tuple[str, ...]:
        return tuple(PLACEHOLDER.findall(self.path))

    def render_path(self, inputs: dict[str, Any]) -> str:
        def substitute(match: re.Match[str]) -> str:
            value = inputs[match.group(1)]
            return quote(str(value), safe="")

        return PLACEHOLDER.sub(substitute, self.path)

    def body(self, inputs: dict[str, Any]) -> dict[str, Any] | None:
        if self.method == "GET":
            return None
        used = set(self.placeholders)
        return {k: v for k, v in inputs.items() if k not in used}


def check_json_schema(schema: dict[str, Any], *, field: str) -> dict[str, Any]:
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise ValueError(f"{field} is not a valid JSON Schema: {exc.message}") from exc
    if schema.get("type") != "object":
        raise ValueError(f"{field} must describe an object")
    return schema


class ActionSpec(BaseModel):
    """The immutable, versioned part of an action definition."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action_id: str
    version: str
    system_id: str
    title: str = Field(min_length=5, max_length=160)
    description: str = Field(min_length=20, max_length=4000)
    gamp_category: GampCategory
    impact: GxpImpact
    detectability: Level = Field(
        description="Likelihood that an erroneous execution is detected before harm"
    )
    reversible: bool
    creates_gxp_record: bool
    requires_source_record: bool = Field(
        default=False, description="Requests must cite the original source record and digest"
    )
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    binding: HttpBinding

    @field_validator("action_id")
    @classmethod
    def _action_id(cls, value: str) -> str:
        if not ACTION_ID.fullmatch(value) or len(value) > 120:
            raise ValueError(
                "action_id must be dotted lowercase segments, e.g. lims.result.release"
            )
        return value

    @field_validator("version")
    @classmethod
    def _semver(cls, value: str) -> str:
        if not SEMVER.fullmatch(value):
            raise ValueError("version must be MAJOR.MINOR.PATCH")
        return value

    @field_validator("system_id")
    @classmethod
    def _system(cls, value: str) -> str:
        if not SLUG.fullmatch(value):
            raise ValueError("system_id must be a lowercase slug")
        return value

    @field_validator("input_schema")
    @classmethod
    def _input_schema(cls, value: dict[str, Any]) -> dict[str, Any]:
        return check_json_schema(value, field="input_schema")

    @field_validator("output_schema")
    @classmethod
    def _output_schema(cls, value: dict[str, Any]) -> dict[str, Any]:
        return check_json_schema(value, field="output_schema")

    @model_validator(mode="after")
    def _binding_matches_inputs(self) -> ActionSpec:
        properties = self.input_schema.get("properties", {})
        required = set(self.input_schema.get("required", []))
        for name in self.binding.placeholders:
            if name not in properties or name not in required:
                raise ValueError(f"path placeholder {{{name}}} must be a required input property")
        return self

    @property
    def key(self) -> str:
        return f"{self.action_id}@{self.version}"

    @property
    def version_tuple(self) -> tuple[int, int, int]:
        major, minor, patch = (int(p) for p in self.version.split("."))
        return major, minor, patch

    @property
    def digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


class ActionDefinition(BaseModel):
    """A registered action spec plus its validation lifecycle."""

    model_config = ConfigDict(frozen=True)

    spec: ActionSpec
    digest: str
    status: ValidationStatus = ValidationStatus.DRAFT
    author: str
    created_at: datetime
    validation_reference: str | None = None
    validated_at: datetime | None = None
    validation_signature_id: str | None = None
    retired_at: datetime | None = None
    retirement_signature_id: str | None = None

    @property
    def key(self) -> str:
        return self.spec.key

    def record_content(self) -> dict[str, Any]:
        """What a validation or retirement signature attests to."""
        return {
            "action": self.key,
            "spec_digest": self.digest,
            "validation_reference": self.validation_reference,
            "status": self.status.value,
        }


# ------------------------------------------------------------------- assessment


class SignatureRequirement(BaseModel):
    model_config = ConfigDict(frozen=True)

    meaning: SignatureMeaning
    role: Role


class RiskAssessment(BaseModel):
    """GAMP 5 functional risk assessment of one action request."""

    model_config = ConfigDict(frozen=True)

    severity: Level
    probability: Level
    risk_class: int = Field(ge=1, le=3, description="1 is the highest risk class")
    detectability: Level
    priority: Level
    rationale: tuple[str, ...]
    required_signatures: tuple[SignatureRequirement, ...]


class AlcoaPrinciple(StrEnum):
    ATTRIBUTABLE = "attributable"
    LEGIBLE = "legible"
    CONTEMPORANEOUS = "contemporaneous"
    ORIGINAL = "original"
    ACCURATE = "accurate"
    COMPLETE = "complete"
    CONSISTENT = "consistent"
    ENDURING = "enduring"
    AVAILABLE = "available"


class AlcoaCheck(BaseModel):
    model_config = ConfigDict(frozen=True)

    principle: AlcoaPrinciple
    passed: bool
    detail: str


class AlcoaAssessment(BaseModel):
    model_config = ConfigDict(frozen=True)

    checks: tuple[AlcoaCheck, ...]

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks)

    @property
    def failures(self) -> tuple[AlcoaCheck, ...]:
        return tuple(c for c in self.checks if not c.passed)


class PolicyOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: str
    matched_rules: tuple[str, ...]
    policy_version: str
    policy_digest: str
    reason: str
    fabric_decision: str | None = None


class SourceRecord(BaseModel):
    """Pointer to the original record an action is based on (ALCOA+ original)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    uri: str = Field(min_length=3, max_length=500)
    digest: str

    @field_validator("digest")
    @classmethod
    def _digest(cls, value: str) -> str:
        if not DIGEST.fullmatch(value):
            raise ValueError("digest must be sha256:<64 lowercase hex>")
        return value


# --------------------------------------------------------------------- requests


class ActionRequest(BaseModel):
    """An agent's request to execute a registered action, and its approval state."""

    model_config = ConfigDict(frozen=True)

    request_id: str
    action_key: str
    action_id: str
    version: str
    definition_digest: str
    system_id: str
    agent_id: str
    delegation_chain: tuple[str, ...] = ()
    inputs: dict[str, Any]
    inputs_digest: str
    justification: str
    context: dict[str, str] = Field(default_factory=dict)
    source_records: tuple[SourceRecord, ...] = ()
    performed_at: datetime = Field(description="Agent-declared time of the activity")
    received_at: datetime
    risk: RiskAssessment
    policy: PolicyOutcome
    alcoa: AlcoaAssessment
    status: RequestStatus
    status_reason: str | None = None
    signature_ids: tuple[str, ...] = ()
    expires_at: datetime | None = None
    updated_at: datetime
    revision: int = 0
    correlation_id: str | None = None

    def record_content(self) -> dict[str, Any]:
        """The content an approval signature is linked to (21 CFR 11.70)."""
        return {
            "request_id": self.request_id,
            "action": self.action_key,
            "definition_digest": self.definition_digest,
            "system_id": self.system_id,
            "agent_id": self.agent_id,
            "delegation_chain": list(self.delegation_chain),
            "inputs_digest": self.inputs_digest,
            "justification": self.justification,
            "context": self.context,
            "source_records": [s.model_dump(mode="json") for s in self.source_records],
            "performed_at": self.performed_at.isoformat(),
            "risk_priority": self.risk.priority.value,
            "required_signatures": [
                r.model_dump(mode="json") for r in self.risk.required_signatures
            ],
        }

    @property
    def record_digest(self) -> str:
        return digest_of(self.record_content())


class ElectronicSignature(BaseModel):
    """A Part 11 electronic signature, cryptographically linked to its record."""

    model_config = ConfigDict(frozen=True)

    signature_id: str
    record_type: RecordType
    record_id: str
    record_digest: str
    signer_subject: str
    signer_name: str
    meaning: SignatureMeaning
    reason: str
    signed_at: datetime
    auth_time: datetime
    auth_methods: tuple[str, ...]
    challenge_id: str
    key_id: str
    value: str = ""

    def manifest(self) -> dict[str, Any]:
        """Signed content: everything except the signature value."""
        return self.model_dump(mode="json", exclude={"value"})


class SigningChallenge(BaseModel):
    """Single-use nonce that binds a re-authentication to one record and meaning."""

    model_config = ConfigDict(frozen=True)

    challenge_id: str
    nonce: str
    record_type: RecordType
    record_id: str
    record_digest: str
    meaning: SignatureMeaning
    subject: str
    created_at: datetime
    expires_at: datetime
    used_at: datetime | None = None


class ExecutionRecord(BaseModel):
    """Immutable evidence of one execution against a validated system."""

    model_config = ConfigDict(frozen=True)

    record_id: str
    request_id: str
    action_key: str
    definition_digest: str
    system_id: str
    agent_id: str
    delegation_chain: tuple[str, ...]
    request_digest: str
    inputs_digest: str
    outputs: dict[str, Any] | None
    outputs_digest: str | None
    response_digest: str | None
    http_status: int | None
    status: Literal["completed", "failed"]
    error: str | None
    received_at: datetime
    started_at: datetime
    completed_at: datetime
    recorded_at: datetime
    risk: RiskAssessment
    policy: PolicyOutcome
    signatures: tuple[ElectronicSignature, ...]
    alcoa: AlcoaAssessment
    record_digest: str = ""
    key_id: str = ""
    signature: str = ""

    def content(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"record_digest", "key_id", "signature"})


class ReviewMetrics(BaseModel):
    model_config = ConfigDict(frozen=True)

    requests_by_status: dict[str, int]
    executions_completed: int
    executions_failed: int
    failure_rate: float
    signatures_by_meaning: dict[str, int]
    alcoa_failures: int
    definitions_validated: tuple[str, ...]
    definitions_retired: tuple[str, ...]
    audit_events_verified: int
    audit_chains_verified: int
    audit_integrity: bool


class PeriodicReview(BaseModel):
    """Periodic evaluation that a validated system remains in a validated state."""

    model_config = ConfigDict(frozen=True)

    review_id: str
    system_id: str
    period_start: datetime
    period_end: datetime
    generated_at: datetime
    generated_by: str
    metrics: ReviewMetrics
    findings: tuple[str, ...]
    conclusion: Literal["remains-validated", "remediation-required"]
    status: ReviewStatus = ReviewStatus.DRAFT
    approval_signature_id: str | None = None
    approved_at: datetime | None = None

    def record_content(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json", exclude={"status", "approval_signature_id", "approved_at"}
        )
