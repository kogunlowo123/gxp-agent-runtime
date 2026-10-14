"""Inputs and outputs of the runtime's use cases (also the published JSON Schemas)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from gxp_agent_runtime.domain.models import (
    SLUG,
    ActionRequest,
    ActionSpec,
    AlcoaAssessment,
    ElectronicSignature,
    GampCategory,
    PolicyOutcome,
    RecordType,
    RiskAssessment,
    SignatureMeaning,
    SignatureRequirement,
    SourceRecord,
)


class RegisterSystem(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    system_id: str = Field(min_length=2, max_length=64)
    name: str = Field(min_length=3, max_length=120)
    description: str = Field(min_length=10, max_length=2000)
    base_url: str = Field(min_length=10, max_length=300)
    gamp_category: GampCategory
    validation_reference: str = Field(min_length=3, max_length=120)
    owner: str = Field(min_length=2, max_length=200)
    review_interval_days: int = Field(ge=30, le=1095)
    last_reviewed_at: datetime = Field(
        description="Date of the validation summary report or last periodic review"
    )

    @field_validator("system_id")
    @classmethod
    def _slug(cls, value: str) -> str:
        if not SLUG.fullmatch(value):
            raise ValueError("system_id must be a lowercase slug")
        return value


class RegisterDefinition(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    spec: ActionSpec
    validation_reference: str = Field(
        min_length=3,
        max_length=120,
        description="Validation protocol or report that verifies this definition version",
    )


class SubmitAction(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    action_id: str = Field(min_length=3, max_length=120)
    version: str | None = Field(
        default=None, max_length=32, description="Omit to use the latest validated version"
    )
    inputs: dict[str, Any]
    justification: str = Field(min_length=1, max_length=2000)
    context: dict[str, str] = Field(default_factory=dict, max_length=20)
    source_records: tuple[SourceRecord, ...] = Field(default=(), max_length=20)
    performed_at: datetime = Field(description="When the agent performed the activity (UTC)")


class CreateChallenge(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    record_type: RecordType
    record_id: str = Field(min_length=1, max_length=160)
    meaning: SignatureMeaning


class ChallengeView(BaseModel):
    model_config = ConfigDict(frozen=True)

    challenge_id: str
    nonce: str = Field(description="Pass as the OIDC nonce when re-authenticating to sign")
    record_type: RecordType
    record_id: str
    record_digest: str
    meaning: SignatureMeaning
    signer: str
    expires_at: datetime
    statement: str = Field(description="What the signer attests to; shown before signing")


class ApplySignature(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    challenge_id: str = Field(min_length=1, max_length=64)
    reauthentication_token: str = Field(
        min_length=20, max_length=8192, description="ID token from re-authentication with nonce"
    )
    reason: str = Field(min_length=5, max_length=1000)


class SignatureOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    signature: ElectronicSignature
    record_status: str
    execution_record_id: str | None = None


class GenerateReview(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    system_id: str = Field(min_length=2, max_length=64)
    period_start: datetime
    period_end: datetime


class ActionCatalogEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    action_id: str
    version: str
    system_id: str
    title: str
    description: str
    digest: str
    reversible: bool
    creates_gxp_record: bool
    requires_source_record: bool
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]

    @classmethod
    def of(cls, spec: ActionSpec, digest: str) -> ActionCatalogEntry:
        return cls(
            action_id=spec.action_id,
            version=spec.version,
            system_id=spec.system_id,
            title=spec.title,
            description=spec.description,
            digest=digest,
            reversible=spec.reversible,
            creates_gxp_record=spec.creates_gxp_record,
            requires_source_record=spec.requires_source_record,
            input_schema=spec.input_schema,
            output_schema=spec.output_schema,
        )


class ActionPreview(BaseModel):
    """Risk classification and policy outcome without submitting the action."""

    model_config = ConfigDict(frozen=True)

    action_key: str
    risk: RiskAssessment
    policy: PolicyOutcome
    alcoa: AlcoaAssessment
    required_signatures: tuple[SignatureRequirement, ...]
    would_execute_immediately: bool


class RequestView(BaseModel):
    model_config = ConfigDict(frozen=True)

    request_id: str
    action_key: str
    system_id: str
    agent_id: str
    delegation_chain: tuple[str, ...]
    status: str
    status_reason: str | None
    inputs_digest: str
    record_digest: str
    risk: RiskAssessment
    policy: PolicyOutcome
    alcoa: AlcoaAssessment
    outstanding_signatures: tuple[SignatureRequirement, ...]
    signature_ids: tuple[str, ...]
    received_at: datetime
    expires_at: datetime | None
    execution_record_id: str | None

    @classmethod
    def of(
        cls, request: ActionRequest, *, signed: frozenset[SignatureMeaning] = frozenset()
    ) -> RequestView:
        outstanding = tuple(r for r in request.risk.required_signatures if r.meaning not in signed)
        return cls(
            request_id=request.request_id,
            action_key=request.action_key,
            system_id=request.system_id,
            agent_id=request.agent_id,
            delegation_chain=request.delegation_chain,
            status=request.status.value,
            status_reason=request.status_reason,
            inputs_digest=request.inputs_digest,
            record_digest=request.record_digest,
            risk=request.risk,
            policy=request.policy,
            alcoa=request.alcoa,
            outstanding_signatures=(
                outstanding if request.status.value == "pending_approval" else ()
            ),
            signature_ids=request.signature_ids,
            received_at=request.received_at,
            expires_at=request.expires_at,
            execution_record_id=(
                request.request_id if request.status.value in {"completed", "failed"} else None
            ),
        )


class SignatureCheck(BaseModel):
    model_config = ConfigDict(frozen=True)

    signature_id: str
    meaning: SignatureMeaning
    signer: str
    signed_at: datetime
    cryptographically_valid: bool
    linked_to_record: bool


class RecordVerification(BaseModel):
    model_config = ConfigDict(frozen=True)

    record_id: str
    record_digest_valid: bool
    record_signature_valid: bool
    signatures: tuple[SignatureCheck, ...]
    alcoa: AlcoaAssessment
    audit_events: int
    verified: bool


class ChainReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    chain_id: str
    events: int
    intact: bool
    error: str | None = None


class AuditVerification(BaseModel):
    model_config = ConfigDict(frozen=True)

    chains: tuple[ChainReport, ...]
    events_verified: int
    intact: bool
