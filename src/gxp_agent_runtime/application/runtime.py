"""GxP agent runtime use cases.

Action Request -> Risk Classification -> Approval Workflow -> Execution Record.

Agents can only reach validated systems through registered, validated and
versioned action definitions. Every request is checked for ALCOA+ data
integrity, classified with the GAMP 5 risk method, and decided by the
identity fabric and the runtime's GxP policy. Anything the policy or the risk
assessment marks as needing a human waits for Part 11 electronic signatures;
nothing high-risk executes autonomously. Every decision and state change is
written to the signed audit chain, and every execution produces a signed,
read-back-verified execution record.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any

from agentic_core.audit import AuditLog, verify_chain
from agentic_core.domain.classification import DataClassification, Decision, RiskLevel
from agentic_core.domain.errors import AuditIntegrityError
from agentic_core.domain.identifiers import new_id
from agentic_core.observability import correlation_id
from agentic_core.policy import PolicyEngine, PolicyRequest, Resource, Subject
from agentic_core.security import SecretScanner

from gxp_agent_runtime.application.commands import (
    ActionCatalogEntry,
    ActionPreview,
    AuditVerification,
    ChainReport,
    ChallengeView,
    CreateChallenge,
    GenerateReview,
    RecordVerification,
    RegisterDefinition,
    RegisterSystem,
    RequestView,
    SignatureCheck,
    SignatureOutcome,
    SubmitAction,
)
from gxp_agent_runtime.application.signatures import SignatureService
from gxp_agent_runtime.domain.alcoa import AlcoaChecker, schema_errors
from gxp_agent_runtime.domain.errors import (
    ConflictError,
    ForbiddenError,
    InvalidStateError,
    NotFoundError,
    SignatureError,
    ValidationFailedError,
)
from gxp_agent_runtime.domain.models import (
    ActionDefinition,
    ActionRequest,
    AlcoaAssessment,
    ElectronicSignature,
    ExecutionRecord,
    PeriodicReview,
    PolicyOutcome,
    RecordType,
    RequestStatus,
    ReviewMetrics,
    ReviewStatus,
    RiskAssessment,
    Role,
    SignatureMeaning,
    SignatureRequirement,
    SystemStatus,
    ValidatedSystem,
    ValidationStatus,
    digest_of,
)
from gxp_agent_runtime.domain.ports import (
    AuditReader,
    Clock,
    DefinitionRepository,
    RecordRepository,
    RequestRepository,
    ReviewRepository,
    SignatureRepository,
    SystemRepository,
)
from gxp_agent_runtime.domain.risk import APPROVAL, FailureHistory, RiskClassifier
from gxp_agent_runtime.infrastructure.connectors import ActionConnector
from gxp_agent_runtime.observability.metrics import RuntimeMetrics
from gxp_agent_runtime.security.agents import AgentGateway, AgentPrincipal
from gxp_agent_runtime.security.humans import HumanPrincipal, require_role
from gxp_agent_runtime.security.keys import RecordSigner, SignatureVerifier

SIGNING_ROLES: dict[SignatureMeaning, tuple[Role, ...]] = {
    SignatureMeaning.APPROVAL: (Role.APPROVER,),
    SignatureMeaning.QUALITY_APPROVAL: (Role.QUALITY,),
    SignatureMeaning.REJECTION: (Role.APPROVER, Role.QUALITY),
    SignatureMeaning.VALIDATION_APPROVAL: (Role.QUALITY,),
    SignatureMeaning.RETIREMENT: (Role.QUALITY,),
    SignatureMeaning.REVIEW: (Role.QUALITY,),
}

RECORD_MEANINGS: dict[RecordType, frozenset[SignatureMeaning]] = {
    RecordType.ACTION_REQUEST: frozenset(
        {SignatureMeaning.APPROVAL, SignatureMeaning.QUALITY_APPROVAL, SignatureMeaning.REJECTION}
    ),
    RecordType.ACTION_DEFINITION: frozenset(
        {SignatureMeaning.VALIDATION_APPROVAL, SignatureMeaning.RETIREMENT}
    ),
    RecordType.PERIODIC_REVIEW: frozenset({SignatureMeaning.REVIEW}),
}

STATEMENTS: dict[SignatureMeaning, str] = {
    SignatureMeaning.APPROVAL: "I approve execution of this agent action as the process owner.",
    SignatureMeaning.QUALITY_APPROVAL: (
        "I approve execution of this agent action on behalf of Quality Assurance."
    ),
    SignatureMeaning.REJECTION: "I reject this agent action; it must not be executed.",
    SignatureMeaning.VALIDATION_APPROVAL: (
        "I confirm this action definition version is verified against its validation evidence."
    ),
    SignatureMeaning.RETIREMENT: "I retire this action definition version from use.",
    SignatureMeaning.REVIEW: (
        "I have reviewed this periodic review and accept its conclusion for the system."
    ),
}

READ_ACTION = "gxp:read"
CAS_ATTEMPTS = 3
FAILURE_FINDING_RATE = 0.05


def execute_action(action_id: str) -> str:
    return f"gxp:execute:{action_id}"


class GxpRuntime:
    def __init__(
        self,
        *,
        systems: SystemRepository,
        definitions: DefinitionRepository,
        requests: RequestRepository,
        signature_store: SignatureRepository,
        records: RecordRepository,
        reviews: ReviewRepository,
        audit_reader: AuditReader,
        signatures: SignatureService,
        agents: AgentGateway,
        connector: ActionConnector,
        policy: PolicyEngine,
        audit: AuditLog,
        signer: RecordSigner,
        verifier: SignatureVerifier,
        audit_keys: SignatureVerifier,
        clock: Clock,
        metrics: RuntimeMetrics,
        classifier: RiskClassifier | None = None,
        alcoa: AlcoaChecker | None = None,
        approval_ttl: timedelta = timedelta(hours=72),
        environment: str = "production",
    ) -> None:
        self._systems = systems
        self._definitions = definitions
        self._requests = requests
        self._signature_store = signature_store
        self._records = records
        self._reviews = reviews
        self._audit_reader = audit_reader
        self._signatures = signatures
        self.agents = agents
        self._connector = connector
        self._policy = policy
        self._audit = audit
        self._signer = signer
        self._verifier = verifier
        self._audit_keys = audit_keys
        self._clock = clock
        self._metrics = metrics
        self._classifier = classifier or RiskClassifier()
        self._alcoa = alcoa or AlcoaChecker()
        self._approval_ttl = approval_ttl
        self._environment = environment
        self._secrets = SecretScanner()

    @property
    def policy(self) -> PolicyEngine:
        return self._policy

    # ------------------------------------------------------------------ audit

    async def record_event(
        self, actor: str, action: str, resource: str, outcome: str, details: dict[str, Any]
    ) -> int:
        """Audit an event raised by an adapter (MCP tool call, A2A message)."""
        return await self._record(actor, action, resource, outcome, details)

    async def _record(
        self,
        actor: str,
        action: str,
        resource: str,
        outcome: str,
        details: dict[str, Any] | None = None,
    ) -> int:
        event = await self._audit.record(
            actor=actor,
            action=action,
            resource=resource,
            outcome=outcome,
            correlation_id=correlation_id(),
            details=details or {},
        )
        return event.sequence

    # ---------------------------------------------------------------- systems

    async def register_system(
        self, command: RegisterSystem, *, who: HumanPrincipal
    ) -> ValidatedSystem:
        require_role(who, Role.SYSTEM_OWNER)
        now = self._clock.now()
        if command.last_reviewed_at > now:
            raise ValidationFailedError("last_reviewed_at cannot be in the future")
        system = ValidatedSystem(
            **command.model_dump(),
            status=SystemStatus.VALIDATED,
            registered_at=now,
            updated_at=now,
        )
        await self._systems.add(system)
        await self._record(
            who.subject,
            "system.register",
            f"system:{system.system_id}",
            "success",
            {
                "validation_reference": system.validation_reference,
                "gamp": int(system.gamp_category),
            },
        )
        return system

    async def get_system(self, system_id: str) -> ValidatedSystem:
        system = await self._systems.get(system_id)
        if system is None:
            raise NotFoundError(f"system {system_id} not found")
        return system

    async def list_systems(self) -> Sequence[ValidatedSystem]:
        systems = await self._systems.list()
        now = self._clock.now()
        self._metrics.reviews_overdue.set(
            sum(1 for s in systems if s.status is SystemStatus.VALIDATED and s.review_overdue(now))
        )
        return systems

    # ------------------------------------------------------------ definitions

    async def register_definition(
        self, command: RegisterDefinition, *, who: HumanPrincipal
    ) -> ActionDefinition:
        require_role(who, Role.SYSTEM_OWNER)
        spec = command.spec
        system = await self.get_system(spec.system_id)
        if system.status is SystemStatus.RETIRED:
            raise InvalidStateError(f"system {system.system_id} is retired")
        existing = await self._definitions.versions(spec.action_id)
        if existing:
            if any(d.spec.system_id != spec.system_id for d in existing):
                raise ConflictError(f"{spec.action_id} belongs to another system")
            latest = existing[-1].spec.version_tuple
            if spec.version_tuple <= latest:
                raise ConflictError(
                    f"version {spec.version} must be greater than {'.'.join(map(str, latest))}"
                )
        definition = ActionDefinition(
            spec=spec,
            digest=spec.digest,
            author=who.subject,
            created_at=self._clock.now(),
            validation_reference=command.validation_reference,
        )
        await self._definitions.add(definition)
        await self._record(
            who.subject,
            "definition.register",
            f"definition:{definition.key}",
            "draft",
            {"digest": definition.digest, "validation_reference": command.validation_reference},
        )
        return definition

    async def get_definition(self, action_id: str, version: str) -> ActionDefinition:
        definition = await self._definitions.get(action_id, version)
        if definition is None:
            raise NotFoundError(f"action definition {action_id}@{version} not found")
        return definition

    async def list_definitions(
        self, *, status: ValidationStatus | None = None
    ) -> Sequence[ActionDefinition]:
        return await self._definitions.list(status=status)

    async def catalog(self, principal: AgentPrincipal) -> list[ActionCatalogEntry]:
        await self.authorize_read(principal)
        validated = await self._definitions.list(status=ValidationStatus.VALIDATED)
        return [
            ActionCatalogEntry.of(d.spec, d.digest)
            for d in validated
            if principal.allows(execute_action(d.spec.action_id))
        ]

    async def _resolve(self, action_id: str, version: str | None) -> ActionDefinition:
        if version is not None:
            return await self.get_definition(action_id, version)
        validated = [
            d
            for d in await self._definitions.versions(action_id)
            if d.status is ValidationStatus.VALIDATED
        ]
        if not validated:
            raise NotFoundError(f"no validated version of {action_id}")
        return validated[-1]

    # --------------------------------------------------------- authorization

    async def authorize_read(self, principal: AgentPrincipal) -> None:
        await self.agents.authorize(
            principal, action=READ_ACTION, resource_id="catalog", attributes={}
        )
        decision = self._policy.evaluate(
            PolicyRequest(
                subject=self._subject(principal, READ_ACTION),
                action=READ_ACTION,
                resource=Resource(type="gxp-catalog", classification=DataClassification.INTERNAL),
            )
        )
        if decision.decision is not Decision.ALLOW:
            raise ForbiddenError(f"{READ_ACTION} denied: {decision.reason}")

    @staticmethod
    def _subject(principal: AgentPrincipal, action: str) -> Subject:
        return Subject(
            id=principal.agent_id,
            kind="agent",
            attributes={
                "scopes": sorted(principal.scopes),
                "action_in_scope": principal.allows(action),
                "delegated": bool(principal.delegation_chain),
                "delegation_depth": len(principal.delegation_chain),
            },
        )

    # --------------------------------------------------------------- requests

    async def _evaluate(
        self, principal: AgentPrincipal, command: SubmitAction
    ) -> tuple[ActionDefinition, ValidatedSystem, RiskAssessment, AlcoaAssessment, PolicyOutcome]:
        definition = await self._resolve(command.action_id, command.version)
        spec = definition.spec
        system = await self.get_system(spec.system_id)
        action = execute_action(spec.action_id)
        attributes = {
            "system_id": system.system_id,
            "version": spec.version,
            "creates_gxp_record": spec.creates_gxp_record,
        }
        try:
            fabric_decision = await self.agents.authorize(
                principal, action=action, resource_id=definition.key, attributes=attributes
            )
        except ForbiddenError as exc:
            await self._record(
                principal.agent_id,
                "action.request",
                f"definition:{definition.key}",
                "denied",
                {"stage": "identity-fabric", "reason": exc.message},
            )
            self._metrics.action_requests.labels(spec.action_id, "denied", "n/a").inc()
            raise

        self._reject_secrets(command)
        now = self._clock.now()
        outcomes = await self._records.recent_outcomes(spec.action_id, 50)
        history = FailureHistory(
            executions=len(outcomes), failures=sum(1 for o in outcomes if o == "failed")
        )
        risk = self._classifier.assess(spec, history=history)
        alcoa = self._alcoa.assess_request(
            spec=spec,
            agent_id=principal.agent_id,
            inputs=command.inputs,
            justification=command.justification,
            context=command.context,
            source_records=command.source_records,
            performed_at=command.performed_at,
            received_at=now,
        )
        decision = self._policy.evaluate(
            PolicyRequest(
                subject=self._subject(principal, action),
                action=action,
                resource=Resource(
                    type="gxp-action",
                    id=definition.key,
                    classification=DataClassification.RESTRICTED,
                    attributes={
                        "definition_status": definition.status.value,
                        "system_status": system.status.value,
                        "system_review_overdue": system.review_overdue(now),
                        "gamp_category": int(spec.gamp_category),
                        "creates_gxp_record": spec.creates_gxp_record,
                        "reversible": spec.reversible,
                        "risk_class": risk.risk_class,
                        "risk_priority_rank": risk.priority.rank,
                        "alcoa_passed": alcoa.passed,
                        "fabric_decision": fabric_decision or "none",
                    },
                ),
                risk=RiskLevel(risk.priority.rank),
                environment={"name": self._environment},
            )
        )
        reason = decision.reason
        if decision.decision is Decision.DENY and alcoa.failures:
            reason += "; ALCOA+: " + "; ".join(
                f"{c.principle.value}: {c.detail}" for c in alcoa.failures
            )
        policy = PolicyOutcome(
            decision=decision.decision.value,
            matched_rules=decision.matched_rules,
            policy_version=decision.policy_version,
            policy_digest=decision.policy_digest,
            reason=reason,
            fabric_decision=fabric_decision,
        )
        return definition, system, risk, alcoa, policy

    def _reject_secrets(self, command: SubmitAction) -> None:
        texts = [command.justification, *command.context.values(), flatten_text(command.inputs)]
        if any(self._secrets.detect(text) for text in texts):
            raise ValidationFailedError("credential material must not be written into GxP records")

    @staticmethod
    def _effective_signatures(
        risk: RiskAssessment, policy: PolicyOutcome
    ) -> tuple[SignatureRequirement, ...]:
        required = risk.required_signatures
        needs_human = Decision.REQUIRE_APPROVAL.value in {policy.decision, policy.fabric_decision}
        if needs_human and not required:
            return (APPROVAL,)
        return required

    async def preview(self, principal: AgentPrincipal, command: SubmitAction) -> ActionPreview:
        definition, _, risk, alcoa, policy = await self._evaluate(principal, command)
        required = self._effective_signatures(risk, policy)
        await self._record(
            principal.agent_id,
            "action.assess",
            f"definition:{definition.key}",
            policy.decision,
            {"priority": risk.priority.value, "rules": list(policy.matched_rules)},
        )
        return ActionPreview(
            action_key=definition.key,
            risk=risk.model_copy(update={"required_signatures": required}),
            policy=policy,
            alcoa=alcoa,
            required_signatures=required,
            would_execute_immediately=policy.decision == Decision.ALLOW.value and not required,
        )

    async def submit(self, principal: AgentPrincipal, command: SubmitAction) -> RequestView:
        definition, system, risk, alcoa, policy = await self._evaluate(principal, command)
        spec = definition.spec
        now = self._clock.now()
        required = self._effective_signatures(risk, policy)
        risk = risk.model_copy(update={"required_signatures": required})
        if policy.decision == Decision.DENY.value:
            status, status_reason, expires = RequestStatus.DENIED, policy.reason, None
        elif required:
            status = RequestStatus.PENDING_APPROVAL
            status_reason = "awaiting " + ", ".join(r.meaning.value for r in required)
            expires = now + self._approval_ttl
        else:
            status, status_reason, expires = RequestStatus.EXECUTING, None, None

        request = ActionRequest(
            request_id=new_id(),
            action_key=definition.key,
            action_id=spec.action_id,
            version=spec.version,
            definition_digest=definition.digest,
            system_id=system.system_id,
            agent_id=principal.agent_id,
            delegation_chain=principal.delegation_chain,
            inputs=command.inputs,
            inputs_digest=digest_of(command.inputs),
            justification=command.justification,
            context=command.context,
            source_records=command.source_records,
            performed_at=command.performed_at,
            received_at=now,
            risk=risk,
            policy=policy,
            alcoa=alcoa,
            status=status,
            status_reason=status_reason,
            expires_at=expires,
            updated_at=now,
            correlation_id=correlation_id(),
        )
        await self._record(
            principal.agent_id,
            "action.request",
            f"request:{request.request_id}",
            status.value,
            {
                "action": definition.key,
                "definition_digest": definition.digest,
                "inputs_digest": request.inputs_digest,
                "record_digest": request.record_digest,
                "priority": risk.priority.value,
                "risk_class": risk.risk_class,
                "rules": list(policy.matched_rules),
                "policy_digest": policy.policy_digest,
                "fabric": policy.fabric_decision,
                "alcoa_failures": [c.principle.value for c in alcoa.failures],
                "delegation_chain": list(principal.delegation_chain),
            },
        )
        await self._requests.add(request)
        for failure in alcoa.failures:
            self._metrics.alcoa_failures.labels(failure.principle.value, "request").inc()
        self._metrics.action_requests.labels(
            spec.action_id, status.value, risk.priority.value
        ).inc()
        if status is RequestStatus.EXECUTING:
            request = await self._execute(request)
        return RequestView.of(request)

    async def get_request(self, request_id: str) -> ActionRequest:
        request = await self._requests.get(request_id)
        if request is None:
            raise NotFoundError(f"request {request_id} not found")
        return request

    async def request_view(self, request: ActionRequest) -> RequestView:
        signed = frozenset(
            s.meaning
            for s in await self._signature_store.for_record(
                RecordType.ACTION_REQUEST, request.request_id
            )
            if s.signature_id in request.signature_ids
        )
        return RequestView.of(request, signed=signed)

    async def agent_request(self, principal: AgentPrincipal, request_id: str) -> RequestView:
        request = await self.get_request(request_id)
        if request.agent_id != principal.agent_id:
            raise NotFoundError(f"request {request_id} not found")
        return await self.request_view(request)

    async def list_requests(
        self,
        *,
        status: RequestStatus | None = None,
        system_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[RequestView]:
        found = await self._requests.list(
            status=status, system_id=system_id, limit=limit, offset=offset
        )
        return [await self.request_view(r) for r in found]

    async def expire_pending(self) -> int:
        expired = 0
        for request in await self._requests.expired_pending(self._clock.now()):
            try:
                await self._transition(
                    request, RequestStatus.EXPIRED, "approval window elapsed without signatures"
                )
            except ConflictError:
                continue
            expired += 1
            self._metrics.pending_expired.inc()
            await self._record(
                "gxp-runtime", "action.expire", f"request:{request.request_id}", "expired"
            )
        return expired

    async def _transition(
        self,
        request: ActionRequest,
        status: RequestStatus,
        reason: str | None,
        *,
        signature_ids: tuple[str, ...] | None = None,
    ) -> ActionRequest:
        updated = request.model_copy(
            update={
                "status": status,
                "status_reason": reason,
                "signature_ids": request.signature_ids if signature_ids is None else signature_ids,
                "updated_at": self._clock.now(),
                "revision": request.revision + 1,
            }
        )
        await self._requests.replace(updated, expected_revision=request.revision)
        return updated

    # -------------------------------------------------------------- execution

    async def _execute(self, request: ActionRequest) -> ActionRequest:
        definition = await self.get_definition(request.action_id, request.version)
        system = await self.get_system(request.system_id)
        now = self._clock.now()
        blocked = None
        if definition.status is not ValidationStatus.VALIDATED:
            blocked = f"definition {definition.key} is {definition.status.value}"
        elif system.status is not SystemStatus.VALIDATED:
            blocked = f"system {system.system_id} is {system.status.value}"
        elif system.review_overdue(now):
            blocked = f"periodic review of {system.system_id} is overdue"
        if blocked:
            await self._record(
                "gxp-runtime",
                "action.execute",
                f"request:{request.request_id}",
                "blocked",
                {"reason": blocked},
            )
            return await self._transition(request, RequestStatus.DENIED, blocked)

        order = {sid: index for index, sid in enumerate(request.signature_ids)}
        signatures = sorted(
            (
                s
                for s in await self._signature_store.for_record(
                    RecordType.ACTION_REQUEST, request.request_id
                )
                if s.signature_id in order
            ),
            key=lambda s: order[s.signature_id],
        )
        result = await self._connector.execute(system, definition.spec, request)
        self._metrics.execution_duration.labels(system.system_id).observe(
            (result.completed_at - result.started_at).total_seconds()
        )
        error = result.error
        status: str = "completed" if result.succeeded else "failed"
        if result.succeeded:
            nonconforming = schema_errors(definition.spec.output_schema, result.outputs or {})
            if nonconforming:
                status = "failed"
                error = "output does not conform to the validated output schema: " + "; ".join(
                    nonconforming
                )
        draft = ExecutionRecord(
            record_id=request.request_id,
            request_id=request.request_id,
            action_key=request.action_key,
            definition_digest=request.definition_digest,
            system_id=request.system_id,
            agent_id=request.agent_id,
            delegation_chain=request.delegation_chain,
            request_digest=request.record_digest,
            inputs_digest=request.inputs_digest,
            outputs=result.outputs,
            outputs_digest=digest_of(result.outputs) if result.outputs is not None else None,
            response_digest=result.response_digest,
            http_status=result.http_status,
            status="completed" if status == "completed" else "failed",
            error=error,
            received_at=request.received_at,
            started_at=result.started_at,
            completed_at=result.completed_at,
            recorded_at=self._clock.now(),
            risk=request.risk,
            policy=request.policy,
            signatures=tuple(signatures),
            alcoa=AlcoaAssessment(checks=()),
        )
        alcoa = self._alcoa.assess_record(
            record=draft,
            output_schema=definition.spec.output_schema,
            required=request.risk.required_signatures,
            signatures=signatures,
        )
        draft = draft.model_copy(update={"alcoa": alcoa})
        record_digest = digest_of(draft.content())
        record = draft.model_copy(
            update={
                "record_digest": record_digest,
                "key_id": self._signer.key_id,
                "signature": self._signer.sign_document({"record_digest": record_digest}),
            }
        )
        await self._record(
            "gxp-runtime",
            "action.execute",
            f"execution-record:{record.record_id}",
            record.status,
            {
                "action": record.action_key,
                "record_digest": record_digest,
                "outputs_digest": record.outputs_digest,
                "response_digest": record.response_digest,
                "http_status": record.http_status,
                "attempts": result.attempts,
                "signatures": [s.signature_id for s in signatures],
                "on_behalf_of": request.agent_id,
            },
        )
        await self._records.add(record)
        readback = await self._records.get(record.record_id)
        storage = self._alcoa.assess_storage(
            record=record,
            audit_events=await self._audit_reader.count_resource(
                f"execution-record:{record.record_id}"
            ),
            readback=readback,
        )
        for failure in (*alcoa.failures, *storage.failures):
            self._metrics.alcoa_failures.labels(failure.principle.value, "record").inc()
        if storage.failures:
            raise InvalidStateError(
                f"execution record {record.record_id} failed storage verification"
            )
        self._metrics.executions.labels(system.system_id, record.status).inc()
        final = RequestStatus.COMPLETED if record.status == "completed" else RequestStatus.FAILED
        return await self._transition(request, final, record.error)

    async def get_record(self, record_id: str) -> ExecutionRecord:
        record = await self._records.get(record_id)
        if record is None:
            raise NotFoundError(f"execution record {record_id} not found")
        return record

    async def agent_record(self, principal: AgentPrincipal, record_id: str) -> ExecutionRecord:
        record = await self.get_record(record_id)
        if record.agent_id != principal.agent_id:
            raise NotFoundError(f"execution record {record_id} not found")
        return record

    async def verify_record(self, record_id: str) -> RecordVerification:
        record = await self.get_record(record_id)
        digest_valid = digest_of(record.content()) == record.record_digest
        signature_valid = self._verifier.verify_document(
            record.key_id, {"record_digest": record.record_digest}, record.signature
        )
        checks = tuple(
            SignatureCheck(
                signature_id=s.signature_id,
                meaning=s.meaning,
                signer=s.signer_subject,
                signed_at=s.signed_at,
                cryptographically_valid=self._signatures.verify(s),
                linked_to_record=s.record_digest == record.request_digest,
            )
            for s in record.signatures
        )
        audit_events = await self._audit_reader.count_resource(f"execution-record:{record_id}")
        storage = self._alcoa.assess_storage(
            record=record, audit_events=audit_events, readback=await self._records.get(record_id)
        )
        definition = await self._definitions.get(*record.action_key.split("@", 1))
        content = self._alcoa.assess_record(
            record=record,
            output_schema=definition.spec.output_schema if definition else {"type": "object"},
            required=record.risk.required_signatures,
            signatures=record.signatures,
        )
        alcoa = AlcoaAssessment(checks=(*content.checks, *storage.checks))
        return RecordVerification(
            record_id=record_id,
            record_digest_valid=digest_valid,
            record_signature_valid=signature_valid,
            signatures=checks,
            alcoa=alcoa,
            audit_events=audit_events,
            verified=digest_valid
            and signature_valid
            and all(c.cryptographically_valid and c.linked_to_record for c in checks)
            and alcoa.passed,
        )

    # ------------------------------------------------------------- signatures

    async def _record_for_signature(
        self, record_type: RecordType, record_id: str
    ) -> tuple[ActionRequest | ActionDefinition | PeriodicReview, str]:
        if record_type is RecordType.ACTION_REQUEST:
            request = await self.get_request(record_id)
            return request, request.record_digest
        if record_type is RecordType.ACTION_DEFINITION:
            action_id, _, version = record_id.partition("@")
            definition = await self.get_definition(action_id, version)
            return definition, digest_of(definition.record_content())
        review = await self.get_review(record_id)
        return review, digest_of(review.record_content())

    async def _check_eligibility(
        self,
        who: HumanPrincipal,
        meaning: SignatureMeaning,
        target: ActionRequest | ActionDefinition | PeriodicReview,
    ) -> None:
        require_role(who, *SIGNING_ROLES[meaning])
        if isinstance(target, ActionRequest):
            if target.status is not RequestStatus.PENDING_APPROVAL:
                raise InvalidStateError(f"request is {target.status.value}, not pending approval")
            if target.expires_at is not None and self._clock.now() > target.expires_at:
                raise InvalidStateError("request approval window has elapsed")
            existing = [
                s
                for s in await self._signature_store.for_record(
                    RecordType.ACTION_REQUEST, target.request_id
                )
                if s.signature_id in target.signature_ids
            ]
            if any(s.signer_subject == who.subject for s in existing):
                raise SignatureError(
                    "a second signature on this request must come from another person"
                )
            if meaning is not SignatureMeaning.REJECTION:
                outstanding = {r.meaning for r in target.risk.required_signatures} - {
                    s.meaning for s in existing
                }
                if meaning not in outstanding:
                    raise InvalidStateError(f"no outstanding {meaning.value} signature on request")
        elif isinstance(target, ActionDefinition):
            if target.author == who.subject:
                raise SignatureError("the author of a definition cannot approve or retire it")
            expected = (
                ValidationStatus.DRAFT
                if meaning is SignatureMeaning.VALIDATION_APPROVAL
                else ValidationStatus.VALIDATED
            )
            if target.status is not expected:
                raise InvalidStateError(f"definition is {target.status.value}")
        else:
            if target.generated_by == who.subject:
                raise SignatureError("the person who generated a review cannot approve it")
            if target.status is not ReviewStatus.DRAFT:
                raise InvalidStateError("periodic review is already approved")

    async def create_challenge(
        self, command: CreateChallenge, *, who: HumanPrincipal
    ) -> ChallengeView:
        if command.meaning not in RECORD_MEANINGS[command.record_type]:
            raise ValidationFailedError(
                f"{command.meaning.value} does not apply to {command.record_type.value} records"
            )
        target, digest = await self._record_for_signature(command.record_type, command.record_id)
        await self._check_eligibility(who, command.meaning, target)
        challenge = await self._signatures.challenge(
            who,
            record_type=command.record_type,
            record_id=command.record_id,
            record_digest=digest,
            meaning=command.meaning,
        )
        await self._record(
            who.subject,
            "signature.challenge",
            f"{command.record_type.value}:{command.record_id}",
            "issued",
            {"meaning": command.meaning.value, "record_digest": digest},
        )
        return ChallengeView(
            challenge_id=challenge.challenge_id,
            nonce=challenge.nonce,
            record_type=challenge.record_type,
            record_id=challenge.record_id,
            record_digest=challenge.record_digest,
            meaning=challenge.meaning,
            signer=who.name,
            expires_at=challenge.expires_at,
            statement=STATEMENTS[challenge.meaning],
        )

    async def sign(
        self,
        *,
        who: HumanPrincipal,
        challenge_id: str,
        reauthentication_token: str,
        reason: str,
    ) -> SignatureOutcome:
        try:
            challenge = await self._signatures.pending_challenge(who, challenge_id)
            target, digest = await self._record_for_signature(
                challenge.record_type, challenge.record_id
            )
            await self._check_eligibility(who, challenge.meaning, target)
            signature = await self._signatures.sign(
                who,
                challenge,
                reauthentication_token=reauthentication_token,
                reason=reason,
                current_digest=digest,
            )
        except (SignatureError, InvalidStateError) as exc:
            self._metrics.signature_failures.labels(exc.code).inc()
            await self._record(
                who.subject,
                "signature.apply",
                f"challenge:{challenge_id}",
                "rejected",
                {"reason": exc.message},
            )
            raise
        self._metrics.signatures.labels(signature.meaning.value).inc()
        await self._record(
            who.subject,
            "signature.apply",
            f"{signature.record_type.value}:{signature.record_id}",
            signature.meaning.value,
            {
                "signature_id": signature.signature_id,
                "record_digest": signature.record_digest,
                "signer_name": signature.signer_name,
                "auth_time": signature.auth_time.isoformat(),
                "auth_methods": list(signature.auth_methods),
                "reason": signature.reason,
                "key_id": signature.key_id,
            },
        )
        if isinstance(target, ActionRequest):
            return await self._apply_to_request(target, signature)
        if isinstance(target, ActionDefinition):
            return await self._apply_to_definition(target, signature)
        return await self._apply_to_review(target, signature)

    async def _apply_to_request(
        self, request: ActionRequest, signature: ElectronicSignature
    ) -> SignatureOutcome:
        """Apply a stored signature; on a lost compare-and-swap reload and re-apply, so
        concurrent signers both count and the action still executes exactly once."""
        for _ in range(CAS_ATTEMPTS):
            try:
                return await self._apply_once(request, signature)
            except ConflictError:
                request = await self.get_request(request.request_id)
                if request.status is not RequestStatus.PENDING_APPROVAL:
                    raise InvalidStateError(
                        f"request became {request.status.value} while signing"
                    ) from None
        raise ConflictError("request is being modified concurrently; signature not applied")

    async def _apply_once(
        self, request: ActionRequest, signature: ElectronicSignature
    ) -> SignatureOutcome:
        ids = (*request.signature_ids, signature.signature_id)
        if signature.meaning is SignatureMeaning.REJECTION:
            updated = await self._transition(
                request,
                RequestStatus.REJECTED,
                f"rejected by {signature.signer_name}: " f"{signature.reason}",
                signature_ids=ids,
            )
            await self._record(
                signature.signer_subject,
                "action.reject",
                f"request:{request.request_id}",
                "rejected",
            )
            return SignatureOutcome(signature=signature, record_status=updated.status.value)
        signed = {
            s.meaning
            for s in await self._signature_store.for_record(
                RecordType.ACTION_REQUEST, request.request_id
            )
            if s.signature_id in ids
        }
        outstanding = [r for r in request.risk.required_signatures if r.meaning not in signed]
        if outstanding:
            updated = await self._transition(
                request,
                RequestStatus.PENDING_APPROVAL,
                "awaiting " + ", ".join(r.meaning.value for r in outstanding),
                signature_ids=ids,
            )
            return SignatureOutcome(signature=signature, record_status=updated.status.value)
        executing = await self._transition(
            request, RequestStatus.EXECUTING, None, signature_ids=ids
        )
        await self._record(
            "gxp-runtime",
            "action.approve",
            f"request:{request.request_id}",
            "approved",
            {"signatures": list(ids)},
        )
        final = await self._execute(executing)
        return SignatureOutcome(
            signature=signature,
            record_status=final.status.value,
            execution_record_id=(
                final.request_id
                if final.status in {RequestStatus.COMPLETED, RequestStatus.FAILED}
                else None
            ),
        )

    async def _apply_to_definition(
        self, definition: ActionDefinition, signature: ElectronicSignature
    ) -> SignatureOutcome:
        if signature.meaning is SignatureMeaning.VALIDATION_APPROVAL:
            updated = definition.model_copy(
                update={
                    "status": ValidationStatus.VALIDATED,
                    "validated_at": signature.signed_at,
                    "validation_signature_id": signature.signature_id,
                }
            )
        else:
            updated = definition.model_copy(
                update={
                    "status": ValidationStatus.RETIRED,
                    "retired_at": signature.signed_at,
                    "retirement_signature_id": signature.signature_id,
                }
            )
        await self._definitions.update(updated)
        await self._record(
            signature.signer_subject,
            "definition.transition",
            f"definition:{definition.key}",
            updated.status.value,
            {"signature_id": signature.signature_id},
        )
        return SignatureOutcome(signature=signature, record_status=updated.status.value)

    async def list_signatures(
        self, record_type: RecordType, record_id: str
    ) -> Sequence[ElectronicSignature]:
        return await self._signature_store.for_record(record_type, record_id)

    # -------------------------------------------------------- periodic review

    async def get_review(self, review_id: str) -> PeriodicReview:
        review = await self._reviews.get(review_id)
        if review is None:
            raise NotFoundError(f"periodic review {review_id} not found")
        return review

    async def verify_audit(self) -> AuditVerification:
        reports: list[ChainReport] = []
        for chain_id in await self._audit_reader.chains():
            events = await self._audit_reader.events(chain_id)
            try:
                verified = verify_chain(events, self._audit_keys.keys)
            except AuditIntegrityError as exc:
                reports.append(
                    ChainReport(
                        chain_id=chain_id,
                        events=len(events),
                        intact=False,
                        error=f"sequence {exc.sequence}: {exc}",
                    )
                )
            else:
                reports.append(ChainReport(chain_id=chain_id, events=verified, intact=True))
        return AuditVerification(
            chains=tuple(reports),
            events_verified=sum(r.events for r in reports if r.intact),
            intact=all(r.intact for r in reports),
        )

    async def generate_review(
        self, command: GenerateReview, *, who: HumanPrincipal
    ) -> PeriodicReview:
        require_role(who, Role.SYSTEM_OWNER, Role.QUALITY)
        now = self._clock.now()
        if command.period_end <= command.period_start:
            raise ValidationFailedError("period_end must be after period_start")
        if command.period_end > now + timedelta(minutes=1):
            raise ValidationFailedError("a review cannot cover the future")
        system = await self.get_system(command.system_id)
        requests = await self._requests.in_period(
            system.system_id, command.period_start, command.period_end
        )
        records = await self._records.in_period(
            system.system_id, command.period_start, command.period_end
        )
        meanings: Counter[str] = Counter()
        for request in requests:
            for signature in await self._signature_store.for_record(
                RecordType.ACTION_REQUEST, request.request_id
            ):
                meanings[signature.meaning.value] += 1
        definitions = [
            d for d in await self._definitions.list() if d.spec.system_id == system.system_id
        ]

        def within(moment: datetime | None) -> bool:
            return moment is not None and command.period_start <= moment < command.period_end

        completed = sum(1 for r in records if r.status == "completed")
        failed = len(records) - completed
        failure_rate = failed / len(records) if records else 0.0
        alcoa_failures = sum(len(r.alcoa.failures) for r in records)
        audit = await self.verify_audit()
        by_status = Counter(r.status.value for r in requests)
        metrics = ReviewMetrics(
            requests_by_status=dict(sorted(by_status.items())),
            executions_completed=completed,
            executions_failed=failed,
            failure_rate=round(failure_rate, 4),
            signatures_by_meaning=dict(sorted(meanings.items())),
            alcoa_failures=alcoa_failures,
            definitions_validated=tuple(d.key for d in definitions if within(d.validated_at)),
            definitions_retired=tuple(d.key for d in definitions if within(d.retired_at)),
            audit_events_verified=audit.events_verified,
            audit_chains_verified=len(audit.chains),
            audit_integrity=audit.intact,
        )
        findings: list[str] = []
        if not audit.intact:
            findings.append("audit trail integrity verification failed")
        if failure_rate > FAILURE_FINDING_RATE:
            findings.append(
                f"execution failure rate {failure_rate:.1%} exceeds {FAILURE_FINDING_RATE:.0%}; "
                "investigate as deviations"
            )
        if alcoa_failures:
            findings.append(f"{alcoa_failures} ALCOA+ failures in execution records")
        if by_status.get(RequestStatus.EXPIRED.value):
            findings.append(
                f"{by_status[RequestStatus.EXPIRED.value]} requests expired awaiting signatures"
            )
        if system.review_overdue(now):
            findings.append("periodic review was overdue when this review was generated")
        remediation = not audit.intact or failure_rate > FAILURE_FINDING_RATE or alcoa_failures > 0
        review = PeriodicReview(
            review_id=new_id(),
            system_id=system.system_id,
            period_start=command.period_start,
            period_end=command.period_end,
            generated_at=now,
            generated_by=who.subject,
            metrics=metrics,
            findings=tuple(findings),
            conclusion="remediation-required" if remediation else "remains-validated",
        )
        await self._reviews.add(review)
        await self._record(
            who.subject,
            "review.generate",
            f"periodic-review:{review.review_id}",
            review.conclusion,
            {"system": system.system_id, "findings": list(findings)},
        )
        return review

    async def _apply_to_review(
        self, review: PeriodicReview, signature: ElectronicSignature
    ) -> SignatureOutcome:
        approved = review.model_copy(
            update={
                "status": ReviewStatus.APPROVED,
                "approval_signature_id": signature.signature_id,
                "approved_at": signature.signed_at,
            }
        )
        await self._reviews.update(approved)
        system = await self.get_system(review.system_id)
        status = (
            SystemStatus.VALIDATED
            if review.conclusion == "remains-validated"
            else SystemStatus.SUSPENDED
        )
        updated = system.model_copy(
            update={
                "last_reviewed_at": signature.signed_at,
                "status": status if system.status is not SystemStatus.RETIRED else system.status,
                "updated_at": signature.signed_at,
            }
        )
        await self._systems.update(updated)
        await self._record(
            signature.signer_subject,
            "system.review",
            f"system:{system.system_id}",
            updated.status.value,
            {"review_id": review.review_id, "conclusion": review.conclusion},
        )
        return SignatureOutcome(signature=signature, record_status=approved.status.value)


def flatten_text(value: Any) -> str:
    """Flatten nested inputs to text so the secret scanner sees every value."""
    if isinstance(value, dict):
        return " ".join(f"{k} {flatten_text(v)}" for k, v in value.items())
    if isinstance(value, list | tuple):
        return " ".join(flatten_text(v) for v in value)
    return str(value)
