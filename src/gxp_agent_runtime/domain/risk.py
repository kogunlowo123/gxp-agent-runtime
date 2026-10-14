"""GAMP 5 quality risk management for agent actions.

Follows the functional risk assessment in ISPE GAMP 5 (2nd edition),
Appendix M3:

1. Severity: the worst impact of a wrong execution on patient safety,
   product quality or data integrity.
2. Probability of a fault, driven by the software category of the function
   (configured and custom software fail more often than standard software)
   and the action's observed failure history.
3. Risk class = severity x probability (class 1 highest).
4. Risk priority = risk class x detectability (low detectability raises
   priority).

The priority, plus the record-creating and reversibility properties of the
action, decide which electronic signatures are required before execution.
"""

from __future__ import annotations

from dataclasses import dataclass

from gxp_agent_runtime.domain.models import (
    ActionSpec,
    GampCategory,
    Level,
    RiskAssessment,
    Role,
    SignatureMeaning,
    SignatureRequirement,
)

H, M, L = Level.HIGH, Level.MEDIUM, Level.LOW

# (severity, probability) -> risk class
RISK_CLASS: dict[tuple[Level, Level], int] = {
    (H, H): 1,
    (H, M): 1,
    (H, L): 2,
    (M, H): 1,
    (M, M): 2,
    (M, L): 3,
    (L, H): 2,
    (L, M): 3,
    (L, L): 3,
}

# (risk class, detectability) -> risk priority
RISK_PRIORITY: dict[tuple[int, Level], Level] = {
    (1, L): H,
    (1, M): H,
    (1, H): M,
    (2, L): H,
    (2, M): M,
    (2, H): L,
    (3, L): M,
    (3, M): L,
    (3, H): L,
}

CATEGORY_PROBABILITY: dict[GampCategory, Level] = {
    GampCategory.INFRASTRUCTURE: L,
    GampCategory.NON_CONFIGURED: L,
    GampCategory.CONFIGURED: M,
    GampCategory.CUSTOM: H,
}

APPROVAL = SignatureRequirement(meaning=SignatureMeaning.APPROVAL, role=Role.APPROVER)
QUALITY_APPROVAL = SignatureRequirement(
    meaning=SignatureMeaning.QUALITY_APPROVAL, role=Role.QUALITY
)


@dataclass(frozen=True)
class FailureHistory:
    """Recent executions of the same action, used to adjust probability."""

    executions: int = 0
    failures: int = 0

    @property
    def rate(self) -> float:
        return self.failures / self.executions if self.executions else 0.0


class RiskClassifier:
    def __init__(self, *, elevated_failure_rate: float = 0.05, minimum_history: int = 20) -> None:
        if not 0 < elevated_failure_rate < 1:
            raise ValueError("elevated_failure_rate must be between 0 and 1")
        self._elevated = elevated_failure_rate
        self._minimum_history = minimum_history

    def probability(self, spec: ActionSpec, history: FailureHistory) -> tuple[Level, list[str]]:
        base = CATEGORY_PROBABILITY[spec.gamp_category]
        notes = [f"GAMP category {int(spec.gamp_category)} gives base probability {base.value}"]
        if history.executions >= self._minimum_history and history.rate >= self._elevated:
            raised = Level.of_rank(base.rank + 1)
            notes.append(
                f"observed failure rate {history.rate:.1%} over {history.executions} executions "
                f">= {self._elevated:.0%}: probability raised to {raised.value}"
            )
            return raised, notes
        return base, notes

    def assess(self, spec: ActionSpec, *, history: FailureHistory | None = None) -> RiskAssessment:
        history = history or FailureHistory()
        severity = spec.impact.severity
        rationale = [
            f"severity {severity.value} (patient safety {spec.impact.patient_safety.value}, "
            f"product quality {spec.impact.product_quality.value}, "
            f"data integrity {spec.impact.data_integrity.value})"
        ]
        probability, notes = self.probability(spec, history)
        rationale.extend(notes)
        risk_class = RISK_CLASS[(severity, probability)]
        priority = RISK_PRIORITY[(risk_class, spec.detectability)]
        rationale.append(
            f"risk class {risk_class}; detectability {spec.detectability.value}; "
            f"priority {priority.value}"
        )
        required = self.required_signatures(spec, priority)
        if required:
            rationale.append("signatures required: " + ", ".join(r.meaning.value for r in required))
        return RiskAssessment(
            severity=severity,
            probability=probability,
            risk_class=risk_class,
            detectability=spec.detectability,
            priority=priority,
            rationale=tuple(rationale),
            required_signatures=required,
        )

    @staticmethod
    def required_signatures(spec: ActionSpec, priority: Level) -> tuple[SignatureRequirement, ...]:
        if priority is Level.HIGH:
            return (APPROVAL, QUALITY_APPROVAL)
        if priority is Level.MEDIUM:
            return (QUALITY_APPROVAL,)
        if spec.creates_gxp_record or not spec.reversible:
            return (APPROVAL,)
        return ()
