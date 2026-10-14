# ADR-0002: GAMP 5 functional risk assessment decides the approval route

- Status: Accepted
- Date: 2026-10-14

## Context

Approval effort must be proportionate to risk (ICH Q9(R1), FDA CSA). A single
"approve everything" rule wastes reviewer time and trains people to sign
without reading; "approve nothing" is unacceptable for GxP records.

## Decision

Use the GAMP 5 (2nd edition) Appendix M3 method on every request:

1. Severity = worst of patient safety, product quality and data integrity
   impact declared in the validated definition.
2. Probability from the software category of the function (1 and 3 low,
   4 medium, 5 high), raised one level when the action's observed failure
   rate over at least 20 recent executions reaches 5%.
3. Risk class from severity x probability (class 1 highest).
4. Risk priority from risk class x detectability.

Signature routing: high priority -> process-owner `approval` and QA
`quality-approval` by two different people; medium -> QA approval; low
priority that creates a GxP record or is irreversible -> approval; otherwise
autonomous. The GxP policy can add an approval (delegation, fabric
escalation) but cannot remove a risk-driven one.

## Consequences

- The rationale (each factor and the resulting route) is stored with the
  request and visible to signers and inspectors.
- Failure history makes risk adaptive without anyone editing a definition.
- The matrix lives in code (`domain/risk.py`) under code-owner review;
  changing it is a GxP-relevant change.
