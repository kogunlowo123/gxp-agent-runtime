# ADR-0001: Agents act only through registered, versioned action definitions

- Status: Accepted
- Date: 2026-10-14

## Context

A validated system stays validated because its intended use is specified,
risk-assessed and verified. An agent with a general API client can do
anything the API allows, which is an unspecified use. Giving agents raw API
access would make every agent deployment a change to the validated system.

## Decision

- Agents never receive credentials for validated systems. The runtime holds
  the only path (network policy plus system-side credentials bound to the
  runtime's identity).
- Each permitted operation is an `ActionSpec`: action id, semantic version,
  target system, JSON Schema for inputs and outputs, HTTP binding, GxP impact,
  detectability, reversibility, whether it creates a GxP record, and whether
  a source record must be cited.
- The spec is content-addressed (sha256 over canonical JSON). The digest is
  what QA approves, what every request stores, and what every execution
  record carries.
- Lifecycle: draft -> validated (QA `validation-approval` e-signature, not
  the author, citing the OQ/validation reference) -> retired (QA
  `retirement`). Versions only increase; a version is immutable once
  registered. Requests without a version use the latest validated one.

## Consequences

- Adding an agent capability is a controlled change (new definition version
  plus verification), not a change to the validated system.
- Agents cannot invent parameters: inputs are schema-checked and the binding
  percent-encodes path parameters.
- The definition catalog is the specification an inspector reviews.
