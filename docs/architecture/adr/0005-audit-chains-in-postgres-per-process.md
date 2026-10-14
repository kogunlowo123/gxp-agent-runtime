# ADR-0005: One signed audit chain per process, stored in PostgreSQL

- Status: Accepted
- Date: 2026-10-14

## Context

agentic-core's `AuditLog` serializes appends in-process to keep sequence
numbers and hash links consistent. The identity fabric keeps one chain per
StatefulSet replica on a volume. The runtime's records already live in
PostgreSQL, and a Deployment (no per-replica volumes) is simpler to operate
and roll back.

## Decision

- Each process starts a new chain with id `<pod name>-<random>` and writes
  events to the `audit_events` table through a `SqlAuditSink`, with primary
  key (chain id, sequence) so forks or replays fail loudly.
- Events are signed with a dedicated Ed25519 audit key (separate from the
  record-signing key). Retired public keys are kept for verification.
- `/v1/audit/verification` and every periodic review verify all chains.
- Evidence is written before the state it describes (write-ahead): if the
  audit write fails, the request is not stored and nothing executes.

## Consequences

- The runtime is a stateless Deployment; audit data shares the database's
  HA, PITR and encryption.
- Database administrators could delete rows; deletion breaks chain
  verification and is detected at the next verification or periodic review.
  Regular exports to the Object Lock bucket provisioned by Terraform bound
  the loss (see the disaster recovery runbook).
