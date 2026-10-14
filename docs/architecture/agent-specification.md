# Agent specification

The runtime is a controlled execution layer for agents. This document states
its own mandate and the contract it imposes on every agent that uses it.

## Role and mission

- **Purpose:** be the only path by which AI agents change or read validated
  GxP systems, and leave evidence an inspector accepts.
- **Business objective:** let quality, QC and manufacturing teams use agents
  for routine work without re-validating each system the agents touch.
- **Protected resources:** validated systems' integration APIs; GxP records
  created by actions; e-signature manifests; execution records; audit chains;
  signing keys.
- **Operating boundaries:** executes only validated definition versions
  against validated systems with current periodic reviews; never follows
  redirects; never stores credentials; never executes when evidence cannot be
  written.
- **Delegated responsibility:** authorization of agents is delegated to
  agent-identity-fabric; signature decisions to named humans holding IdP
  roles; policy content to QA through `policies/gxp-runtime.yaml` (code-owned).

## Delegated scope

| Allowed autonomously | Requires e-signatures | Disallowed | Escalation |
|---|---|---|---|
| Low priority, reversible, non-record actions within scope (e.g. read sample status) | Medium priority: QA approval. High priority: process owner + QA (two people). Record-creating or irreversible: approval. Delegated agents: approval | Unvalidated or retired definitions; suspended/retired systems; overdue periodic review; ALCOA+ failures; out-of-scope actions; delegation deeper than one hop; credentials in requests | Failed executions page on-call and open a deviation; ALCOA+ failures on records page QA; signature-failure spikes page security |

Risk classification uses GAMP 5 Appendix M3 (see ADR-0002).

## Objectives

| Type | Definition | Target |
|---|---|---|
| SLO availability | Non-5xx share of agent and signing endpoints | 99.9% over 30 days |
| SLO latency | p99 `/v1/action-requests` (including validated-system call) | < 2 s |
| SLO latency | p99 `/v1/signatures/challenges` | < 300 ms |
| SLI | `gxp:request_errors:ratio_5m`, latency histograms, `gxp_execution_duration_seconds` | Prometheus |
| KPI | Share of agent changes to validated systems that went through the runtime | 100% (enforced by network policy and system credentials) |
| KPI | Execution records passing verification at periodic review | 100% |
| KPI | Median time from request to final signature | Reported per system in the dashboard |
| Completion | An action is complete when its execution record is signed, stored, read back identical, and referenced by an audit event | Enforced: storage verification failure raises |

## Permissions

| Mechanism | Use |
|---|---|
| RBAC (humans) | IdP roles `gxp-system-owner`, `gxp-approver`, `gxp-qa`, `gxp-auditor`; each signature meaning maps to roles |
| ABAC (agents) | GxP policy facts: scopes, delegation, definition and system status, review currency, risk class and priority, record creation, reversibility, ALCOA+ result, fabric decision |
| Agent identity | SPIFFE IDs issued by agent-identity-fabric |
| OAuth 2.0 / OIDC | Fabric RFC 7662 introspection and `/v1/authorize`; RFC 7523 jwt-bearer for the runtime's own credential; enterprise OIDC for users; OIDC re-authentication (`nonce`, `auth_time`, `amr`) for signatures |
| Workload identity | Projected service-account token exchanged at the fabric; cloud workload identity (IRSA, Azure Workload ID, GKE WI) for evidence storage |

Agent scopes: `gxp:read` (catalog, own requests and records) and
`gxp:execute:<action_id>` (or a wildcard such as `gxp:execute:lims.*`).

## Inputs and outputs

Every body is a Pydantic model with a JSON Schema in `schemas/`:

| Contract | Schema |
|---|---|
| Submit action | `submit-action.request.schema.json` (action, version, inputs, justification, context, source records, `performed_at`) |
| Request view | `action-request.response.schema.json` (status, risk, policy, ALCOA+, outstanding signatures, record digest) |
| Preview | `action-preview.response.schema.json` |
| Signing | `signature-challenge.*`, `apply-signature.request`, `signature-outcome.response`, `electronic-signature` |
| Records | `execution-record.schema.json`, `record-verification.response.schema.json` |
| Registry | `register-system.request`, `register-definition.request`, `action-spec` |
| Reviews | `generate-review.request`, `periodic-review` |

### Validation

Inputs reject unknown fields; action inputs must satisfy the definition's
JSON Schema (format checking on); `performed_at` must be within the
contemporaneity window; source records must carry `sha256:` digests;
justification is required; credential material anywhere in the request is
rejected before storage.

### Provenance and audit metadata

Each request stores the definition digest, inputs digest, cited source
record digests and the delegation chain. Each execution record stores the
request digest (what signers signed), output and raw-response digests, the
signatures, the policy version and digest, and is itself signed. Every audit
event carries actor, action, resource, outcome, correlation ID and the
relevant digests.

## Contract for agents

1. Discover actions with `GET /v1/actions` (or MCP `list_gxp_actions`).
2. Optionally preview with `POST /v1/actions/assess`.
3. Submit with the inputs, a justification, the time the activity was
   performed and the source records relied on.
4. If `pending_approval`, poll `GET /v1/action-requests/{id}` (or A2A
   `tasks/get`); do not resubmit. Expired requests must be resubmitted.
5. Read the execution record; treat `failed` as a deviation, not a retry
   signal.
