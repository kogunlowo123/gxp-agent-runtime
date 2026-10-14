# GxP Agent Runtime

A runtime that lets AI agents act on validated BioPharma systems (LIMS, MES,
QMS, ELN) without leaving the validated state. Agents never call those
systems directly: they request a registered, validated, versioned action
definition; the runtime classifies the risk with the GAMP 5 method, checks
the request against ALCOA+, decides with the identity fabric and its own GxP
policy, collects 21 CFR Part 11 electronic signatures when a human must sign
off, executes through the definition's binding, and keeps a signed execution
record and audit trail that an inspector can verify.

```
Action Request -> Risk Classification -> Approval Workflow -> Execution Record
```

## Capabilities

| Capability | Implementation |
|---|---|
| Validated systems only | Registry of systems in validated state (validation reference, GAMP category, HTTPS endpoint, periodic review interval); suspended, retired or review-overdue systems refuse actions |
| Registered action definitions | Versioned specs with JSON Schema inputs/outputs, HTTP binding, GxP impact and detectability; content-addressed by sha256; draft -> validated (QA e-signature, not the author) -> retired |
| GAMP 5 risk classification | Severity (patient safety, product quality, data integrity) x probability (software category, observed failure rate) -> risk class; x detectability -> priority; rationale stored with the request |
| Approval workflow | High priority: process-owner approval + QA approval by two different people; medium: QA approval; record-creating or irreversible: approval; only low-risk, reversible, non-record actions run autonomously |
| Part 11 e-signatures | Single-use challenge; OIDC re-authentication with nonce, fresh `auth_time`, accepted `amr`; manifest with printed name, time and meaning; Ed25519 signature over the record digest; rejection with reason |
| ALCOA+ | Attributable, legible, contemporaneous, original, accurate, complete, consistent on requests; plus enduring and available (read-back) on records |
| Execution records | Input, output and raw-response digests, signatures, risk and policy outcome, ALCOA+ assessment; signed and verifiable at `/v1/execution-records/{id}/verification` |
| Audit trail | agentic-core hash chain, Ed25519-signed, one chain per process in PostgreSQL; `/v1/audit/verification` |
| Validation evidence | URS -> test traceability matrix with executed results (`python -m gxp_agent_runtime.validation`), produced in CI and attached to every release |
| Periodic review | Executions, failures, signatures, definition changes and audit integrity for a period; QA approval keeps or suspends validated state |
| Agent identity | agent-identity-fabric introspection and `/v1/authorize` (or offline verification of fabric credentials) plus local GxP policy; scopes `gxp:read`, `gxp:execute:<action>` |
| Agent protocols | REST, MCP tools over streamable HTTP at `/mcp`, A2A Agent Card and JSON-RPC at `/a2a` |
| Observability | Prometheus metrics, OpenTelemetry traces, JSON logs with correlation IDs, SLO and GxP alerts, Grafana dashboard |

Shared controls (policy engine, audit chain, provenance digests, secret
scanning, logging, telemetry) come from
[agentic-core](https://github.com/kogunlowo123/agentic-core); agent
credentials come from
[agent-identity-fabric](https://github.com/kogunlowo123/agent-identity-fabric).

## Quick start (local)

Requires Docker. No API keys or cloud credentials are needed.

```bash
docker compose up --build
curl -s localhost:8080/.well-known/agent-card.json | jq .skills
```

The compose stack runs PostgreSQL, agent-identity-fabric, an OIDC provider
standing in for the enterprise IdP, and an OpenTelemetry collector.

## Development

```bash
uv sync
make check        # ruff, black, mypy --strict, bandit, contracts, tests (coverage >= 90%)
make validation   # tests with JUnit output + URS traceability matrix (strict)
make integration  # PostgreSQL tests (needs GXP_TEST_DATABASE_URL)
```

Test suites: `tests/unit`, `tests/security` (attacks mapped to the threat
model), `tests/chaos` (dependency failures, concurrent signing),
`tests/performance` (latency budgets; `locustfile.py` for load), `tests/e2e`
(REST, MCP and A2A flows; property-based OpenAPI contract test),
`tests/integration` (PostgreSQL). Validated systems are exercised through
recorded wire shapes over `httpx.MockTransport`.

## API

| Endpoint | Caller | Purpose |
|---|---|---|
| `POST /v1/systems`, `GET /v1/systems[/{id}]` | System owner; any GxP role reads | Validated system registry |
| `POST /v1/action-definitions`, `GET /v1/action-definitions[/{id}/{version}]` | System owner; any GxP role reads | Versioned action definitions |
| `GET /v1/actions` | Agent (`gxp:read`) | Catalog of validated actions in the agent's scopes |
| `POST /v1/actions/assess` | Agent | Risk, ALCOA+ and policy preview |
| `POST /v1/action-requests` | Agent (`gxp:execute:<action>`) | Submit; executes or waits for signatures |
| `GET /v1/action-requests[/{id}]` | Approvers, QA, auditors; agent for its own | Approval queue and status |
| `POST /v1/signatures/challenges`, `POST /v1/signatures` | Approver, QA | Part 11 signing ceremony |
| `GET /v1/signatures` | Any GxP role | Signatures on a record |
| `GET /v1/execution-records/{id}[/verification]` | Agent (own), QA, auditor | Records and their verification |
| `POST /v1/periodic-reviews`, `GET /v1/periodic-reviews/{id}` | System owner, QA | Periodic review |
| `GET /v1/audit/verification` | QA, auditor | Audit-trail integrity |
| `/mcp` | Agent | MCP tools: `list_gxp_actions`, `assess_gxp_action`, `request_gxp_action`, `get_gxp_request`, `get_execution_record` |
| `GET /.well-known/agent-card.json`, `POST /a2a` | Agent | A2A discovery, `message/send`, `tasks/get` |
| `GET /.well-known/jwks.json` | Anyone | Keys that verify records, signatures and audit chains |

Full contract: [docs/api/openapi.json](docs/api/openapi.json); JSON Schemas in [schemas/](schemas/).

## Deployment

| Layer | Location |
|---|---|
| Container image | `Dockerfile` (non-root, read-only root filesystem compatible) |
| Helm chart | `deployments/helm/gxp-agent-runtime` (Deployment, HPA, PDB, NetworkPolicy, ServiceMonitor, projected token for the fabric) |
| Namespace and secret sync | `deployments/kubernetes` (restricted Pod Security, External Secrets) |
| Cloud infrastructure | `deployments/terraform/{aws,azure,gcp}`: managed PostgreSQL, KMS, secret store, WORM evidence storage, workload identity. AWS is the reference deployment |

See the [startup runbook](docs/runbooks/startup.md).

## Documentation

- [Architecture](docs/architecture/overview.md), [agent specification](docs/architecture/agent-specification.md), [integrations: identity fabric, MCP, A2A](docs/architecture/integrations.md)
- [ADRs](docs/architecture/adr/)
- [Threat model and risk register](docs/security/threat-model.md)
- [Compliance control mapping](docs/compliance/control-mapping.md)
- [Validation approach and acceptance criteria](docs/validation/validation-plan.md), [URS](docs/validation/urs.yaml)
- Runbooks: [startup](docs/runbooks/startup.md), [monitoring](docs/runbooks/monitoring.md), [incident response](docs/runbooks/incident-response.md), [periodic review](docs/runbooks/periodic-review.md), [key rotation](docs/runbooks/key-rotation.md), [rollback](docs/runbooks/rollback.md), [disaster recovery](docs/runbooks/disaster-recovery.md)
- [Configuration reference](docs/operations/configuration.md), [cost and scalability](docs/operations/cost-and-scalability.md)

## License

Apache-2.0
