# Integrations: identity fabric, MCP, A2A, validated systems

## agent-identity-fabric

| Use | Fabric endpoint | Client |
|---|---|---|
| Is this agent credential still valid (revocation, suspension, epoch)? | `POST /oauth2/introspect` (RFC 7662) | `IdentityFabricClient.introspect` |
| May this agent perform `gxp:execute:<action>` on `gxp-action:<key>`? | `POST /v1/authorize` with the agent's bearer token | `IdentityFabricClient.authorize` |
| Credential the runtime presents to validated systems | `POST /oauth2/token`, `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, assertion = projected service-account token | `RuntimeCredentials` (cached until 60 s before expiry) |

A fabric `deny` stops the request (audited). A fabric `require_approval` is
carried into the runtime policy (`approve-fabric-escalation`). Transport
errors and unexpected bodies raise `dependency_unavailable` (HTTP 503): the
runtime never falls back to admitting an agent.

Without `GXP_FABRIC_URL`, fabric-issued EdDSA credentials are verified
offline against `GXP_AGENT_JWKS_URL` (issuer and audience checked, time
claims against the injected clock) and the runtime's local policy engine is
the only decision point. Revocation then takes effect at token expiry (at
most 15 minutes for fabric credentials); ADR-0004 explains when that is
acceptable.

## MCP

The official `mcp` SDK (`MCPServer`, streamable HTTP, stateless, JSON
responses) is mounted at `/mcp`. DNS-rebinding protection accepts only the
public host and `GXP_MCP_ALLOWED_HOSTS`.

| Tool | Input | Output | Authorization |
|---|---|---|---|
| `list_gxp_actions` | none | `CatalogResult` | `gxp:read` |
| `assess_gxp_action` | action, inputs, justification, `performed_at`, optional version/context/source records | `ActionPreview` | `gxp:execute:<action>` via fabric + policy |
| `request_gxp_action` | as above | `RequestView` | as above |
| `get_gxp_request` | `request_id` | `RequestView` | `gxp:read`, own requests only |
| `get_execution_record` | `record_id` | `ExecutionRecord` | `gxp:read`, own records only |

Every call authenticates the `Authorization` header of the HTTP request,
writes an audit event (`mcp.<tool>` with outcome `success`, `error` or
`unauthenticated`) and returns errors as MCP tool errors with the domain
error code.

## A2A

- Agent Card: `GET /.well-known/agent-card.json` (protocol 0.3.0) with
  name, description, url (`<public url>/a2a`), version, capabilities,
  skills (`execute-gxp-action`, `assess-gxp-action`, `get-gxp-task`),
  `securitySchemes` (HTTP bearer, fabric credential) and `security`.
- JSON-RPC 2.0 at `POST /a2a`, authenticated before parsing.
  - `message/send`: a data part with `action_id`, `inputs`,
    `justification`, `performed_at` and optional `version`, `context`,
    `source_records`, `skill` (`execute` default, or `assess`). `execute`
    returns a Task whose id is the request id; `assess` returns a Message.
  - `tasks/get`: `{"id": <request id>}`.
  - Task states: `pending_approval` -> `input-required`, `executing` ->
    `working`, `completed`, `failed`, `rejected`/`denied` -> `rejected`,
    `expired` -> `canceled`.
  - Errors: -32700 parse, -32600 invalid request, -32601 method not found,
    -32602 invalid params, -32001 task not found, -32003 forbidden, -32000
    dependency unavailable.

## Validated systems

Bindings are `METHOD /path/{required_input}` on the system's HTTPS base URL.
Placeholders must be required inputs and are percent-encoded; remaining
inputs form the JSON body. Calls carry `Idempotency-Key`, `X-GxP-Action`,
`X-GxP-Agent`, `X-Correlation-ID` and the runtime's fabric credential.
Redirects are not followed. 502/503/504 and transport errors are retried
(three attempts, exponential backoff) with the same idempotency key; other
non-success statuses and responses that are not JSON objects or that violate
the output schema produce a `failed` execution record.
