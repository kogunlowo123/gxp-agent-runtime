# Configuration reference

All settings are `GXP_*` environment variables (see
`src/gxp_agent_runtime/config.py`). The service refuses to start with
incomplete or contradictory configuration.

| Variable | Required | Default | Description |
|---|---|---|---|
| `GXP_ENVIRONMENT` | no | `production` | `production` forbids ephemeral keys and plain-HTTP public URLs |
| `GXP_PUBLIC_URL` | yes | | Public URL; A2A card URL and MCP Host allow list |
| `GXP_DATABASE_URL` | yes | | SQLAlchemy async URL (`postgresql+asyncpg://...`) |
| `GXP_INSTANCE_ID` | no | host name | Prefix of this process's audit chain id (Helm sets the pod name) |
| `GXP_SIGNING_KEY_FILE` | yes* | | Ed25519 PEM signing signature manifests and execution records; key id = file stem |
| `GXP_AUDIT_KEY_FILE` | yes* | | Ed25519 PEM signing audit events |
| `GXP_TRUSTED_PUBLIC_KEYS_DIR` | no | | Retired public keys (`<kid>.pem`) kept for verification |
| `GXP_DEV_EPHEMERAL_KEYS` | no | `false` | In-memory keys for development; replaces the two * settings; refused in production |
| `GXP_SIGNER_ISSUER` | yes | | Enterprise OIDC issuer (users and re-authentication) |
| `GXP_SIGNER_AUDIENCE` | yes | | Audience / client id of user and re-authentication tokens |
| `GXP_SIGNER_JWKS_URL` | yes | | IdP JWKS |
| `GXP_SIGNER_ROLES_CLAIM` | no | `roles` | Claim carrying GxP roles |
| `GXP_SIGNER_NAME_CLAIM` | no | `name` | Claim used as printed name on signatures |
| `GXP_REAUTH_MAX_AGE_SECONDS` | no | `300` | Maximum age of `auth_time` at signing (30-900) |
| `GXP_CHALLENGE_TTL_SECONDS` | no | `300` | Signing challenge validity (60-900) |
| `GXP_FABRIC_URL` | yes** | | agent-identity-fabric base URL (introspection, authorize, token) |
| `GXP_AGENT_ISSUER` | yes** | | Fabric issuer, for offline verification |
| `GXP_AGENT_JWKS_URL` | yes** | | Fabric JWKS, for offline verification |
| `GXP_AGENT_AUDIENCE` | no | `agent-platform` | Audience of agent credentials |
| `GXP_RUNTIME_CLIENT_ID` | no | | This runtime's SPIFFE ID in the fabric; enables outbound credentials |
| `GXP_WORKLOAD_TOKEN_FILE` | with client id | | Projected service-account token exchanged at the fabric |
| `GXP_POLICY_FILE` | no | `policies/gxp-runtime.yaml` | GxP policy (image sets `/app/policies/gxp-runtime.yaml`) |
| `GXP_APPROVAL_TTL_HOURS` | no | `72` | Approval window before requests expire (1-720) |
| `GXP_MAX_CLOCK_SKEW_SECONDS` | no | `120` | Allowed future skew of `performed_at` |
| `GXP_MAX_ACTIVITY_AGE_SECONDS` | no | `900` | Maximum delay between activity and submission (contemporaneous) |
| `GXP_CONNECTOR_TIMEOUT_SECONDS` | no | `30` | Validated-system call timeout |
| `GXP_EXPIRY_SWEEP_SECONDS` | no | `60` | Interval of the expiry sweep |
| `GXP_MCP_ALLOWED_HOSTS` | no | `[]` | JSON list of extra Host headers accepted on `/mcp` |
| `GXP_LOG_LEVEL` | no | `INFO` | |
| `GXP_OTLP_ENDPOINT` | no | | OTLP gRPC endpoint for traces |
| `GXP_HOST` / `GXP_PORT` | no | `127.0.0.1` / `8080` | The image sets host `0.0.0.0` |
| `GXP_FORWARDED_ALLOW_IPS` | no | `127.0.0.1` | Proxies trusted for `X-Forwarded-*` |

\* unless `GXP_DEV_EPHEMERAL_KEYS=true` outside production.
\*\* `GXP_FABRIC_URL`, or both `GXP_AGENT_ISSUER` and `GXP_AGENT_JWKS_URL`.

## Policy

`policies/gxp-runtime.yaml` is evaluated by the agentic-core policy engine
(deny overrides, then require_approval, then allow; default deny). Its
version and digest are stored with every request. Changing it is a
GxP-relevant change (code owners, release, validation package).
