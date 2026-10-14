# ADR-0004: Agent authorization through agent-identity-fabric, offline verification as fallback

- Status: Accepted
- Date: 2026-10-14

## Context

Agents already hold credentials from agent-identity-fabric, which can
suspend or revoke an agent immediately (credential epochs) and decide
authorization centrally. Some deployments (validation environments,
disconnected sites) run the runtime without network access to the fabric.

## Decision

- With `GXP_FABRIC_URL`: every agent call introspects the credential and
  calls the fabric's `/v1/authorize` for `gxp:execute:<action>`; a fabric deny
  is final, a fabric `require_approval` is carried into the runtime policy.
- Without it: fabric-issued EdDSA credentials are verified offline against
  the fabric JWKS; the runtime policy is the decision point.
- In both modes the runtime's own GxP policy runs afterwards. No mode admits
  unauthenticated or unverified agents; fabric unavailability returns 503.

## Consequences

- Offline mode honours revocation only at token expiry (15 minutes at most
  for fabric credentials). It is intended for validation and isolated
  environments; production deployments set the fabric URL (the Helm chart's
  CI values do).
