# ADR-0003: Part 11 signatures by challenge, OIDC re-authentication and manifest signing

- Status: Accepted
- Date: 2026-10-14

## Context

21 CFR 11.200(a) requires non-biometric signatures to use two distinct
identification components, executed at each signing when not in a
continuous controlled session; 11.50 requires printed name, date/time and
meaning; 11.70 requires signatures to be linked to their records so they
cannot be excised, copied or transferred. The enterprise IdP already owns
passwords and MFA; the runtime must not handle them.

## Decision

- Signing is two-step. `POST /v1/signatures/challenges` fixes the record,
  its current digest and the meaning, and returns a random single-use nonce
  (5-minute validity) and the statement being attested.
- The signer re-authenticates at the IdP with `prompt=login`, `max_age` and
  the nonce, and submits the ID token. The runtime requires: same subject as
  the session, matching nonce, `auth_time` within 5 minutes, and at least one
  RFC 8176 `amr` value. The challenge is consumed with compare-and-swap, so
  it can be used once.
- The record digest is recomputed at signing; any change since the
  challenge rejects the signature.
- The manifest (signer subject and printed name, meaning, reason, time,
  auth time and methods, record type/id/digest, challenge id) is signed with
  the runtime's Ed25519 record key. The signature event goes into the signed
  audit chain.
- Separation of duties: one person cannot sign twice on a request; authors
  cannot validate their definitions; review generators cannot approve their
  reviews; roles gate each meaning.

## Consequences

- Passwords never reach the runtime; MFA policy stays with the IdP.
- Verification needs only the published public keys (`/.well-known/jwks.json`)
  and the stored records.
- Signers whose IdP does not emit `amr` must have it enabled (Entra ID, Okta
  and Google Workspace can), otherwise signing is refused.
