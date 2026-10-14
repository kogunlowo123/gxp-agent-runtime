# Runbook: signing key rotation

Rotate the record-signing key and the audit key every 12 months, and
immediately on suspected exposure.

1. Generate new Ed25519 keys (`records-<new kid>.pem`, `audit-<new kid>.pem`)
   in a controlled ceremony and store them in the secret manager with the
   names External Secrets expects (`gxp-agent-runtime-records-key-<kid>`,
   `gxp-agent-runtime-audit-key-<kid>`).
2. Export the old public keys and store them in a secret named by
   `secrets.trustedPublicKeys` (one entry `<old kid>.pem` per key, for
   example `records-2026-10.pem` and `audit-2026-10.pem`); the chart mounts
   it and sets `GXP_TRUSTED_PUBLIC_KEYS_DIR`, so existing records and chains
   stay verifiable:

   ```bash
   openssl pkey -in records-2026-10.pem -pubout -out public/records-2026-10.pem
   openssl pkey -in audit-2026-10.pem -pubout -out public/audit-2026-10.pem
   kubectl -n gxp-runtime create secret generic gxp-agent-runtime-retired-keys --from-file=public/
   ```

3. Set `secrets.signingKeyFile` and `secrets.auditKeyFile` to the new file
   names and upgrade the release. New pods start new audit chains with the
   new key id.
4. Verify: `/.well-known/jwks.json` lists the new kids;
   `/v1/audit/verification` reports `intact: true` for old and new chains.
5. Remove the old private keys from the secret manager. Keep the public
   keys for the record retention period.

On suspected exposure, also review signatures and records created between
the suspected exposure and rotation: verification still succeeds for forged
items signed with a stolen key, so cross-check them against the audit trail
and IdP sign-in logs.
