# Runbook: first deployment and startup

## Prerequisites

- Kubernetes >= 1.27 (EKS reference; AKS and GKE supported) with External
  Secrets Operator and a `ClusterSecretStore` named `platform-secrets` bound
  to the cloud secret manager.
- agent-identity-fabric deployed; the runtime registered in it as an agent
  (for example `spiffe://<trust-domain>/agent/platform/gxp-agent-runtime`)
  with a workload binding to the `gxp-runtime/gxp-agent-runtime` service
  account and audience `identity-fabric`.
- Enterprise IdP application for the runtime exposing roles
  `gxp-system-owner`, `gxp-approver`, `gxp-qa`, `gxp-auditor`, emitting
  `name`, `auth_time` and `amr` in ID tokens, and allowing `prompt=login`
  with `nonce` for re-authentication.
- Each validated system's integration API trusts the runtime's fabric
  credential and nothing else for agent-originated changes.

## 1. Provision cloud resources

```bash
cd deployments/terraform/aws        # or azure / gcp
terraform init                      # configure an encrypted remote backend first
terraform apply -var-file=<environment>.tfvars
```

Record the outputs: workload-identity binding, database URL secret name, KMS
key, evidence bucket.

## 2. Key ceremony (record-signing key and audit key)

Generate two Ed25519 keys on a controlled workstation; never in Terraform.

```bash
openssl genpkey -algorithm ed25519 -out records-2026-10.pem
openssl genpkey -algorithm ed25519 -out audit-2026-10.pem
aws secretsmanager create-secret --name gxp-agent-runtime-records-key-2026-10 \
  --kms-key-id <kms_key_arn> --secret-string file://records-2026-10.pem
aws secretsmanager create-secret --name gxp-agent-runtime-audit-key-2026-10 \
  --kms-key-id <kms_key_arn> --secret-string file://audit-2026-10.pem
shred -u records-2026-10.pem audit-2026-10.pem
```

Azure: `az keyvault secret set --vault-name <vault> --name ... --file <pem>`.
GCP: `gcloud secrets create ... --data-file=<pem>`. Record the ceremony
(who, when, key ids) in the system's change record.

## 3. Namespace and secret sync

```bash
kubectl apply -k deployments/kubernetes
kubectl -n gxp-runtime get externalsecret   # all READY=True
```

## 4. Install the chart

Create `<environment>.yaml` with every value marked REQUIRED in
`values.yaml` (public URL, signer issuer/audience/JWKS, fabric URL, runtime
client id, key file names `records-<kid>.pem` / `audit-<kid>.pem`) plus the
workload-identity annotation from Terraform:

```bash
helm upgrade --install gxp oci://ghcr.io/kogunlowo123/charts/gxp-agent-runtime \
  --version 0.1.0 -n gxp-runtime -f <environment>.yaml --wait
```

## 5. Verify

```bash
kubectl -n gxp-runtime rollout status deployment/gxp-gxp-agent-runtime
kubectl -n gxp-runtime port-forward svc/gxp-gxp-agent-runtime 8080:80
curl -sf localhost:8080/readyz
curl -s localhost:8080/.well-known/jwks.json | jq '.keys[].kid'
curl -s localhost:8080/.well-known/agent-card.json | jq .url
```

Expected: `{"status":"ready"}`, both key ids, the public A2A URL.

## 6. Register systems and definitions (installation qualification)

1. A system owner registers each validated system (`POST /v1/systems`) with
   its validation summary reference and last review date.
2. The system owner registers each action definition as a draft.
3. QA verifies each definition against its OQ protocol and signs
   `validation-approval` (two-step signing ceremony).
4. Record the release's validation package (GitHub release asset) and the
   image digest in the deployment's IQ record.
