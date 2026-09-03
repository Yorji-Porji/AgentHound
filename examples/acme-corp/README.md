# Acme Robotics — reference cloud environment

A **fake but production-shaped** AWS + GCP + Azure org for exercising AgentHound's
cloud collectors end-to-end. Everything here is identity/permission **metadata**
(account IDs, ARNs, role names, policies, scopes, GUIDs) — **never credential
values** (AgentHound invariant #1). AgentHound is network-free and upload-only:
it *never* calls a cloud API. You generate the export yourself and hand it over.

The values are obvious placeholders chosen so you can **find-and-replace them with
your real ones** later (see [Replace with your real values](#replace-with-your-real-values)),
then re-run against your actual org.

## Run it

```bash
# from the repo root, with the venv active (pip install -e ".[dev]")
bash examples/acme-corp/run.sh          # prints the findings
KEEP=1 bash examples/acme-corp/run.sh   # also keeps the emitted BloodHound payload
```

Or drive the CLI directly:

```bash
agenthound aws   -i examples/acme-corp/aws_iam.json    -o aws.json
agenthound gcp   -i examples/acme-corp/gcp_iam.json    -o gcp.json
agenthound azure -i examples/acme-corp/azure_rbac.json -o azure.json
agenthound infer aws.json gcp.json azure.json -o merged.json
agenthound emit merged.json -o acme-bloodhound.json     # ingest into BloodHound CE
```

## The environment

| Cloud | Container | Key identities |
|---|---|---|
| **AWS** | prod account `481516234299` (trusts security `235711131719`, CI `314159265358`, vendor `999988887777`) | `OrganizationAdmin`, `terraform-ci`, `app-payments`, `ReadOnlySecurityAudit`, `vendor-datadog`, user `legacy-jenkins` |
| **GCP** | org `acmerobotics.io`, projects `acme-prod` / `acme-staging` | SAs `terraform-deployer`, `payments-api`; groups `org-admins`, `dev-platform`; GitHub workload-identity principal; user `auditor` |
| **Azure** | tenant `acmerobotics`, MG `acme-root`, subscription `…0001`, RG `prod-rg` | `global-platform-sp`, `terraform-azure-sp`, `payments-func-mi`, `ci-runner-sp`, `auditors`, `breakglass-admin` |

## Planted findings

What AgentHound should surface — each is a deliberate teaching case:

| # | Cloud | Finding | Why it matters |
|---|---|---|---|
| 1 | AWS | `terraform-ci` is **admin** via an inline `Allow *:*`, and is assumable from the CI account's OIDC role | The over-privileged-CI classic: a build role that is effectively root, reachable from CI federation |
| 2 | AWS | `OrganizationAdmin` (AdministratorAccess) is **assumable from break-glass** in the security account | Cross-account `CanAssume` into full admin |
| 3 | AWS | `legacy-jenkins` holds `iam:*` + `s3:*` but is **NOT flagged admin** | Evidence, not vibes — admin means `Action:* on Resource:*`, which this is not (still worth review, but not full-access) |
| 4 | GCP | `dev-platform` group **and** the GitHub workload-identity principal can **impersonate** `terraform-deployer` (which is `roles/owner`) | `serviceAccountTokenCreator` / `workloadIdentityUser` = GCP's assume-role; a non-admin reaches owner |
| 5 | Azure | `terraform-azure-sp` is **flagged admin by evidence** — its custom role *"Acme Deploy All"* grants `*` with no `notActions` | The role *name* is irrelevant; the definition's content is the verdict |
| 6 | Azure | `ci-runner-sp` (Contributor) is **NOT admin** | Contributor has `*` but `notActions` on access-management, so it is not full-access |

The headline cross-cloud query, `injection_to_full_access_identity`
(`cypher/queries.yaml`), lights up every full-access identity above regardless of
provider; `gcp_service_account_impersonation_escalation` walks finding #4.

## Replace with your real values

Find-and-replace these tokens in the three JSON files, then re-run. (Leave the
**Azure built-in role-definition GUIDs** — Owner `8e3af657…`, Reader `acdd72a7…`,
Contributor `b24988ac…`, Storage Blob Data Contributor `ba92f5b4…`, User Access
Administrator `18d7d88d…` — as-is; they are global and identical in every tenant.
Only the **custom** role `aaaaaaaa-…-acme` is yours to change.)

### `aws_iam.json`
| Placeholder | Replace with |
|---|---|
| `481516234299` | your prod account ID |
| `235711131719` / `314159265358` / `999988887777` | your security / CI / vendor account IDs |
| `OrganizationAdmin`, `terraform-ci`, `app-payments`, `ReadOnlySecurityAudit`, `vendor-datadog`, `legacy-jenkins` | your real user/role names |
| `acme-payments-prod`, `acme-data-lake-prod`, `Orders`, `prod/payments/stripe-*` | your real bucket / table / secret ARNs |
| `us-east-1` | your region |

### `gcp_iam.json`
| Placeholder | Replace with |
|---|---|
| `acme-prod`, `acme-staging` | your project IDs |
| `terraform-deployer@…`, `payments-api@…` | your service-account emails (keep them identical where one SA is both grantee and impersonation target, so the nodes join) |
| `org-admins@acmerobotics.io`, `dev-platform@acmerobotics.io`, `auditor@acmerobotics.io` | your groups / users |
| `acme-prod-artifacts`, `payments-db-prod` | your bucket / Cloud SQL instance |
| `729000000001`, `github-pool`, `acmerobotics/infra` | your project number, WIF pool, and repo |

### `azure_rbac.json`
| Placeholder | Replace with |
|---|---|
| `00000000-0000-0000-0000-000000000001` | your subscription ID |
| `acme-root` | your management-group name |
| `11111111-…0001` … `66666666-…0006` | your principals' real object IDs |
| `global-platform-sp`, `terraform-azure-sp`, `payments-func-mi`, `ci-runner-sp`, `auditors`, `breakglass-admin@…` | your principal display names |
| `aaaaaaaa-0000-0000-0000-00000000acme` + `"Acme Deploy All"` | your custom role's GUID + name |
| `prod-rg`, `acmepaymentsprod` | your resource group / storage account |

## Generating your real exports (read-only)

```bash
# AWS  — needs iam:GetAccountAuthorizationDetails
aws iam get-account-authorization-details > aws_iam.json

# GCP  — needs roles/cloudasset.viewer; enable cloudasset.googleapis.com
gcloud asset search-all-iam-policies --scope=organizations/ORG_ID --format=json > gcp_iam.json

# Azure — needs the Reader role; combine the two listings into one file:
az role assignment list --all -o json > _ra.json
az role definition  list        -o json > _rd.json
#   then assemble:  {"roleAssignments": <_ra.json>, "roleDefinitions": <_rd.json>}
```

None of these commands mutate anything, and none of the output contains a secret
value — only the identity and permission topology AgentHound graphs.
