# Changelog

Notable changes to AgentHound. The format is loosely based on
[Keep a Changelog](https://keepachangelog.com/). AgentHound is in **alpha** —
the graph schema and CLI surface may change between releases.

## [0.2.2] - 2026-07-05

### Added

- **`agenthound gcp-iam`**: resolves *real* GCP permissions from an uploaded
  `gcloud asset search-all-iam-policies` export, the GCP analogue of `aws-iam`.
  Emits each binding member as an NHI, the resources their bindings grant
  (`GRANTS_ACCESS`), an **evidence-based** admin flag (`roles/owner`, GCP's own
  basic role, never a custom-role name), and **`CAN_ASSUME`** edges for
  service-account impersonation (`serviceAccountTokenCreator` / `serviceAccountUser`
  / `workloadIdentityUser` on a service account). Upload-only; **the tool never
  calls GCP**. Service accounts are keyed on their email, so impersonation
  targets join their grantee node. Ships with a
  `gcp_service_account_impersonation_escalation` Cypher query.
- **`agenthound azure-rbac`**: resolves *real* Azure permissions from an
  uploaded RBAC export (`az role assignment list` plus, recommended, `az role
  definition list`), the Azure analogue of `aws-iam`. Emits each principal as an
  NHI, the scopes their assignments grant (`GRANTS_ACCESS`), and an
  **evidence-based** admin flag (action `*` with no `notActions`, the built-in
  Owner role, never a role name; falls back to the fixed `Owner` name when role
  definitions are absent). Upload-only; **the tool never calls Azure**.

## [0.2.1] — 2026-06-13

Corrective release: ships the AWS collectors that the `v0.2.0` tag documented but
never actually contained — they had merged into a feature branch that was not
re-landed on `main`. No behavioural changes beyond first delivery of the code
below.

### Added

- **AWS assume-role topology** — `agenthound local` now reads the `role_arn` /
  `source_profile` wiring in `~/.aws/config` and emits each assumable role as its
  own NHI plus a new **`CAN_ASSUME`** edge (identity → role), exposing local
  privilege-escalation chains (e.g. `default → … → OrgAdmin`, possibly
  cross-account). Read from on-disk config only — **no network, no credential
  values**; *what* a role can do is left to the `aws-iam` collector. Ships with an
  `aws_role_assumption_escalation` Cypher query.
- **`agenthound aws-iam`** — resolves *real* AWS permissions from an uploaded
  `aws iam get-account-authorization-details` export: identities, the resources
  their policies grant (`GRANTS_ACCESS`), an **evidence-based** admin flag (the
  managed `AdministratorAccess` ARN or an `Allow *` on `*` — never the role's
  name), and `CAN_ASSUME` edges from role trust policies. Upload-only — **the
  tool never calls AWS**, so it stays network-free. Role NHIs are keyed on their
  ARN, so they join the assume-role topology `local` discovers.

## [0.2.0] — 2026-06-05

First tagged release. AgentHound is a [BloodHound OpenGraph](https://specterops.io/opengraph/)
collector that maps attack paths through AI-agent ecosystems
(Agent → MCP → NHI → resource) and adds **coercion edges** modelling
prompt-injection reachability.

### Added

- **`agenthound local`** — scan the current machine for installed AI assistants,
  their configured MCP servers, and the non-human identities their runtime can
  reach. Records presence and identifiers only — **never credential values**.
- **`agenthound offline`** — analyze a captured `.tar.gz` of an offline host
  instead of a live machine. Untrusted archives are extracted defensively (no
  path traversal or escaping links); produces the same graph as `local`.
- **`agenthound mcp`** — model a documented MCP-server fleet from a YAML/JSON
  inventory without touching each developer's machine.
- **Unknown-tool access mapping** — for custom or unrecognized MCP servers,
  AgentHound infers which credential providers a server can reach (AWS, GitHub,
  GCP, Slack, Stripe, …) from its declared environment-variable **names** —
  never their values — and emits the backing NHI and credential-read edges,
  scope permitting. Unclassified tools are treated as injection sources.
- **`agenthound infer`** — coercion inference pass emitting `COERCES` edges from
  injectable input sources through agents into the tools and identities they
  reach.
- **`agenthound emit`** — produce a BloodHound OpenGraph JSON payload for
  ingestion into BloodHound CE.
- **`agenthound verify-audit`** — re-walk an audit log's HMAC hash-chain and
  report the first edited, deleted, or reordered line.
- **Engagement scope** (`--scope`) — deny-wins provider/path lists, an
  authorization expiry that hard-fails when past, and time windows. A denied
  provider yields no node and no edge.
- **Tamper-evident audit log** — append-only, HMAC-SHA256 signed, hash-chained
  to a fixed genesis; no unsigned mode.
- **Documentation** — MITRE ATT&CK + ATLAS mapping, threat model, and an
  authorized-use posture (`docs/`).
- **Signed releases** — wheel and sdist are Sigstore-signed in CI; see
  [docs/RELEASES.md](docs/RELEASES.md) to verify a download.

### Security

- `verify-audit` now rejects log lines that carry fields outside the signed set,
  closing an unsigned-field-injection gap in chain verification.
- Malformed collection files and partial overlay records fail soft (a clear
  error or a skipped record) instead of crashing the CLI.

[0.2.2]: https://github.com/Yorji-Porji/AgentHound/releases/tag/v0.2.2
[0.2.1]: https://github.com/Yorji-Porji/AgentHound/releases/tag/v0.2.1
[0.2.0]: https://github.com/Yorji-Porji/AgentHound/releases/tag/v0.2.0
