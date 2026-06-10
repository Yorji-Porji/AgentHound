# Changelog

Notable changes to AgentHound. The format is loosely based on
[Keep a Changelog](https://keepachangelog.com/). AgentHound is in **alpha** —
the graph schema and CLI surface may change between releases.

## [Unreleased]

### Added

- **AWS assume-role topology** — `agenthound local` now reads the `role_arn` /
  `source_profile` wiring in `~/.aws/config` and emits each assumable role as its
  own NHI plus a new **`CAN_ASSUME`** edge (identity → role), exposing local
  privilege-escalation chains (e.g. `default → … → OrgAdmin`, possibly
  cross-account). Read from on-disk config only — **no network, no credential
  values**; *what* a role can do is left to the `aws-iam` collector. Ships with an
  `aws_role_assumption_escalation` Cypher query.

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

[0.2.0]: https://github.com/Yorji-Porji/AgentHound/releases/tag/v0.2.0
