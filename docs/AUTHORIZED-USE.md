# Authorized Use

AgentHound is **defensive, analysis-only security tooling**. It maps attack
paths through AI-agent ecosystems so that defenders, red teams, and the
engineers who own these systems can see — and close — the blast radius of a
coerced AI assistant. It does not exploit anything.

This document states the intended use plainly, in the same spirit as the
authorized-use postures published by SpecterOps (BloodHound) and Praetorian.
Read it before you run the tool against anything you do not personally own.

---

## What AgentHound is for

- **Authorized engagements.** Red-team / purple-team assessments and pentests
  where you have **written authorization** to enumerate the target's systems.
- **Your own infrastructure.** Auditing the AI-agent and MCP footprint of
  machines, fleets, and cloud accounts you own or operate.
- **Defensive baselining.** Inventorying which assistants hold which
  credentials, and which untrusted-input sources can reach which sink tools, so
  you can reduce that surface.
- **Research & education** against a lab you own — a deliberately-vulnerable
  agent ecosystem you stand up yourself is the only acceptable demo surface.

## What AgentHound is *not* for

- **No exploitation.** AgentHound surfaces candidate paths as data. A human
  operator runs any actual test, by hand, under authorization. The tool fires
  nothing.
- **No autonomous action.** There is no execution layer. The forthcoming
  dual-agent pipeline (Phase 3) *proposes* findings and *generates* detections;
  a human reviews before anything leaves the tool. This boundary is enforced in
  code and in prompt, and it is non-negotiable.
- **No unauthorized targets.** Never point AgentHound at systems, accounts, or
  data you do not own or lack written authorization to assess.
- **Not a secret exfiltration tool.** By design it reads credential *presence
  and identifiers* — never values. See "Built-in guardrails" below.

---

## Built-in guardrails

AgentHound enforces engagement discipline in the tool itself, not just in
policy:

### Engagement scope (`agenthound/scope.py`)

A run can be gated by a scope file (`--scope scope.yaml`). The scope declares:

- `engagement` — a human-readable engagement name, stamped into the audit log.
- `authorized_until` — an RFC 3339 expiry. **If it is in the past, the tool
  refuses to run at all.**
- `providers_allowed` / `providers_denied` — provider allow/deny lists, with
  **deny winning** on conflict. A denied provider produces **no node and no
  edge** — not a redacted one. The data is never collected.
- `paths_denied` — path globs the collector will not read.
- `time_windows` — day/time/timezone windows; a run outside the window is
  refused and audited.

Allowed and out-of-scope checks produce signed `ALLOW` and `SKIPPED` audit
entries respectively; collection is never silent.

### Tamper-evident audit log (`agenthound/audit.py`)

Every scope decision is written to an append-only JSONL audit log. Each line is
**HMAC-SHA256 signed** with a per-engagement key (`AGENTHOUND_AUDIT_KEY`) and
**hash-chained** to the line before it, anchored at a fixed genesis hash. An
edit, insertion, interior deletion, or reordering breaks the chain.

- There is **no unsigned mode** — the log refuses to write without a key.
- `agenthound va <file>` (or `agenthound verify-audit <file>`) re-walks the chain and reports the first
  tampered line.
- A malformed, altered, wrong-key, or internally broken log makes a resuming
  run **refuse**, not silently append from an unverified hash.

The chain authenticates the sequence that is present. It cannot detect valid
suffix truncation — including truncation to an empty log — unless the verifier
also has an independently retained terminal hash or receipt. AgentHound does
not create that external anchor in this release.

This gives an engagement a defensible, court-legible record of exactly what the
tool was permitted to do and when — chain-of-custody for automated recon.

### Never read or store credential values

The local collector's parsers (`_aws_profile_names`, `_gh_hosts`,
`_ssh_pubkeys`, `_kube_contexts`, `_npmrc_registries`) return only identifiers
and metadata — profile names, secret-free registry endpoints, hostnames,
public-key *filenames*, and context names. npm URL userinfo, query strings, and
fragments are stripped before an identifier is emitted.
The test `test_no_credential_values_emitted` enforces this and must never
regress. AgentHound maps the graph; it does not collect the secrets.

---

## Your responsibility

Authorization is yours to hold. AgentHound's guardrails make *good-faith*
engagement discipline easy and *tampering* evident — they are not a substitute
for a signed scope of work. Running this tool against systems you are not
authorized to assess may be illegal in your jurisdiction. Don't.

If you find a vulnerability in AgentHound itself, please report it responsibly
via a private [GitHub security advisory](https://github.com/Yorji-Porji/AgentHound/security/advisories/new)
rather than a public issue.
