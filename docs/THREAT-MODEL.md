# Threat Model

This is the threat model **of AgentHound itself** — what data it touches, where
its trust boundaries are, how it could be misused or go wrong, and what in the
design mitigates each risk. It is deliberately conservative: a recon tool that
reads a developer's most sensitive config directories has to be trustworthy
about what it does with what it sees.

For *what AgentHound models about its targets* (prompt injection, NHI blast
radius), see `ATTACK-MAPPING.md`. For the authorized-use posture, see
`AUTHORIZED-USE.md`.

---

## 1. Assets

What AgentHound handles that an adversary would want:

| Asset | Sensitivity | Where it lives |
|---|---|---|
| Credential **identifiers** (profile names, hostnames, key filenames, kube contexts) | Medium — reveals what access exists, not the access itself | In-memory during a run; serialized into output JSON |
| The **graph** (who can reach what) | Medium–High — a map of the blast radius is a target-selection aid | Output JSON (`local.json`, `bloodhound.json`, …) |
| The **audit log** + its HMAC key | High — the key authenticates every log line | `audit.jsonl`; key in `AGENTHOUND_AUDIT_KEY` env var |
| Credential **values** | Critical | **Never read. Never stored.** (see §4) |

## 2. Trust boundaries

```
   ┌─────────────────────────── operator's machine ───────────────────────────┐
   │                                                                            │
   │   filesystem (configs, creds) ──read──▶ AgentHound ──write──▶ output JSON  │
   │        ▲ untrusted content                  │                              │
   │        in scanned configs                   ├──append──▶ audit.jsonl       │
   │                                             │                              │
   │   AGENTHOUND_AUDIT_KEY (env) ───────────────┘                              │
   └────────────────────────────────────────────────────────────────────────┘
                                        │
                          output JSON crosses here ──▶ BloodHound CE (ingest)
```

The key boundaries:

- **Scanned files are untrusted input.** A malformed or hostile config must not
  crash the tool or cause it to misbehave.
- **The output JSON leaves the host.** Whatever ends up in it is exportable —
  so it must contain identifiers, never secrets.
- **The audit key is the root of trust** for the tamper-evidence property. If
  it leaks, an attacker can forge a clean-looking log.

## 3. Adversaries & abuse cases

| Adversary | Goal | Relevant mitigation |
|---|---|---|
| **Malicious operator** | Use AgentHound to recon systems they aren't authorized for | Scope file + expiry hard-fail; tamper-evident audit log makes out-of-scope activity evident (§5) |
| **Operator covering tracks** | Edit/delete audit entries after the fact | HMAC + hash-chain detects edits, insertion, interior deletion, and reorder; suffix truncation requires an external anchor (§5) |
| **Hostile config on a scanned host** | Crash the collector, or smuggle a secret into output | Fail-soft parsing (§4); identifiers-only parsers (§4) |
| **Output-stealing attacker** | Read the graph JSON to pick targets | Out of tool scope — operators must protect output like any recon artifact; `.gitignore` keeps it out of the repo |
| **Key thief** | Forge audit-log lines | Key handling is the operator's responsibility (§6); never written to disk by the tool |

## 4. Design mitigations

### Never read or store credential values

The architectural invariant. Every credential parser in `collectors/local.py`
returns only identifiers and metadata — AWS profile *names*, gh *hostnames*,
SSH public-key *filenames*, kube *context names*, npm *registry endpoints* with
userinfo/query/fragment removed. Private keys, tokens, and secrets are never
opened for their contents. Enforced by
`test_no_credential_values_emitted`; a regression fails CI.

### Fail soft on untrusted input

Every file open, JSON parse, and YAML parse in a collector is wrapped. A
missing, truncated, or malicious config produces a `result.warnings` entry and
the run continues — it never crashes and never partially-writes a corrupt graph.

### Property flattening on emit

`schema/opengraph.py` flattens node/edge properties to primitives and
homogeneous arrays and drops anything else. This bounds what an attacker-shaped
config can push into the emitted JSON — no nested attacker-controlled objects
ride along into BloodHound.

### Deny-wins scope, deny means *absent*

A denied provider or path yields **no node and no edge**, not a redacted
placeholder. Out-of-scope data is never collected in the first place, so it
cannot leak through the output.

## 5. The audit log's guarantee (and its limit)

**Guarantee.** Given the per-engagement key, `va` (or `verify-audit`) authenticates every
line in the sequence presented to it. It detects edited or inserted entries,
reordered entries, and removal of an interior entry, and reports the first bad
index. A resuming writer performs the same full verification before appending.

**Limit.** A chain whose valid suffix was removed is still a valid chain from
genesis. This includes truncation to an empty log. Detecting suffix truncation
requires comparing against an independently retained terminal hash or external
receipt, which AgentHound does not create in this release. The log is also
tamper-*evident*, not tamper-*proof*: an attacker who holds the key can forge a
new valid chain. Protect the key accordingly (§6).

## 6. Operator responsibilities (out of the tool's control)

- **Protect `AGENTHOUND_AUDIT_KEY`.** It is the root of the tamper-evidence
  property. Keep it out of shell history and CI logs; rotate per engagement.
- **Protect the output JSON.** It is a blast-radius map. Treat it like any
  recon deliverable — it is already `.gitignore`d so it won't land in the repo.
- **Hold real authorization.** The scope file enforces discipline; it does not
  grant permission. See `AUTHORIZED-USE.md`.

## 7. Non-goals

- AgentHound does **not** defend the host it runs on.
- It does **not** encrypt its output at rest — that's the operator's pipeline.
- It does **not** exploit, execute, or act autonomously — by design, and this
  holds across every planned phase of the project.
