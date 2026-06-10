# ATT&CK Mapping

This document maps each AgentHound collector, edge, and inference rule to the
adversary behavior it models. It uses two frameworks:

- **[MITRE ATT&CK Enterprise](https://attack.mitre.org/)** — for the
  credential-access and valid-accounts behavior the graph exposes.
- **[MITRE ATLAS](https://atlas.mitre.org/)** — the adversarial-ML companion
  matrix to ATT&CK, for the AI-specific behavior the graph models. ATLAS spans
  **both halves** of the chain: the *coercion edges* (prompt injection, AI-agent
  tool invocation) where AgentHound's differentiator lives, and — through
  ATLAS's own credential-access, discovery, and exfiltration techniques — the
  credential and valid-account behavior the `local` and `mcp` collectors
  surface. Where a row maps to both frameworks, both IDs are given.

AgentHound is **analysis-only**. It maps where these techniques *could* land —
it never executes any of them. The mapping below is "what an operator looking
at this graph is reasoning about," not "what the tool does."

> Scope note: the table reflects edges the current collectors actually emit
> (`local`, `mcp`). Cloud-side enumeration (a dedicated AWS/IAM collector) is
> Phase 2 — `GRANTS_ACCESS` ships today only when a `mcp` inventory file
> declares resources explicitly.

---

## Collectors → techniques

### `local` — credential & agent discovery

`agenthound/collectors/local.py` walks the developer's machine for installed
assistants and the non-human identities their runtime can pick up from disk. It
records **presence and identifiers only — never credential values** (see
`THREAT-MODEL.md`). The behavior it surfaces:

| What it finds | Source paths | ATT&CK technique |
|---|---|---|
| AWS profile names | `~/.aws/credentials`, `~/.aws/config` | **T1552.001** Unsecured Credentials: Credentials In Files |
| GitHub CLI host/user | `~/.config/gh/hosts.yml` | **T1552.001** Credentials In Files |
| SSH public-key filenames | `~/.ssh/*.pub` | **T1552.004** Unsecured Credentials: Private Keys |
| kube context names | `~/.kube/config`, `$KUBECONFIG` | **T1552.001** Credentials In Files |
| npm registry hosts | `~/.npmrc` | **T1552.001** Credentials In Files |
| docker / gcloud / azure presence | provider config markers | **T1552.001** Credentials In Files |
| Installed AI assistants & MCP configs | per-OS app dirs | **T1518** Software Discovery |

**ATLAS counterpart.** The same behavior maps into the adversarial-ML matrix:
credential discovery on disk is **AML.T0055** Unsecured Credentials (ATLAS's
analogue to T1552), and enumerating the installed assistants and their tool
configs is **AML.T0007** Discover AI Artifacts. Presence and identifiers only —
the techniques describe the reconnaissance target, never the theft.

The collector models the *target* of credential theft, not the theft itself.
An over-broad set of NHIs reachable from one runtime is exactly the
`T1552.001 → T1078.004` pivot a graph is meant to make legible.

### `mcp` — documented-fleet inventory

`agenthound/collectors/mcp.py` parses a curated inventory file describing MCP
servers, the tools they expose, the NHIs they authenticate as, and (optionally)
the cloud/SaaS resources those NHIs reach. No live network connection.

| Relationship | ATT&CK | ATLAS |
|---|---|---|
| NHI → cloud/SaaS resource (`GRANTS_ACCESS`) | **T1078.004** Valid Accounts: Cloud Accounts | **AML.T0012** Valid Accounts |
| MCP server authenticates as NHI (`AUTHENTICATES_AS`) | **T1078** Valid Accounts | **AML.T0012** Valid Accounts |

---

## Edges → techniques

### Permission edges (`PermissionEdgeKind`)

Standard authority relationships — "this principal legitimately holds this
access." They are the substrate the coercion analysis runs over.

| Edge | Meaning | ATT&CK | ATLAS |
|---|---|---|---|
| `RUNS_AS` | Agent → AgentRuntime | — (structural) | — |
| `TRUSTS` | Developer → Agent (agent inherits dev authority) | **T1078** Valid Accounts | **AML.T0012** Valid Accounts |
| `EXPOSES` | MCPServer → MCPTool | — (structural) | — |
| `CALLS_TOOL` | Agent → MCPTool | **T1059** Command and Scripting Interpreter (sink case) | **AML.T0050** Command and Scripting Interpreter |
| `AUTHENTICATES_AS` | MCPServer/MCPTool → NHI | **T1078** Valid Accounts | **AML.T0012** Valid Accounts |
| `CAN_READ_CRED` | AgentRuntime → NHI (credential pickup) | **T1552.001** Credentials In Files | **AML.T0055** Unsecured Credentials |
| `GRANTS_ACCESS` | NHI → Resource | **T1078.004** Valid Accounts: Cloud | **AML.T0012** Valid Accounts |
| `CAN_ASSUME` | NHI → NHI (one identity can assume-role into another) | **T1548** Abuse Elevation Control Mechanism / **T1078.004** Valid Accounts: Cloud | **AML.T0012** Valid Accounts |

### Coercion edges (`CoercionEdgeKind`) — the differentiator

These model prompt-injection reachability: "untrusted input reaching this
agent's context can steer it." This is ATLAS territory.

| Edge | Meaning | ATLAS technique |
|---|---|---|
| `IS_INJECTION_SOURCE` | MCPTool → InjectableInput (a source tool pulls untrusted content in) | **AML.T0051** LLM Prompt Injection |
| `COERCES` | InjectableInput → Agent (the headline edge: untrusted input steers the agent) | **AML.T0051.000/.001** Direct / Indirect Prompt Injection |
| `ESCALATES_VIA` | Agent → MCPTool (agent can be steered into invoking a privileged sink with attacker-chosen args) | **AML.T0053** AI Agent Tool Invocation |

The `injection_class` property on each coercion edge refines the ATLAS mapping:

| `injection_class` | Source tag(s) | ATLAS |
|---|---|---|
| `direct` | `url_fetcher` | AML.T0051.000 Direct Prompt Injection |
| `indirect` | `mail_reader`, `file_reader` | AML.T0051.001 Indirect Prompt Injection |
| `stored` | `rag_retriever`, `query_runner` | AML.T0051.001 Indirect; staged by **AML.T0070** RAG Poisoning / **AML.T0066** Retrieval Content Crafting |
| `shadow` | (cross-server tool shadowing — roadmap) | AML.T0053 AI Agent Tool Invocation |

Where the injected content's aim is to defeat the model's guardrails rather than
merely steer it, the payload itself is **AML.T0054** LLM Jailbreak. Coercion
reachability — these edges — is the precondition; the jailbreak is what the
content does once it lands in context.

### Sink classifications → downstream effect

When a coerced agent invokes a sink tool, the *effect* maps back into Enterprise
ATT&CK by tool class, with the ATLAS counterpart where one exists:

| Sink tag | Effect | ATT&CK | ATLAS |
|---|---|---|---|
| `shell_executor` | Runs attacker-chosen commands | **T1059** Command and Scripting Interpreter | **AML.T0050** Command and Scripting Interpreter |
| `code_writer` | Writes code that will execute | **T1059** / **T1554** Compromise Host Software Binary | **AML.T0050** Command and Scripting Interpreter |
| `cloud_mutator` | Mutates cloud state | **T1098** Account Manipulation / **T1578** Modify Cloud Compute Infrastructure | — |
| `query_runner` | Reads possibly-poisoned data, writes it (both source and sink) | **T1213** Data from Information Repositories | **AML.T0036** Data from Information Repositories |

When the coerced action is to *move data out* — reading credentials or
repository data and sending it onward — that exfiltration is **AML.T0057** LLM
Data Leakage (inducing the agent to surface what it can reach) and
**AML.T0025** Exfiltration via Cyber Means (the data leaving over a normal
channel).

---

## The headline chain

The end-to-end path AgentHound is built to make queryable, with its technique
mapping at each hop:

```
InjectableInput ──COERCES──▶ Agent ──ESCALATES_VIA──▶ MCPTool(sink)
   AML.T0051            (TRUSTS: T1078)              AML.T0053 → T1059
                                                          │
                                              AUTHENTICATES_AS
                                                          ▼
                                                        NHI ──GRANTS_ACCESS──▶ Resource
                                                     T1078.004 / AML.T0012  (prod blast radius)
```

*"If untrusted content reaches this developer's AI assistant, what production
resources are reachable in N tool-call hops?"* — the Cypher that walks this
chain answers it.

---

## Roadmap: technique IDs in edge properties

A future change will embed the relevant ATT&CK and ATLAS technique ID(s)
directly in each edge's `properties.attck` / `properties.atlas` fields so the
mapping is queryable in BloodHound, not just documented here. Tracked against
the Phase 1 docs milestone.
