# AgentHound

Graph-based attack path mapping for AI agents, MCP servers, and the non-human identities they reach.

AgentHound is a [BloodHound OpenGraph](https://specterops.io/opengraph/) collector for AI agent ecosystems. It models AI assistants (Cursor, Claude Code, Claude Desktop, VS Code, Zed) alongside the MCP servers they consume, the non-human identities (NHIs) those servers authenticate as, and the cloud and SaaS resources reachable through the resulting chain.

Where traditional identity graphs treat edges as *permissions an identity holds*, AgentHound adds a second edge class: **coercion edges** — the relationship "this identity can be made to do X by untrusted input reaching its context window." Prompt injection becomes a first-class graph primitive, and reachability queries can answer the previously unanswerable question: *"if untrusted content reaches this developer's AI assistant, what's the production blast radius in N tool-call hops?"*

## Why

Non-human identities are now the dominant cloud breach vector and agentic AI is accelerating NHI proliferation past what existing IAM tooling can govern. Developer-side AI assistants routinely hold the union of every credential a developer has — GitHub PATs, AWS profiles, kube configs, npm tokens, MCP server OAuth tokens — and most organizations have no visibility into the resulting blast radius.

The existing MCP security tool ecosystem (Snyk agent-scan, Invariant mcp-scan, Cisco mcp-scanner, AQtive Guard) scans individual servers in isolation. None of them graph the full agent → MCP → NHI → resource chain. AgentHound is the open-source attack path tool for that chain.

## What it does

- **`agenthound local`** — scans the current machine for installed AI assistants, their configured MCP servers, and reachable credentials. Produces an inventory of agent nodes, runtime nodes, and the credentials each agent's runtime can pick up from environment variables, profile files, and config dirs.
- **`agenthound offline`** — analyze an *offline host* (one you're not on) from a captured `.tar.gz` of its config/credential paths, rather than scanning a live machine. "Offline" refers to the target, not the tool — AgentHound is network-free either way; this is the "capture cheap on the engagement host, analyze in a clean room" workflow. Produces the same graph as `local`; untrusted archives are extracted defensively (no path traversal or escaping links).
- **`agenthound mcp`** — parses a curated MCP server inventory file (YAML or JSON) and emits its nodes and edges. Useful for modeling documented fleets without touching each developer's machine.
- **`agenthound infer`** — runs the coercion inference pass over collected nodes, emitting `COERCES` edges from injectable input sources through agents into the tools and identities they can reach.
- **`agenthound emit`** — produces a BloodHound OpenGraph JSON payload ready for ingestion into BloodHound CE.

## Node and edge taxonomy

### Nodes
| Kind | Description |
|---|---|
| `Agent` | An AI assistant instance (Cursor, Claude Code, Claude Desktop, VS Code, Zed) |
| `AgentRuntime` | Where the agent runs (workstation, Codespace, CI runner, server) |
| `MCPServer` | A configured MCP server, local or remote |
| `MCPTool` | An individual tool function exposed by an MCP server |
| `NHI` | A non-human identity — OAuth app, service account, API key, certificate |
| `Resource` | A reachable resource (S3 bucket, Salesforce object, repo, database) |
| `InjectableInput` | A source of untrusted content that can reach an agent's context |
| `Developer` | A human principal whose credentials the agent runtime can access |

### Permission edges (standard authority)
| Edge | From → To |
|---|---|
| `RUNS_AS` | Agent → AgentRuntime |
| `TRUSTS` | Developer → Agent |
| `CALLS_TOOL` | Agent → MCPTool |
| `EXPOSES` | MCPServer → MCPTool |
| `AUTHENTICATES_AS` | MCPServer/MCPTool → NHI |
| `GRANTS_ACCESS` | NHI → Resource |
| `CAN_READ_CRED` | AgentRuntime → NHI |

### Coercion edges (novel)
| Edge | From → To |
|---|---|
| `COERCES` | InjectableInput → Agent |
| `IS_INJECTION_SOURCE` | MCPTool → InjectableInput |
| `ESCALATES_VIA` | Agent → MCPTool |

## Headline query

```cypher
MATCH path = (i:InjectableInput)-[:Coerces]->(a:Agent)
       -[:CallsTool*1..4]->(t:MCPTool)
       -[:AuthenticatesAs]->(n:Nhi)
       -[:GrantsAccess]->(r:Resource)
WHERE r.tier = 'production'
RETURN path, length(path) AS hops
ORDER BY hops ASC
LIMIT 25
```

In English: *for any external content source that can reach an agent, walk up to four tool-call hops to find every production resource reachable, shortest path first.*

> **Note on kind names.** The taxonomy tables above use the internal enum names
> (`COERCES`, `CALLS_TOOL`, `NHI`, …). On emission these are sanitized to the
> PascalCase form BloodHound expects, so **Cypher must use the emitted names**:
> `Coerces`, `CallsTool`, `AuthenticatesAs`, `GrantsAccess`, `CanReadCred`,
> `RunsAs`, `EscalatesVia`, and the `NHI` node kind becomes `Nhi`.

See `cypher/queries.yaml` for the full query library (already in emitted form).

## Quick start

```bash
pip install -e .

# Scan the current machine. Without -o, JSON goes to stdout.
agenthound local -o local.json

# Analyze a curated MCP server inventory file (YAML or JSON).
agenthound mcp -i examples/mcp_inventory.yaml -o mcp.json

# Run coercion inference over collected data.
agenthound infer local.json mcp.json -o graph.json

# Emit a BloodHound OpenGraph payload.
agenthound emit graph.json -o bloodhound.json
```

Ingest `bloodhound.json` into BloodHound CE via Settings → Manage data → Upload, or the `/api/v2/graphs/ingest` endpoint.

### End-to-end demo

```bash
bash examples/run_demo.sh
```

Builds a synthetic developer home, runs the full pipeline, and walks the resulting graph to print the production blast-radius paths.

## Extending the MCP server registry

The bundled registry at `agenthound/data/known_mcp_servers.yaml` covers ~50 of the most common MCP servers. To add servers, either edit that file directly or supply an overlay:

```bash
agenthound local --known-servers ./my-org-mcp-servers.yaml -o local.json
```

The overlay file uses the same schema as the bundled registry. Entries in the overlay take precedence on key collision.

## What's not yet implemented

- **Live MCP introspection over the wire.** Currently classifies from the configured server name against the registry. The next milestone connects via stdio/SSE to enumerate the actual tool surface live, the way Snyk agent-scan does.
- **Cloud-side NHI permission expansion.** No AWS IAM, GCP, or Azure collector yet — these will fan `NHI → GRANTS_ACCESS → Resource` edges out into real cloud topology.
- **Path scoring.** Every path currently treated as binary. Reachability scoring (production tier, mutable-tag refs, indirect-injection sources) is the next analytic layer.

Progress is tracked in [GitHub Issues](https://github.com/Yorji-Porji/AgentHound/issues).

## Documentation

- [docs/ATTACK-MAPPING.md](docs/ATTACK-MAPPING.md) — every collector and edge mapped to MITRE ATT&CK and ATLAS techniques.
- [docs/AUTHORIZED-USE.md](docs/AUTHORIZED-USE.md) — defensive, analysis-only posture and the built-in engagement guardrails.
- [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) — trust boundaries, abuse cases, and what the tamper-evident audit log does and does not guarantee.

## Prior art

- [BloodHound](https://github.com/SpecterOps/BloodHound) and OpenGraph by SpecterOps — the graph framework AgentHound is a collector for
- [GitHound](https://github.com/SpecterOps/GitHound) — SpecterOps' official OpenGraph collector for GitHub
- [PrivHound](https://github.com/dazzyddos/PrivHound) — community OpenGraph collector for Windows local privesc, a good example of the collector pattern
- [Snyk agent-scan](https://github.com/snyk/agent-scan) — closest analogue in the MCP space; auto-discovers agent configs and scans them, but is a static analyzer rather than a graph
- [Invariant mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) — MCP tool-description scanner for tool poisoning and rug pulls
- OWASP MCP Top 10 (beta, 2026) — the risk taxonomy AgentHound's coercion edges map against

## License

Apache 2.0. See `LICENSE`.

## Status

Alpha. Schemas and CLI surface will change.
