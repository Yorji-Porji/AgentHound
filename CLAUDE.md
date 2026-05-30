# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

AgentHound is a BloodHound OpenGraph collector for AI agent ecosystems. It maps the chain
`AI assistant → MCP server → MCP tool → non-human identity (NHI) → cloud/SaaS resource`, then
overlays a second, novel edge class — **coercion edges** — that model prompt-injection reachability
("untrusted input reaching an agent's context can make it do X"). The headline output answers:
*if untrusted content reaches a developer's AI assistant, what production resources are reachable in
N tool-call hops?*

## Commands

```bash
pip install -e ".[dev]"      # install with dev tooling (pytest, ruff, mypy)

pytest                       # run the whole suite
pytest tests/test_pipeline.py::test_pipeline_finds_production_blast_radius   # single test
pytest -k coercion           # run tests matching a keyword

ruff check .                 # lint (config in pyproject.toml: line-length 100, py311 target)
ruff check --fix .           # autofix
mypy agenthound              # type-check

bash examples/run_demo.sh    # full end-to-end pipeline against a synthetic home dir
```

Python 3.11–3.12 only (`requires-python = ">=3.11,<3.13"`). The console entry point `agenthound`
maps to `agenthound.cli:main`.

## The four-stage pipeline

The CLI is four subcommands that chain via intermediate JSON files. Each writes to stdout by default;
`-o FILE` writes a file instead. **All four accept `--no-branding`** to strip the `AgentHound` source
kind and `AH-` objectid prefix for cleaner OpenGraph merges.

```
local ─┐
       ├─> infer ─> emit ─> bloodhound.json (ingest into BloodHound CE)
mcp  ──┘
```

1. **`local`** (`collectors/local.py`) — scans the current machine for installed AI assistants
   (Cursor, Claude Desktop, Claude Code, VS Code, Zed), their `mcpServers` configs, and reachable
   credentials. Emits Agent/AgentRuntime/MCPServer/MCPTool/NHI/Developer nodes + permission edges.
2. **`mcp`** (`collectors/mcp.py`) — parses a curated MCP inventory file (YAML/JSON, see
   `examples/mcp_inventory.yaml`) describing a documented fleet. No live network connection.
3. **`infer`** (`inference/coercion.py`) — takes one or more collection-result files, merges them,
   and derives the coercion edges. **This is the analytic core.**
4. **`emit`** (`schema/opengraph.py`) — converts to the BloodHound OpenGraph wire format.

`infer`/`emit` read both the OpenGraph format (`{"graph": {"nodes", "edges"}}`) and the legacy
intermediate shape; see `_result_from_json` in `cli.py`.

## Architecture invariants — read before editing

- **Never read or store credential values.** Credential parsers in `local.py`
  (`_aws_profile_names`, `_gh_hosts`, `_ssh_pubkeys`, `_kube_contexts`, `_npmrc_registries`) return
  only identifiers/metadata — profile names, hostnames, key *filenames*, context names. The test
  `test_no_credential_values_emitted` enforces this; don't regress it.
- **Fail soft.** Every file/JSON/YAML read in a collector is wrapped; a malformed config produces a
  `result.warnings` entry, never a crash.
- **Deterministic node identity.** `Node.objectid` is `AH-{kind}-{sha1(kind:stable_id)[:16]}`
  (`schema/nodes.py`). Two collectors observing the same logical entity must produce the same
  `stable_id` so the nodes join into one. This is why MCPServer identity is name-only (`mcp:{name}`)
  — a local config scan and a documented inventory of the same server collapse to one node. Use the
  `*_node()` factory helpers rather than constructing `Node` directly, to keep `stable_id` schemes
  consistent.
- **Node/edge merge happens in `build_payload`** (`opengraph.py`): nodes dedup by objectid with
  property-merge; edges dedup by `(kind, source, target)` keeping the *first*; dangling edges
  (endpoint not in the node set) are dropped with a warning.

## Two edge classes

`schema/edges.py` defines `PermissionEdgeKind` (standard authority: `RUNS_AS`, `CALLS_TOOL`,
`EXPOSES`, `AUTHENTICATES_AS`, `GRANTS_ACCESS`, `CAN_READ_CRED`, …) and `CoercionEdgeKind`
(`COERCES`, `IS_INJECTION_SOURCE`, `ESCALATES_VIA`, `SHADOWED_BY`, …). `Edge.is_coercion`
discriminates them. Keep the two enums separate — queries and emission depend on the distinction.

## Coercion inference logic

`CoercionInferencer.infer` (`inference/coercion.py`) does three things, in order:

1. **Propagate `CALLS_TOOL` across server boundaries** — an agent observed calling *any* tool of
   server S is assumed to reach *every* tool S exposes (the MCP client has the whole tool list once
   connected). Also fans each tool's `AUTHENTICATES_AS` down from its server so queries can hop
   `MCPTool → NHI` directly.
2. **Classify each MCPTool** by its `classification` tags into source / sink / both. Source tags
   (`url_fetcher`, `rag_retriever`, `mail_reader`, `file_reader`) get an `InjectableInput` node + a
   `COERCES` edge into every calling agent. Sink tags (`shell_executor`, `code_writer`,
   `cloud_mutator`) get an `ESCALATES_VIA` edge. `query_runner` is both. **`unclassified` tools are
   treated pessimistically as both source and sink.**
3. Each coercion edge carries an `injection_class` (`direct`/`indirect`/`stored`/`shadow`) recorded
   per source tag in `TAG_TO_INJECTION_CLASS`.

Tool classification comes from `agenthound/data/known_mcp_servers.yaml` (~50 servers). Unknown
servers are tagged `unclassified` with a warning. Extend the file, or overlay at runtime with
`agenthound local --known-servers FILE` (overlay wins on key collision). The classification taxonomy
is documented in the YAML header and mirrored in `coercion.py`'s `SOURCE_TAGS`/`SINK_TAGS`/`BOTH_TAGS`.

## OpenGraph emission gotcha

`opengraph.py` **sanitizes edge/node kinds to PascalCase** on emit: `GRANTS_ACCESS` → `GrantsAccess`,
`COERCES` → `Coerces`. So graph-walking code that reads the *emitted* JSON must match the PascalCase
form (see `tests/test_pipeline.py`, which checks `ek == "GrantsAccess"`). Note `examples/run_demo.sh`
matches the raw `"GRANTS_ACCESS"` string — these are not interchangeable. `_flatten_properties` drops
nested dicts and heterogeneous arrays (OpenGraph only accepts primitive/homogeneous-array properties);
collision with a reserved BloodHound edge kind emits a `warnings.warn`.

## Reference files

- `cypher/queries.yaml` — the query library, including the headline production-blast-radius query.
- `schemas/node.json` — JSON schema for the node wire format.
- `Plan.md`, `ROADMAP.md`, `testplans.md` — design intent and forward plan (v0.2 live MCP
  introspection, v0.3 AWS IAM/OIDC collector, v0.4 reachability scoring). Not yet implemented:
  live MCP introspection, cloud-side NHI expansion, path scoring.

Note: `pyproject.toml` version is `0.2.0` and `opengraph.SCHEMA_VERSION` is `0.2.0`, but
`agenthound/__init__.py` `__version__` is `0.1.0` — keep these in mind if touching version strings.
