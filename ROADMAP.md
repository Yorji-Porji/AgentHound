# Roadmap

AgentHound's v0 is a complete vertical slice — collectors, schema, inference,
emission. The next milestones extend coverage and analytic depth.

## v0.2 — Live MCP introspection

Replace the static known-server registry with a live MCP client that connects
over stdio and SSE, lists tools, and inspects argument schemas. Tool
classification should be derived from the schema (parameter names, types,
descriptions) rather than a hand-curated dict. Tools that take URL-shaped
parameters get auto-tagged `url_fetcher`; tools whose descriptions reference
"file path" or "directory" get `file_reader`; etc.

Risk: live introspection requires auth for any non-trivial MCP server, and
some servers gate `tools/list` behind capabilities. The collector needs a
credential-handling story that does not regress the "never read secret values"
posture.

## v0.3 — AWS IAM collector with OIDC bridge

The single most valuable cross-domain edge in modern cloud-native attack paths
is `GitHubWorkflow → CAN_ASSUME_VIA_OIDC → AWSRole`. SpecterOps has explicitly
called out AWS IAM as a missing OpenGraph collector. Build it. Parse trust
policies, encode `sub` claim conditions as edge metadata, resolve them against
GitHub repos and environments collected by GitHound or AgentHound's local
collector when the dev's GitHub auth is reachable.

## v0.4 — Reachability scoring

Today every path is treated as binary. Real risk weighting needs:

- Approval-required workflows score lower than auto-run
- Pinned-SHA action references score lower than mutable-tag
- Production-tagged resources weight higher than dev
- Indirect-injection paths score higher than direct (they bypass user awareness)
- Sink-tool capability (cloud_mutator > code_writer > query_runner)

Output: a 0–100 risk score on every path that the OpenGraph metadata can
expose to the BloodHound UI's filtering.

## v0.5 — Agent runtime forensics

Beyond config-file scanning, parse:

- Agent conversation logs for inadvertent credential disclosure
- MCP server runtime logs for tool invocation patterns
- Browser-resident agents (Chrome extensions, Claude in Chrome) for
  cross-origin reachability

## v1.0 — Cross-domain stitching

Stitch the AgentHound subgraph into GitHound, AzureHound, AWSHound, etc. via
shared identity nodes. A developer's GitHub identity collected by GitHound is
the same `Developer` node AgentHound emits — the `MapsTo` edge pattern from
BloodHound CE links them. This is when the tool stops being "the AgentHound
graph" and becomes "a layer on the BloodHound graph."

## How to contribute

The two highest-leverage open issues will be:

1. **Extend `KNOWN_MCP_SERVERS`** with classifications for every MCP server
   from the official Anthropic registry and the most-installed community
   servers. PRs welcome.
2. **Replace the static registry with live introspection** (v0.2 above). This
   is the largest single piece of work and the one that unlocks the rest.
