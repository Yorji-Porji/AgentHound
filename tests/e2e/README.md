# End-to-end ingest check (P1-W1-OG-26)

The automated suite validates emitted payloads against the vendored BloodHound
schemas (`schemas/node.json`, `schemas/edge.json`). The final Week-1 gate —
**clean ingest into a live BloodHound CE** — is manual, documented here.

## Prerequisites

- BloodHound CE running (Docker compose or a hosted instance).
- AgentHound installed: `pip install -e ".[dev]"`.
- A target `$HOME` to scan (your lab's fake production home, or `--home DIR`).

## Procedure

Run the full pipeline to produce an OpenGraph payload:

```bash
# 1. Scan the target machine / fake-prod home.
agenthound local --home /path/to/fake-prod-home --hostname prod-mimic -o local.json

# 2. (Optional) Add a curated MCP inventory describing the documented fleet.
agenthound mcp -i examples/mcp_inventory.yaml -o mcp.json

# 3. Merge + derive coercion edges.
agenthound infer local.json mcp.json -o merged.json

# 4. Emit the BloodHound OpenGraph payload.
agenthound emit merged.json -o bloodhound.json
```

Then ingest `bloodhound.json` into BloodHound CE:

- **UI:** Settings → Administration → Manage data → Upload Files → select
  `bloodhound.json`.
- **API:** `POST /api/v2/graphs/ingest` with the JSON body.

## Pass criteria

1. Upload reports **0 schema / ingest errors**.
2. The headline coercion edge is queryable. In Explore → Cypher:

   ```cypher
   MATCH p=(:InjectableInput)-[:Coerces]->(:Agent) RETURN p LIMIT 25
   ```

   Note kinds are PascalCase in BloodHound (`Coerces`, `CallsTool`,
   `GrantsAccess`, `AuthenticatesAs`) — the exporter sanitizes the internal
   `COERCES` / `CALLS_TOOL` enum values on emit.

3. The production blast-radius query returns at least one path (see
   `cypher/queries.yaml` → `production_blast_radius_from_injection`, adjusting
   edge kinds to their PascalCase form).

## Notes

- `--no-branding` strips the `AH-` id prefix and the `AgentHound` source kind /
  `metadata.tool`, for merging into an existing BloodHound graph without the
  AgentHound namespace. Default keeps branding on.
- If a node fails to ingest, validate locally first:
  `python -c "import json,jsonschema; ..."` against `schemas/node.json` /
  `schemas/edge.json` — the same gate CI enforces.
