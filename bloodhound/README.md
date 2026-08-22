# BloodHound-side setup

Assets you apply to a BloodHound CE instance once, so AgentHound's subgraph reads
properly in the UI. Nothing here is consumed by the `agenthound` CLI.

## Custom node icons

`custom-nodes.json` gives each AgentHound node kind a Font Awesome icon and colour.
Without it, BloodHound renders every custom kind as a `(?)` placeholder, which makes a
coercion path hard to read at a glance.

| Kind | Icon | Colour | Why |
|---|---|---|---|
| `Developer` | `user` | slate | The human principal at the start of the chain |
| `Agent` | `robot` | violet | The AI assistant, the pivot point of the whole graph |
| `AgentRuntime` | `laptop` | blue | Where the agent runs and picks up credentials |
| `MCPServer` | `server` | sky | A configured MCP server |
| `MCPTool` | `wrench` | cyan | An individual tool function |
| `Nhi` | `key` | amber | A non-human identity, the credential layer |
| `Resource` | `database` | emerald | The reachable resource, the target |
| `InjectableInput` | `syringe` | red | Untrusted content, the coercion source |

Red is reserved for `InjectableInput` so the untrusted-input entry point stands out
against the permission-edge chain, matching the coercion styling in the README diagram.

### Applying it

**AgentHound does not upload this file.** The tool never makes network calls (security
invariant 2 in `CLAUDE.md`), and icons cannot travel inside an ingest payload, so this is
a step you run against your own instance. It is the mirror of how the cloud collectors
work: there you generate an export and hand it to AgentHound, here AgentHound hands you a
file and you apply it.

Get an API token from **Settings -> Administration -> My Profile -> API Tokens**, then:

```bash
curl -X POST "$BLOODHOUND_URL/api/v2/custom-nodes" \
  -H "Authorization: Bearer $BLOODHOUND_TOKEN" \
  -H "Content-Type: application/json" \
  --data @bloodhound/custom-nodes.json
```

PowerShell:

```powershell
Invoke-RestMethod -Method Post -Uri "$env:BLOODHOUND_URL/api/v2/custom-nodes" `
  -Headers @{ Authorization = "Bearer $env:BLOODHOUND_TOKEN" } `
  -ContentType "application/json" `
  -InFile bloodhound/custom-nodes.json
```

Use `PUT` instead of `POST` to update definitions that already exist. Re-ingest is not
required: icons are display configuration, so the change shows up on the next render.

### Editing it

Keys must be the **emitted** kind names, not the internal enum values.
`schema/opengraph.py` sanitizes kinds on the way out, so `NHI` becomes `Nhi`. A key that
does not match binds to nothing and silently leaves a `(?)` in the UI. This is the same
trap that made the Cypher query library render nothing before v0.2.2.

Icon names come from the free, **solid** Font Awesome set and take no `fa-` prefix.
Colours are `#RGB` or `#RRGGBB`.

`tests/test_custom_icons.py` fails the build if a node kind gains or loses an icon, if a
key is written in the internal form, or if an entry is malformed. The visual check that
the icons look right in a live instance stays manual, see `tests/e2e/README.md`.
