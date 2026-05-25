#!/usr/bin/env bash
# Demonstrates the full AgentHound pipeline against a synthetic developer machine.
# Run from the repo root: bash examples/run_demo.sh

set -euo pipefail

WORK=$(mktemp -d)
trap "rm -rf $WORK" EXIT

echo "==> Building a synthetic developer home at $WORK"
mkdir -p "$WORK/.config/Claude" "$WORK/.aws" "$WORK/.ssh" "$WORK/.kube" "$WORK/.config/gh"

cat > "$WORK/.config/Claude/claude_desktop_config.json" <<'EOF'
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/alice"]
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "${GH_TOKEN}" }
    },
    "fetch": { "command": "uvx", "args": ["mcp-server-fetch"] },
    "salesforce-mcp": {
      "command": "/opt/mcp/salesforce",
      "env": { "SF_OAUTH_TOKEN": "${SF_TOKEN}" }
    },
    "prod-deploy": {
      "command": "/opt/mcp/prod-deploy",
      "env": { "AWS_ROLE_ARN": "arn:aws:iam::111122223333:role/prod-deploy-role" }
    }
  }
}
EOF

cat > "$WORK/.aws/credentials" <<'EOF'
[default]
[prod-readonly]
[prod-admin]
EOF

touch "$WORK/.ssh/id_ed25519.pub"
cat > "$WORK/.config/gh/hosts.yml" <<'EOF'
github.com:
  user: alice
EOF

echo "==> agenthound local"
agenthound local --home "$WORK" --hostname demo-laptop -o "$WORK/local.json"

echo "==> agenthound mcp"
agenthound mcp -i examples/mcp_inventory.yaml -o "$WORK/mcp.json"

echo "==> agenthound infer"
agenthound infer "$WORK/local.json" "$WORK/mcp.json" -o "$WORK/merged.json"

echo "==> agenthound emit (BloodHound OpenGraph payload)"
agenthound emit "$WORK/merged.json" -o "$WORK/bloodhound.json"

echo
echo "==> Production blast-radius paths (simulated locally):"
python3 - <<PY
import json
from collections import defaultdict, deque

data = json.load(open("$WORK/bloodhound.json"))
nodes = {n["id"]: n for n in data["graph"]["nodes"]}
adj = defaultdict(list)
for e in data["graph"]["edges"]:
    adj[e["start"]["value"]].append((e["kind"], e["end"]["value"]))

sources = [nid for nid, n in nodes.items() if n["kinds"][0] == "InjectableInput"]
prod = {nid for nid, n in nodes.items()
        if n["kinds"][0] == "Resource" and n["properties"].get("tier") == "production"}

paths = []
for src in sources:
    q = deque([(src, [src])])
    while q:
        cur, trail = q.popleft()
        if len(trail) > 10:
            continue
        for ek, tgt in adj[cur]:
            if tgt in trail:
                continue
            new_trail = trail + [tgt]
            if tgt in prod and ek == "GRANTS_ACCESS":
                paths.append(new_trail)
                continue
            q.append((tgt, new_trail))

unique = list({tuple(p): p for p in paths}.values())
print(f"Found {len(unique)} production blast-radius paths.")
for p in sorted(unique, key=len)[:3]:
    print()
    for j, nid in enumerate(p):
        n = nodes[nid]
        arrow = "    └─>" if j else "       "
        print(f"  {arrow} [{n['kinds'][0]:18s}] {n['properties']['name']}")
PY

echo
echo "==> bloodhound.json ready at: $WORK/bloodhound.json"
echo "==> Ingest into BloodHound CE: Settings → Manage data → Upload."
