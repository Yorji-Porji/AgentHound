#!/usr/bin/env bash
# Self-contained AgentHound demo. Builds a throwaway synthetic developer machine
# AND its own MCP inventory in a temp dir, runs the full collect→infer→emit
# pipeline, and prints the production blast-radius paths.
#
# Everything is created under a temp dir and removed on exit — it never touches
# your real $HOME and depends on nothing in the repo except the installed CLI.
# Run from anywhere: bash examples/run_demo.sh

set -euo pipefail

# Resolve the agenthound entry point (installed console script, or module).
if command -v agenthound >/dev/null 2>&1; then
  AH() { agenthound "$@"; }
elif python3 -c "import agenthound" >/dev/null 2>&1; then
  AH() { python3 -m agenthound.cli "$@"; }
else
  echo "error: agenthound not found. Install it first:  pip install -e ." >&2
  exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "==> Building a synthetic developer home at $WORK/home"
HOME_DIR="$WORK/home"
mkdir -p "$HOME_DIR/.config/Claude" "$HOME_DIR/.aws" "$HOME_DIR/.ssh" "$HOME_DIR/.config/gh"

# Agent config. Server names here are chosen to MATCH the inventory below, so the
# locally-discovered servers and the documented inventory join into one node.
cat > "$HOME_DIR/.config/Claude/claude_desktop_config.json" <<'EOF'
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/work"]
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

# A realistic ~/.aws, the way a real developer machine looks — but with NO secret
# values. AWS splits its config across two files, and AgentHound reads only the
# parts that are safe to read:
#
#   ~/.aws/credentials  -> long-lived IAM keys live here. AgentHound reads the
#                          [profile] NAMES only, never the key values. This demo
#                          writes no key values at all, to prove the point.
#   ~/.aws/config       -> non-secret settings: region, output, and assume-role
#                          chains (role_arn + source_profile). Those role_arn
#                          lines are the "blast-radius" breadcrumbs a future
#                          release will resolve into the resources each role
#                          can actually reach.
cat > "$HOME_DIR/.aws/credentials" <<'EOF'
# On a real box the secret keys would live here, e.g.:
#   [default]
#   aws_access_key_id     = AKIAIOSFODNN7EXAMPLE        # an identifier, not a secret
#   aws_secret_access_key = wJalrXUtnFEMI/...EXAMPLE    # the SECRET — never logged
# Only [default] holds real keys; the prod-* profiles are *assumed* roles that
# chain off it (see ~/.aws/config below), so they don't appear here.
[default]
EOF

cat > "$HOME_DIR/.aws/config" <<'EOF'
[default]
region = us-east-1
output = json

# A read-only role this developer can assume by chaining off [default]'s keys.
[profile prod-readonly]
region = us-east-1
role_arn = arn:aws:iam::111122223333:role/ReadOnlyAuditor
source_profile = default

# A high-privilege role — the blast-radius target. Assuming it requires MFA.
[profile prod-admin]
region = us-east-1
role_arn = arn:aws:iam::111122223333:role/OrgAdmin
source_profile = default
mfa_serial = arn:aws:iam::111122223333:mfa/alice
EOF
touch "$HOME_DIR/.ssh/id_ed25519.pub"
cat > "$HOME_DIR/.config/gh/hosts.yml" <<'EOF'
github.com:
  user: alice
EOF

echo "==> Writing a synthetic MCP inventory at $WORK/inventory.yaml"
# Self-contained inventory. `salesforce-mcp` and `prod-deploy` match the agent
# config above; each carries a backing NHI and a production-tier resource, so a
# full InjectableInput → Agent → MCPTool → NHI → production Resource path forms.
cat > "$WORK/inventory.yaml" <<'EOF'
servers:
  - name: salesforce-mcp
    transport: http
    provider: salesforce
    tools:
      - name: search_records
        classification: [rag_retriever, query_runner]
      - name: update_record
        classification: [cloud_mutator]
    backing_nhi:
      provider: salesforce
      identifier: oauth_app_marketing
      nhi_type: oauth_app
    accessible_resources:
      - provider: salesforce
        kind: object
        identifier: Account
        tier: production

  - name: prod-deploy
    transport: stdio
    provider: aws
    tools:
      - name: read_plan
        classification: [file_reader]
      - name: apply_terraform
        classification: [cloud_mutator, code_writer]
    backing_nhi:
      provider: aws
      identifier: prod-deploy-role
      nhi_type: assumed_role
    accessible_resources:
      - provider: aws
        kind: account
        identifier: "111122223333"
        tier: production
EOF

echo "==> agenthound local"
AH local --home "$HOME_DIR" --hostname demo-laptop -o "$WORK/local.json"

echo "==> agenthound mcp"
AH mcp -i "$WORK/inventory.yaml" -o "$WORK/mcp.json"

echo "==> agenthound infer"
AH infer "$WORK/local.json" "$WORK/mcp.json" -o "$WORK/merged.json"

echo "==> agenthound emit (BloodHound OpenGraph payload)"
AH emit "$WORK/merged.json" -o "$WORK/bloodhound.json"

echo
echo "==> Production blast-radius paths (simulated locally):"
python3 - "$WORK/bloodhound.json" <<'PY'
import json, sys
from collections import defaultdict, deque

data = json.load(open(sys.argv[1]))
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
            # Edge kinds are PascalCase-sanitized on emit (GRANTS_ACCESS -> GrantsAccess).
            if tgt in prod and ek == "GrantsAccess":
                paths.append(new_trail)
                continue
            q.append((tgt, new_trail))

unique = list({tuple(p): p for p in paths}.values())
print(f"Graph: {len(nodes)} nodes, {sum(len(v) for v in adj.values())} edges.")
print(f"Found {len(unique)} production blast-radius path(s).")
for p in sorted(unique, key=len)[:3]:
    print()
    for j, nid in enumerate(p):
        n = nodes[nid]
        arrow = "    └─>" if j else "       "
        print(f"  {arrow} [{n['kinds'][0]:16s}] {n['properties']['name']}")
PY

echo
echo "==> bloodhound.json was generated at: $WORK/bloodhound.json (removed on exit)"
echo "==> To keep it, copy it out before this script returns, e.g.:"
echo "      bash examples/run_demo.sh ; # or edit the trap"
echo "==> Ingest into BloodHound CE: Settings → Manage data → Upload Files."
