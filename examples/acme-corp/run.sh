#!/usr/bin/env bash
# Run AgentHound over the Acme Robotics reference environment (a FAKE but
# production-shaped AWS + GCP + Azure org) and print the findings.
#
# It runs the three cloud collectors on the bundled JSON exports, merges them
# with `infer`, emits one BloodHound OpenGraph payload, and reports:
#   - full-access ("admin") identities per cloud, by policy EVIDENCE
#   - CanAssume escalation edges (assume-role / SA impersonation), flagging hops
#     that land on a full-access identity
#   - node / edge counts
#
# AgentHound is network-free and upload-only — it NEVER calls AWS/GCP/Azure.
# To run against your REAL org, replace the values in the three JSON files per
# README.md ("Replace with your real values"), then re-run this script.
#
# Run from anywhere:
#   bash examples/acme-corp/run.sh
#   KEEP=1 bash examples/acme-corp/run.sh     # keep the emitted payload

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$SCRIPT_DIR"
cd "$SCRIPT_DIR/../.."   # repo root

if   [[ -x .venv/bin/python ]];          then PYBIN=".venv/bin/python"
elif [[ -x .venv/Scripts/python.exe ]];  then PYBIN=".venv/Scripts/python.exe"
elif command -v python3 >/dev/null 2>&1; then PYBIN="python3"
else                                          PYBIN="python"
fi

if ! "$PYBIN" -c "import agenthound, click, yaml, pydantic" >/dev/null 2>&1; then
  echo "error: agenthound and its deps aren't importable with '$PYBIN'." >&2
  echo "       python3 -m venv .venv && . .venv/bin/activate && pip install -e ." >&2
  exit 1
fi

AH() { "$PYBIN" -m agenthound.cli "$@"; }

WORK="$(mktemp -d)"
if [[ "${KEEP:-0}" == "1" ]]; then echo "==> Keeping artifacts at $WORK"
else trap 'rm -rf "$WORK"' EXIT; fi

echo "==> Collecting (network-free, from the bundled exports)"
AH aws-iam    -i "$DATA_DIR/aws_iam.json"    -o "$WORK/aws.json"   >/dev/null
AH gcp-iam    -i "$DATA_DIR/gcp_iam.json"    -o "$WORK/gcp.json"   >/dev/null
AH azure-rbac -i "$DATA_DIR/azure_rbac.json" -o "$WORK/azure.json" >/dev/null
AH infer "$WORK/aws.json" "$WORK/gcp.json" "$WORK/azure.json" -o "$WORK/merged.json" >/dev/null
AH emit "$WORK/merged.json" -o "$WORK/acme-bloodhound.json" >/dev/null

"$PYBIN" - "$WORK/acme-bloodhound.json" <<'PYEOF'
import json, sys
g = json.load(open(sys.argv[1]))["graph"]
nodes = {n["id"]: n for n in g["nodes"]}
def prop(nid, k): return nodes[nid]["properties"].get(k) if nid in nodes else None

admins = [n for n in g["nodes"] if n["properties"].get("grants_full_access") is True]
print(f"\n==> Graph: {len(g['nodes'])} nodes, {len(g['edges'])} edges\n")

print(f"==> Full-access (admin) identities — by policy evidence — {len(admins)} found:")
for n in sorted(admins, key=lambda n: (n['properties'].get('provider',''), n['properties'].get('principal_name',''))):
    p = n["properties"]
    print(f"      [{p.get('provider','?'):5s}] {p.get('principal_name')}   ({p.get('nhi_type')})")

esc = [e for e in g["edges"] if e["kind"] == "CanAssume"]
print(f"\n==> CanAssume escalation edges (assume-role / impersonation) — {len(esc)} found:")
for e in esc:
    src, tgt = e["start"]["value"], e["end"]["value"]
    src_name = prop(src, "principal_name") or prop(src, "name") or src
    tgt_name = prop(tgt, "principal_name") or prop(tgt, "name") or tgt
    flag = "  <== lands on FULL-ACCESS identity" if prop(tgt, "grants_full_access") is True else ""
    via = e.get("properties", {}).get("via", "")
    print(f"      {src_name}  -[{via}]->  {tgt_name}{flag}")
print()
PYEOF

echo "==> Emitted payload: $WORK/acme-bloodhound.json"
echo "    Ingest into BloodHound CE: Settings -> Manage data -> Upload Files."
