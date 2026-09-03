#!/usr/bin/env bash
# Self-contained smoke test for AgentHound's three cloud collectors:
#   agenthound aws    (AWS  — IAM authorization-details export)
#   agenthound gcp    (GCP  — Cloud Asset Inventory IAM-policy export)
#   agenthound azure  (Azure — RBAC role assignments + definitions)
#
# It runs each collector against the BUNDLED example exports (so it works on a
# fresh box with NO cloud accounts and NO network), chains infer -> emit into one
# BloodHound OpenGraph payload, and asserts the headline behaviours:
#   [1] each collector produces a graph
#   [2] evidence-based admin: admin comes from policy CONTENT, not a name
#   [3] GCP service-account impersonation forms a CanAssume escalation edge
#   [4] the merged graph inventories full-access identities across all 3 clouds
#   [5] engagement scope (--scope) deny-wins: a denied provider yields nothing
#
# AgentHound is network-free and upload-only: it NEVER calls AWS/GCP/Azure. To
# point it at a REAL environment, generate the exports yourself with the
# read-only commands below and pass them with -i instead of the example files:
#
#   AWS    aws iam get-account-authorization-details > aws_iam.json
#          (read-only; needs iam:GetAccountAuthorizationDetails)
#   GCP    gcloud asset search-all-iam-policies \
#            --scope=organizations/ORG_ID --format=json > gcp_iam.json
#          (read-only; needs roles/cloudasset.viewer; enable cloudasset.googleapis.com)
#   Azure  az role assignment list --all -o json   > _ra.json
#          az role definition  list        -o json  > _rd.json
#          # combine into {"roleAssignments": <_ra>, "roleDefinitions": <_rd>}
#          (read-only; needs the Reader role)
#
# Never touches your real $HOME — everything lives under a temp dir removed on
# exit (set KEEP=1 to keep the artifacts for inspection).
#
# Run from anywhere:
#   bash examples/try_clouds.sh
#   KEEP=1 bash examples/try_clouds.sh

set -euo pipefail

# --- locate repo root and a usable interpreter -------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

if   [[ -x .venv/bin/python ]];          then PYBIN=".venv/bin/python"
elif [[ -x .venv/Scripts/python.exe ]];  then PYBIN=".venv/Scripts/python.exe"
elif command -v python3 >/dev/null 2>&1; then PYBIN="python3"
else                                          PYBIN="python"
fi

if ! "$PYBIN" -c "import agenthound, click, yaml, pydantic" >/dev/null 2>&1; then
  echo "error: agenthound and its deps aren't importable with '$PYBIN'." >&2
  echo "       Set up a venv first:" >&2
  echo "         python3 -m venv .venv && . .venv/bin/activate && pip install -e ." >&2
  exit 1
fi

AH() { "$PYBIN" -m agenthound.cli "$@"; }

AWS_EXPORT="examples/aws_iam_export.example.json"
GCP_EXPORT="examples/gcp_iam_policies.example.json"
AZURE_EXPORT="examples/azure_role_assignments.example.json"

# --- temp workspace ----------------------------------------------------------
WORK="$(mktemp -d)"
if [[ "${KEEP:-0}" == "1" ]]; then
  echo "==> Keeping artifacts at $WORK"
else
  trap 'rm -rf "$WORK"' EXIT
fi

# --- pass/fail bookkeeping ---------------------------------------------------
PASS=0; FAIL=0
ok()  { echo "    [ok] $1"; PASS=$((PASS + 1)); }
bad() { echo "    [XX] $1"; FAIL=$((FAIL + 1)); }

counts() {  # prints "<nodes> <edges>" for an emitted payload (CR-stripped for Git Bash)
  "$PYBIN" -c "import json,sys; g=json.load(open(sys.argv[1]))['graph']; print(len(g['nodes']), len(g['edges']))" "$1" | tr -d '\r'
}

# --- [1/5] each collector produces a graph -----------------------------------
echo "==> [1/5] running the three cloud collectors against the bundled examples"
AH aws   -i "$AWS_EXPORT"   -o "$WORK/aws.json"   >/dev/null
AH gcp   -i "$GCP_EXPORT"   -o "$WORK/gcp.json"   >/dev/null
AH azure -i "$AZURE_EXPORT" -o "$WORK/azure.json" >/dev/null
for cloud in aws gcp azure; do
  read -r N E < <(counts "$WORK/$cloud.json")
  if [[ "$N" -gt 0 && "$E" -gt 0 ]]; then ok "$cloud: $N nodes, $E edges"
  else bad "$cloud collector produced an empty graph"; fi
done

# --- [2/5] evidence-based admin (a name is not a verdict) --------------------
echo
echo "==> [2/5] evidence-based admin flags (admin from policy content, not name)"
if "$PYBIN" - "$WORK/aws.json" "$WORK/gcp.json" "$WORK/azure.json" <<'PYEOF'
import json, sys

def by_name(path):
    g = json.load(open(path))["graph"]
    return {n["properties"].get("principal_name"): n["properties"].get("grants_full_access")
            for n in g["nodes"] if n["properties"].get("principal_name")}

aws, gcp, azure = (by_name(p) for p in sys.argv[1:4])

checks = [
    # AWS: OrgAdmin (AdministratorAccess ARN) and the blandly-named ci-deployer
    #      (inline Allow *:*) are BOTH admin; ReadOnlyAuditor is not.
    ("AWS  OrgAdmin is admin",                 aws.get("OrgAdmin") is True),
    ("AWS  ci-deployer (bland name) is admin", aws.get("ci-deployer") is True),
    ("AWS  ReadOnlyAuditor is NOT admin",      aws.get("ReadOnlyAuditor") is False),
    # GCP: the owner SA is admin (roles/owner); auditor (viewer) is not.
    ("GCP  ci-deployer SA is admin",           gcp.get("ci-deployer@acme-prod.iam.gserviceaccount.com") is True),
    ("GCP  auditor (viewer) is NOT admin",     gcp.get("auditor@example.com") is False),
    # Azure: Owner is admin; Contributor has '*' but notActions -> NOT admin.
    ("Azure Owner SP is admin",                azure.get("ci-deployer-sp") is True),
    ("Azure Contributor MI is NOT admin",      azure.get("acme-app-mi") is False),
]
ok = True
for label, passed in checks:
    print(f"      {'.' if passed else '!'} {label}")
    ok = ok and passed
sys.exit(0 if ok else 1)
PYEOF
then ok "admin flags match policy evidence on all three clouds"
else bad "an admin flag did not match its policy evidence"; fi

# --- [3/5] GCP service-account impersonation -> CanAssume escalation ----------
echo
echo "==> [3/5] GCP impersonation forms a privilege-escalation edge"
if "$PYBIN" - "$WORK/gcp.json" <<'PYEOF'
import json, sys
g = json.load(open(sys.argv[1]))["graph"]
nodes = {n["id"]: n for n in g["nodes"]}

def find(name):
    return next((nid for nid, n in nodes.items()
                 if n["properties"].get("principal_name") == name), None)

dev = find("dev@example.com")
sa  = find("ci-deployer@acme-prod.iam.gserviceaccount.com")
# dev (a non-admin user) can impersonate ci-deployer, which is roles/owner.
escalates = any(
    e["kind"] == "CanAssume" and e["start"]["value"] == dev and e["end"]["value"] == sa
    for e in g["edges"]
)
target_is_admin = sa is not None and nodes[sa]["properties"].get("grants_full_access") is True
print(f"      {'.' if escalates else '!'} dev -[CanAssume]-> ci-deployer SA")
print(f"      {'.' if target_is_admin else '!'} the impersonated SA is roles/owner (admin)")
sys.exit(0 if (escalates and target_is_admin) else 1)
PYEOF
then ok "non-admin user reaches an owner SA via impersonation"
else bad "impersonation escalation edge missing"; fi

# --- [4/5] merged graph: cross-cloud full-access inventory -------------------
echo
echo "==> [4/5] infer + emit -> one BloodHound OpenGraph payload"
AH infer "$WORK/aws.json" "$WORK/gcp.json" "$WORK/azure.json" -o "$WORK/merged.json" >/dev/null
AH emit "$WORK/merged.json" -o "$WORK/bloodhound.json" >/dev/null
read -r MN ME < <(counts "$WORK/bloodhound.json")
echo "      merged graph: $MN nodes, $ME edges"
if "$PYBIN" - "$WORK/bloodhound.json" <<'PYEOF'
import json, sys
from collections import Counter
g = json.load(open(sys.argv[1]))["graph"]
admins = Counter(
    n["properties"].get("provider")
    for n in g["nodes"]
    if n["properties"].get("grants_full_access") is True
)
for prov in ("aws", "gcp", "azure"):
    print(f"      {'.' if admins.get(prov) else '!'} {prov}: {admins.get(prov, 0)} full-access identity(ies)")
# AWS 2 (OrgAdmin, ci-deployer) + GCP 1 + Azure 1 = 4, across all three providers.
sys.exit(0 if (sum(admins.values()) >= 4 and {"aws", "gcp", "azure"} <= set(admins)) else 1)
PYEOF
then ok "full-access identities inventoried across all three clouds"
else bad "cross-cloud full-access inventory incomplete"; fi

# --- [5/5] engagement scope deny-wins ----------------------------------------
echo
echo "==> [5/5] --scope deny-wins: a denied provider yields nothing"
cat > "$WORK/deny.yaml" <<'EOF'
engagement: cloud-smoke-test
authorized_until: "2099-01-01T00:00:00Z"
providers_denied: [gcp]
EOF
AH gcp -i "$GCP_EXPORT" --scope "$WORK/deny.yaml" -o "$WORK/denied.json" >/dev/null
read -r DN DE < <(counts "$WORK/denied.json")
if [[ "$DN" -eq 0 && "$DE" -eq 0 ]]; then ok "scoped-out 'gcp' produced 0 nodes, 0 edges"
else bad "denied provider still produced $DN nodes / $DE edges"; fi

# --- summary -----------------------------------------------------------------
echo
echo "==> Summary: $PASS passed, $FAIL failed"
echo "    Final payload: $WORK/bloodhound.json (ingest via BloodHound CE → Manage data → Upload)"
if [[ "$FAIL" -eq 0 ]]; then
  echo "    All cloud-collector checks passed."
else
  echo "    Some checks FAILED."
  exit 1
fi
