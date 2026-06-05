#!/usr/bin/env bash
# Self-contained smoke test for AgentHound's OFFLINE analysis mode.
#
# Builds a throwaway "captured" home dir in a temp location, tars it, and
# exercises `agenthound offline` four ways:
#   [1] it produces a graph from the tarball
#   [2] it finds the expected NHIs (aws profiles, ssh keypair, github MCP cred)
#   [3] its output matches a live `local` scan of the same tree (parity)
#   [4] it REFUSES a path-traversal tarbomb instead of extracting it
#
# Never touches your real $HOME — everything lives under a temp dir that is
# removed on exit (set KEEP=1 to keep the artifacts for inspection).
#
# Run from anywhere:
#   bash examples/try_offline.sh
#   KEEP=1 bash examples/try_offline.sh

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

# --- temp workspace ----------------------------------------------------------
WORK="$(mktemp -d)"
if [[ "${KEEP:-0}" == "1" ]]; then
  echo "==> Keeping artifacts at $WORK"
else
  trap 'rm -rf "$WORK"' EXIT
fi
CAP="$WORK/captured_home"

# --- pass/fail bookkeeping ---------------------------------------------------
PASS=0; FAIL=0
ok()  { echo "    [ok] $1"; PASS=$((PASS + 1)); }
bad() { echo "    [XX] $1"; FAIL=$((FAIL + 1)); }

# --- [setup] build a fake captured home --------------------------------------
echo "==> [setup] building a throwaway captured home at $CAP"
mkdir -p "$CAP/.aws" "$CAP/.ssh" "$CAP/.config/Claude"

# AWS profile NAMES only — the collector never reads the secret values.
cat > "$CAP/.aws/credentials" <<'EOF'
[default]
aws_access_key_id = AKIAFAKE
[work]
aws_access_key_id = AKIAFAKE2
EOF

# An SSH public-key filename — contents are never read.
echo 'ssh-ed25519 AAAAC3NzaC1fakekey demo@host' > "$CAP/.ssh/id_ed25519.pub"

# A Claude Desktop MCP config (multi-line JSON so it can't get wrap-mangled).
cat > "$CAP/.config/Claude/claude_desktop_config.json" <<'EOF'
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_TOKEN": "x" }
    }
  }
}
EOF

echo "==> [setup] packing the capture tarball"
tar -czf "$WORK/capture.tar.gz" -C "$CAP" .

# --- [1/4] offline produces a graph ------------------------------------------
echo
echo "==> [1/4] agenthound offline -> graph"
AH offline "$WORK/capture.tar.gz" -o "$WORK/offline.json"
NODES="$("$PYBIN" -c "import json,sys; print(len(json.load(open(sys.argv[1]))['graph']['nodes']))" "$WORK/offline.json")"
EDGES="$("$PYBIN" -c "import json,sys; print(len(json.load(open(sys.argv[1]))['graph']['edges']))" "$WORK/offline.json")"
if [[ "$NODES" -gt 0 ]]; then ok "graph has $NODES nodes, $EDGES edges"; else bad "no nodes produced"; fi

# --- [2/4] expected NHIs discovered ------------------------------------------
echo
echo "==> [2/4] expected NHIs discovered"
if "$PYBIN" - "$WORK/offline.json" <<'PYEOF'
import json, sys
g = json.load(open(sys.argv[1]))["graph"]
found = {(n["properties"].get("provider"), n["properties"].get("identifier"))
         for n in g["nodes"] if n["properties"].get("nhi_type")}
expect = {("aws", "default"), ("aws", "work"),
          ("ssh", "id_ed25519.pub"), ("github", "github")}
missing = expect - found
for p, i in sorted(expect):
    print(f"      {'.' if (p, i) in found else '!'} {p}: {i}")
sys.exit(1 if missing else 0)
PYEOF
then ok "all expected NHIs present"; else bad "some expected NHIs missing"; fi

# --- [3/4] parity with a live local scan -------------------------------------
echo
echo "==> [3/4] parity vs a live 'local' scan of the same tree"
AH local --home "$CAP" --hostname offline -o "$WORK/live.json"
if "$PYBIN" - "$WORK/offline.json" "$WORK/live.json" <<'PYEOF'
import json, sys
def load(p):
    g = json.load(open(p))["graph"]
    return sorted(n["id"] for n in g["nodes"]), len(g["edges"])
on, oe = load(sys.argv[1]); ln, le = load(sys.argv[2])
print(f"      offline: {len(on)} nodes / {oe} edges   live: {len(ln)} nodes / {le} edges")
sys.exit(0 if (on == ln and oe == le) else 1)
PYEOF
then ok "offline graph identical to live scan"; else bad "parity mismatch"; fi

# --- [4/4] tarbomb is refused ------------------------------------------------
echo
echo "==> [4/4] path-traversal tarbomb is refused"
"$PYBIN" - "$WORK/evil.tar.gz" <<'PYEOF'
import tarfile, io, sys
with tarfile.open(sys.argv[1], "w:gz") as t:
    data = b"pwned"
    info = tarfile.TarInfo("../../escape.txt")  # tries to escape the extract root
    info.size = len(data)
    t.addfile(info, io.BytesIO(data))
PYEOF
if AH offline "$WORK/evil.tar.gz" >/dev/null 2>"$WORK/evil.err"; then
  bad "tarbomb was NOT refused (it got extracted!)"
else
  ok "tarbomb refused: $(sed 's/^Error: //' "$WORK/evil.err" | head -1)"
fi

# --- summary -----------------------------------------------------------------
echo
echo "==> Summary: $PASS passed, $FAIL failed"
if [[ "$FAIL" -eq 0 ]]; then
  echo "    All offline-mode checks passed."
else
  echo "    Some checks FAILED."
  exit 1
fi
