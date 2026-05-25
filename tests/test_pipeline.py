"""End-to-end pipeline test.

Builds a synthetic developer home directory, runs the local collector, the
MCP inventory collector, the coercion inferencer, and the OpenGraph emitter,
then walks the resulting graph to confirm at least one production-blast-radius
path exists. Covers the entire happy path in one test.
"""

from __future__ import annotations

import json
from collections import defaultdict, deque
from pathlib import Path

import pytest

from agenthound.collectors.local import LocalCollector
from agenthound.collectors.mcp import MCPCollector
from agenthound.inference import CoercionInferencer
from agenthound.schema import build_payload


CLAUDE_DESKTOP_CONFIG = {
    "mcpServers": {
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/alice"],
        },
        "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]},
        "salesforce-mcp": {
            "command": "/opt/mcp/salesforce",
            "env": {"SF_OAUTH_TOKEN": "${SF_TOKEN}"},
        },
        "prod-deploy": {
            "command": "/opt/mcp/prod-deploy",
            "env": {"AWS_ROLE_ARN": "arn:aws:iam::111122223333:role/prod-deploy-role"},
        },
    }
}


INVENTORY = """
servers:
  - name: salesforce-mcp
    transport: stdio
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
    tools:
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
"""


@pytest.fixture
def synthetic_home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    config_dir = home / ".config" / "Claude"
    config_dir.mkdir(parents=True)
    (config_dir / "claude_desktop_config.json").write_text(json.dumps(CLAUDE_DESKTOP_CONFIG))

    # Seed a few credentials so the credential collectors have something to find.
    aws_dir = home / ".aws"
    aws_dir.mkdir()
    (aws_dir / "credentials").write_text("[default]\n[prod-readonly]\n[prod-admin]\n")

    ssh_dir = home / ".ssh"
    ssh_dir.mkdir()
    (ssh_dir / "id_ed25519.pub").touch()

    gh_dir = home / ".config" / "gh"
    gh_dir.mkdir(parents=True)
    (gh_dir / "hosts.yml").write_text("github.com:\n  user: alice\n")

    return home


@pytest.fixture
def inventory_file(tmp_path: Path) -> Path:
    p = tmp_path / "inventory.yaml"
    p.write_text(INVENTORY)
    return p


def test_pipeline_finds_production_blast_radius(synthetic_home: Path, inventory_file: Path) -> None:
    """End-to-end: local → mcp → infer → emit, with a reachable prod path."""
    local = LocalCollector(home=synthetic_home, hostname="test-host").collect()
    mcp = MCPCollector(inventory_path=inventory_file).collect()

    merged = local
    merged.extend(mcp)

    derived = CoercionInferencer().infer(merged)
    merged.extend(derived)

    payload = build_payload(merged.nodes, merged.edges)
    data = payload.to_dict()

    nodes = {n["id"]: n for n in data["graph"]["nodes"]}
    edges = data["graph"]["edges"]

    adj: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for e in edges:
        adj[e["start"]["value"]].append((e["kind"], e["end"]["value"]))

    sources = [nid for nid, n in nodes.items() if n["kinds"][0] == "InjectableInput"]
    prod = {
        nid
        for nid, n in nodes.items()
        if n["kinds"][0] == "Resource" and n["properties"].get("tier") == "production"
    }

    assert sources, "Expected at least one InjectableInput from source-tagged tools"
    assert prod, "Expected at least one production-tier Resource"

    found = False
    for src in sources:
        queue = deque([(src, [src])])
        while queue:
            cur, trail = queue.popleft()
            if len(trail) > 10:
                continue
            for ek, tgt in adj[cur]:
                if tgt in trail:
                    continue
                new_trail = trail + [tgt]
                if tgt in prod and ek == "GRANTS_ACCESS":
                    found = True
                    break
                queue.append((tgt, new_trail))
            if found:
                break
        if found:
            break

    assert found, "Expected at least one InjectableInput → ... → production Resource path"


def test_coercion_edges_carry_injection_class(synthetic_home: Path, inventory_file: Path) -> None:
    """COERCES edges must always carry an injection_class property."""
    local = LocalCollector(home=synthetic_home, hostname="test-host").collect()
    mcp = MCPCollector(inventory_path=inventory_file).collect()
    merged = local
    merged.extend(mcp)
    derived = CoercionInferencer().infer(merged)

    coerces = [e for e in derived.edges if e.kind.value == "COERCES"]
    assert coerces, "Expected COERCES edges from the inferencer"
    for e in coerces:
        assert "injection_class" in e.properties
        assert e.properties["injection_class"] in {"direct", "indirect", "stored", "shadow"}


def test_registry_loaded_from_yaml(synthetic_home: Path) -> None:
    """The known-MCP-server registry should populate from the bundled YAML."""
    collector = LocalCollector(home=synthetic_home, hostname="test-host")
    assert "filesystem" in collector.registry
    assert "github" in collector.registry
    assert "salesforce" in collector.registry
    # The expanded registry should have substantially more than the original 12 entries.
    assert len(collector.registry) >= 30


def test_no_credential_values_emitted(synthetic_home: Path) -> None:
    """Sanity check: no node property should contain credential-looking content."""
    result = LocalCollector(home=synthetic_home, hostname="test-host").collect()
    for n in result.nodes:
        for key, value in n.properties.items():
            sval = str(value).lower()
            for forbidden in ("aws_secret", "private_key", "bearer ", "ghp_", "sk-"):
                assert forbidden not in sval, f"Node {n.name}.{key} leaks {forbidden!r}"
