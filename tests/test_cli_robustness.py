"""Robustness tests from the Pass-1 audit cleanup.

F8 — `infer`/`emit` must fail cleanly (ClickException, not a traceback) on a
malformed or wrong-shaped input file.
F9 — a `--known-servers` overlay entry missing keys must not crash the local
collector; it falls back to the unknown-server defaults.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from agenthound.audit import AuditLog
from agenthound.cli import main
from agenthound.collectors.local import LocalCollector
from agenthound.collectors.mcp import MCPCollector
from agenthound.scope import EngagementScope, ScopeGuard


def test_public_command_names_are_concise() -> None:
    commands = main.commands
    assert {"aws", "azure", "gcp", "va", "verify-audit"} <= commands.keys()
    assert {"aws-iam", "azure-rbac", "gcp-iam"}.isdisjoint(commands)
    assert not commands["va"].hidden
    assert commands["verify-audit"].hidden


def test_audit_verification_commands(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    AuditLog(audit_path, "test-key").record("collect", "test", "ALLOW", "in scope")

    for command in ("va", "verify-audit"):
        result = CliRunner().invoke(
            main,
            [command, str(audit_path)],
            env={"AGENTHOUND_AUDIT_KEY": "test-key"},
        )

        assert result.exit_code == 0
        assert "AUDIT OK" in result.output

# --- F8: infer/emit reject bad input cleanly ---------------------------------

def test_infer_rejects_malformed_json(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{ this is not valid json")
    result = CliRunner().invoke(main, ["infer", str(bad)])
    assert result.exit_code != 0
    assert "Could not read collection file" in result.output


def test_emit_rejects_structurally_invalid_graph(tmp_path: Path) -> None:
    # Valid JSON, but the only node kind is the branding kind — this used to
    # raise IndexError out of _result_from_json and traceback to the user.
    bad = tmp_path / "bad.json"
    only_branding_node = {"id": "x", "kinds": ["AgentHound"], "properties": {}}
    bad.write_text(json.dumps({"graph": {"nodes": [only_branding_node], "edges": []}}))
    result = CliRunner().invoke(main, ["emit", str(bad)])
    assert result.exit_code != 0
    assert "Could not read collection file" in result.output


# --- F9: malformed known-servers overlay does not crash ----------------------

def test_known_servers_overlay_missing_keys_does_not_crash(tmp_path: Path) -> None:
    home = tmp_path / "home"
    config_dir = home / ".config" / "Claude"
    config_dir.mkdir(parents=True)
    (config_dir / "claude_desktop_config.json").write_text(
        json.dumps({"mcpServers": {"weirdserver": {"command": "x"}}})
    )
    # Overlay entry is missing `classification` and `provider`.
    overlay = tmp_path / "overlay.yaml"
    overlay.write_text("servers:\n  weirdserver:\n    tools: [do_thing]\n")

    # Previously raised KeyError on known['classification']; must now fail soft.
    result = LocalCollector(home=home, hostname="h", known_servers=overlay).collect()

    server_nodes = [n for n in result.nodes if n.kind.value == "MCPServer"]
    assert server_nodes, "server should still be emitted with default classification/provider"
    tool_nodes = [n for n in result.nodes if n.kind.value == "MCPTool"]
    assert any(t.properties.get("classification") == ["unclassified"] for t in tool_nodes)


def test_mcp_scalar_server_entry_fails_soft(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory.yaml"
    inventory.write_text("servers: [just-a-string]\n")
    result = MCPCollector(inventory).collect()
    assert result.nodes == [] and result.edges == []
    assert any("expected a mapping" in warning for warning in result.warnings)


def test_mcp_scalar_servers_field_fails_soft(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory.yaml"
    inventory.write_text("servers: not-a-list\n")
    result = MCPCollector(inventory).collect()
    assert result.nodes == [] and result.edges == []
    assert any("must be a list" in warning for warning in result.warnings)


def test_local_mcp_non_mapping_env_fails_soft(tmp_path: Path) -> None:
    home = tmp_path / "home"
    config = home / ".config" / "Claude" / "claude_desktop_config.json"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({"mcpServers": {"github": {"env": "bad"}}}))
    result = LocalCollector(home=home, hostname="h").collect()
    assert any("non-mapping 'env'" in warning for warning in result.warnings)


def test_denied_known_server_overlay_is_not_read(tmp_path: Path, monkeypatch) -> None:
    overlay = tmp_path / "secret-overlay.yaml"
    scope = EngagementScope.model_validate(
        {
            "engagement": "test",
            "authorized_until": "2099-01-01T00:00:00Z",
            "paths_denied": [overlay.as_posix()],
        }
    )
    original_read = Path.read_text

    def guarded_read(path, *args, **kwargs):
        if path == overlay:
            raise AssertionError("denied overlay was read")
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read)
    collector = LocalCollector(
        home=tmp_path / "home",
        hostname="h",
        known_servers=overlay,
        guard=ScopeGuard(scope),
    )
    assert collector.registry
