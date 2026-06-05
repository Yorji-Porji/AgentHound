"""Unknown / custom MCP tool handling.

Two behaviours added after the Pass-1 audit:
- access mapping: an unknown server's credential env-var *names* are attributed
  to their provider (aws, github, ...), scope permitting;
- F10: an unclassified tool is still treated as a pessimistic injection source.
"""

from __future__ import annotations

import json
from pathlib import Path

from agenthound.collectors.local import LocalCollector, _providers_from_env
from agenthound.inference import CoercionInferencer
from agenthound.schema.nodes import NodeKind
from agenthound.scope import EngagementScope, ScopeGuard


def _home_with_server(tmp_path: Path, server_cfg: dict) -> Path:
    home = tmp_path / "home"
    config_dir = home / ".config" / "Claude"
    config_dir.mkdir(parents=True)
    (config_dir / "claude_desktop_config.json").write_text(
        json.dumps({"mcpServers": {"custom-thing": server_cfg}})
    )
    return home


def _nhi_providers(nodes) -> set[str]:
    return {n.properties.get("provider") for n in nodes if n.kind == NodeKind.NHI}


# --- env-name -> provider inference ------------------------------------------

def test_providers_from_env_recognizes_common_creds() -> None:
    out = _providers_from_env(["AWS_ACCESS_KEY_ID", "GITHUB_TOKEN", "RANDOM_SETTING"])
    assert out["aws"] == ["AWS_ACCESS_KEY_ID"]
    assert out["github"] == ["GITHUB_TOKEN"]
    assert "postgres" not in out  # unmatched names are simply dropped


def test_unknown_server_env_maps_provider_access(tmp_path: Path) -> None:
    home = _home_with_server(
        tmp_path, {"command": "x", "env": {"AWS_SECRET_ACCESS_KEY": "${A}", "GITHUB_TOKEN": "${G}"}}
    )
    result = LocalCollector(home=home, hostname="h").collect()
    providers = _nhi_providers(result.nodes)
    assert "aws" in providers
    assert "github" in providers


def test_env_provider_mapping_respects_scope(tmp_path: Path) -> None:
    home = _home_with_server(
        tmp_path, {"command": "x", "env": {"AWS_SECRET_ACCESS_KEY": "${A}", "GITHUB_TOKEN": "${G}"}}
    )
    guard = ScopeGuard(
        EngagementScope.model_validate(
            {
                "engagement": "t",
                "authorized_until": "2099-01-01T00:00:00Z",
                "providers_denied": ["aws"],
            }
        )
    )
    result = LocalCollector(home=home, hostname="h", guard=guard).collect()
    providers = _nhi_providers(result.nodes)
    assert "aws" not in providers  # deny-wins: no node, no edge
    assert "github" in providers


# --- F10: unclassified tool is a pessimistic injection source ----------------

def test_unclassified_tool_is_pessimistic_injection_source(tmp_path: Path) -> None:
    # 'custom-thing' is not in the registry, so its tool is tagged unclassified.
    home = _home_with_server(tmp_path, {"command": "x"})
    collected = LocalCollector(home=home, hostname="h").collect()
    derived = CoercionInferencer().infer(collected)
    coerces = [e for e in derived.edges if e.kind.value == "COERCES"]
    assert coerces, "an unclassified tool should still yield a pessimistic COERCES edge"
