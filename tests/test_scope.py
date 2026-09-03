"""Week 2 scope tests — P1-W2-SCOPE-01..18.

Covers the pydantic model, the three ScopeGuard checks, and the enforcement
wiring into collectors. Time-window cases freeze the clock with freezegun so
timezone math is deterministic.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import click
import pytest
from freezegun import freeze_time
from pydantic import ValidationError

from agenthound.collectors.aws_iam import AWSIAMCollector
from agenthound.collectors.azure_rbac import AzureRBACCollector
from agenthound.collectors.gcp_iam import GCPIAMCollector
from agenthound.collectors.local import LocalCollector
from agenthound.collectors.mcp import MCPCollector
from agenthound.scope import (
    EngagementScope,
    ScopeExpired,
    ScopeGuard,
    TimeWindow,
    _glob_to_regex,
    _parse_clock,
)

FIXTURES = Path(__file__).parent / "fixtures"
FUTURE = "2099-12-31T23:59:59Z"


def _scope(**overrides) -> EngagementScope:
    base = {"engagement": "t", "authorized_until": FUTURE}
    base.update(overrides)
    return EngagementScope.model_validate(base)


def _guard(**overrides) -> ScopeGuard:
    return ScopeGuard(_scope(**overrides))


# --- loading & validation (SCOPE-01..04) -------------------------------------

def test_scope01_valid_loads():
    scope = EngagementScope.from_yaml(FIXTURES / "scope_valid.yaml")
    assert scope.engagement == "acme-corp-2026-q2"
    assert scope.authorized_until.tzinfo is not None
    assert scope.providers_allowed == ["aws", "github"]
    assert scope.providers_denied == ["azure"]
    assert scope.audit_log == "audit.jsonl"
    assert isinstance(scope.time_windows[0], TimeWindow)


def test_scope02_missing_engagement_raises():
    with pytest.raises(ValidationError):
        EngagementScope.model_validate({"authorized_until": FUTURE})


def test_scope03_bad_authorized_until_raises():
    with pytest.raises(ValidationError):
        EngagementScope.model_validate({"engagement": "x", "authorized_until": "not-a-date"})


def test_scope04_expired_guard_refuses():
    scope = EngagementScope.from_yaml(FIXTURES / "scope_expired.yaml")
    with pytest.raises(ScopeExpired):
        ScopeGuard(scope)


def test_unknown_field_is_rejected():
    with pytest.raises(ValidationError):
        EngagementScope.model_validate(
            {"engagement": "x", "authorized_until": FUTURE, "bogus": 1}
        )


def test_naive_authorized_until_gets_utc():
    scope = _scope(authorized_until="2099-12-31T23:59:59")
    assert scope.authorized_until.tzinfo is not None


# --- provider rules (SCOPE-05..08) -------------------------------------------

def test_scope05_provider_allowed():
    assert _guard(providers_allowed=["aws"]).check_provider("aws") is True


def test_scope06_provider_denied():
    assert _guard(providers_denied=["azure"]).check_provider("azure") is False


def test_scope07_conflict_deny_wins():
    scope = EngagementScope.from_yaml(FIXTURES / "scope_conflict.yaml")
    assert ScopeGuard(scope).check_provider("aws") is False


def test_scope08_allowlist_is_exclusive():
    assert _guard(providers_allowed=["aws"]).check_provider("github") is False


def test_no_allowlist_allows_anything_not_denied():
    assert _guard().check_provider("whatever") is True


# --- path rules (SCOPE-09..11) -----------------------------------------------

def test_scope09_path_denied():
    g = _guard(paths_denied=["/home/x/.aws/*"])
    assert g.check_path("/home/x/.aws/credentials") is False


def test_scope10_sibling_path_allowed():
    g = _guard(paths_denied=["/home/*/.medical/**"])
    assert g.check_path("/home/x/.config/notes") is True


def test_scope11_deep_glob_depth_correct():
    g = _guard(paths_denied=["/home/*/.medical/**"])
    assert g.check_path("/home/x/.medical/notes") is False
    assert g.check_path("/home/x/.medical/sub/dir/notes") is False


def test_single_star_does_not_cross_separator():
    g = _guard(paths_denied=["/home/*/x"])
    assert g.check_path("/home/a/b/x") is True  # * must not span a/b


def test_glob_question_and_literal_dot():
    rx = _glob_to_regex("a?c.txt")
    assert rx.match("abc.txt")
    assert not rx.match("ac.txt")  # ? requires exactly one char
    assert not rx.match("abcXtxt")  # '.' is a literal, not a wildcard


@pytest.mark.skipif(os.name != "nt", reason="Windows path matching behavior")
def test_windows_path_matching_is_case_insensitive(tmp_path: Path):
    denied = (tmp_path / "Secrets" / "Inventory.JSON").as_posix().upper()
    candidate = tmp_path / "secrets" / "inventory.json"
    assert _guard(paths_denied=[denied]).check_path(candidate) is False


# --- time windows (SCOPE-12..15) ---------------------------------------------

NY_WINDOW = {
    "days": ["mon", "tue", "wed", "thu", "fri"],
    "start": "09:00",
    "end": "17:00",
    "tz": "America/New_York",
}


@freeze_time("2026-06-01 14:00:00")  # Monday, 10:00 EDT
def test_scope12_inside_window_allows():
    assert _guard(time_windows=[NY_WINDOW]).check_time() is True


@freeze_time("2026-06-01 12:30:00")  # Monday, 08:30 EDT — before open
def test_scope14_timezone_respected():
    assert _guard(time_windows=[NY_WINDOW]).check_time() is False


@freeze_time("2026-06-06 14:00:00")  # Saturday
def test_scope15_day_of_week_gating():
    assert _guard(time_windows=[NY_WINDOW]).check_time() is False


def test_check_time_no_windows_always_allows():
    assert _guard().check_time() is True


# --- TimeWindow unit coverage ------------------------------------------------

def test_timewindow_wraps_past_midnight():
    w = TimeWindow(days=["mon"], start="22:00", end="02:00", tz="UTC")
    assert w.contains(datetime(2026, 6, 1, 23, 0, tzinfo=UTC)) is True
    assert w.contains(datetime(2026, 6, 2, 1, 0, tzinfo=UTC)) is True
    assert w.contains(datetime(2026, 6, 1, 1, 0, tzinfo=UTC)) is False
    assert w.contains(datetime(2026, 6, 1, 22, 0, tzinfo=UTC)) is True
    assert w.contains(datetime(2026, 6, 2, 2, 0, tzinfo=UTC)) is True
    assert w.contains(datetime(2026, 6, 1, 12, 0, tzinfo=UTC)) is False


def test_check_time_rechecks_expiry_after_guard_construction():
    scope = _scope(authorized_until="2026-06-01T12:00:00Z")
    guard = ScopeGuard(scope, now=datetime(2026, 6, 1, 11, 0, tzinfo=UTC))
    assert guard.check_time(datetime(2026, 6, 1, 12, 0, tzinfo=UTC)) is True
    assert guard.check_time(datetime(2026, 6, 1, 12, 0, 1, tzinfo=UTC)) is False


def test_timewindow_bad_day():
    with pytest.raises(ValidationError):
        TimeWindow(days=["funday"], start="09:00", end="17:00")


def test_timewindow_bad_clock_format():
    with pytest.raises(ValidationError):
        TimeWindow(days=["mon"], start="9am", end="17:00")


def test_timewindow_clock_out_of_range():
    with pytest.raises(ValidationError):
        TimeWindow(days=["mon"], start="25:00", end="17:00")


def test_timewindow_bad_tz():
    with pytest.raises(ValidationError):
        TimeWindow(days=["mon"], start="09:00", end="17:00", tz="Mars/Phobos")


def test_parse_clock_ok():
    assert _parse_clock("09:30").hour == 9


# --- enforcement wiring (SCOPE-17, SCOPE-18) ---------------------------------

@pytest.fixture
def fake_home(tmp_path: Path) -> Path:
    """A minimal home tree with an AWS credentials file the collector will see."""
    aws = tmp_path / ".aws"
    aws.mkdir()
    (aws / "credentials").write_text("[default]\n[work]\n")
    return tmp_path


def test_scope17_denied_provider_yields_no_node_or_edge(fake_home: Path):
    guard = _guard(providers_denied=["aws"])
    collector = LocalCollector(home=fake_home, hostname="host", guard=guard)
    result = collector.collect()
    aws_nodes = [n for n in result.nodes if n.properties.get("provider") == "aws"]
    assert aws_nodes == []
    aws_ids = {n.objectid for n in aws_nodes}
    assert not any(e.source_id in aws_ids or e.target_id in aws_ids for e in result.edges)


def test_unscoped_run_sees_the_provider(fake_home: Path):
    # Control: without a guard the same scan emits the aws NHI.
    result = LocalCollector(home=fake_home, hostname="host").collect()
    assert any(n.properties.get("provider") == "aws" for n in result.nodes)


def _local_factory(home: Path, tmp_path: Path, guard) -> LocalCollector:
    return LocalCollector(home=home, hostname="host", guard=guard)


def _mcp_factory(home: Path, tmp_path: Path, guard) -> MCPCollector:
    inv = tmp_path / "inv.yaml"
    inv.write_text(
        "servers:\n  - name: sf\n    provider: salesforce\n"
        "    tools:\n      - name: q\n        classification: [query_runner]\n"
    )
    return MCPCollector(inventory_path=inv, guard=guard)


@pytest.mark.parametrize("factory", [_local_factory, _mcp_factory])
def test_scope18_collectors_consult_guard(factory, fake_home: Path, tmp_path: Path):
    guard = MagicMock()
    guard.check_provider.return_value = True
    guard.check_path.return_value = True
    factory(fake_home, tmp_path, guard).collect()
    assert guard.check_provider.called


def test_mcp_inventory_path_is_denied_before_read(tmp_path: Path, monkeypatch):
    inventory = tmp_path / "secret_inventory.yaml"
    guard = _guard(paths_denied=[inventory.as_posix()])

    def forbidden_read(*args, **kwargs):
        raise AssertionError("denied inventory was read")

    monkeypatch.setattr(Path, "read_text", forbidden_read)
    result = MCPCollector(inventory_path=inventory, guard=guard).collect()
    assert result.nodes == [] and result.edges == []


def test_local_mcp_config_is_denied_before_read(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    config = home / ".config" / "Claude" / "claude_desktop_config.json"
    config.parent.mkdir(parents=True)
    config.write_text('{"mcpServers": {"github": {}}}')
    collector = LocalCollector(
        home=home,
        hostname="host",
        guard=_guard(paths_denied=[config.as_posix()]),
    )
    original_read = Path.read_text

    def guarded_read(path, *args, **kwargs):
        if path == config:
            raise AssertionError("denied MCP config was read")
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read)
    result = collector.collect()
    assert not any(node.kind.value == "MCPServer" for node in result.nodes)


def test_denied_agent_install_path_does_not_emit_agent(tmp_path: Path):
    install = tmp_path / ".cursor"
    install.mkdir()
    result = LocalCollector(
        home=tmp_path,
        hostname="host",
        guard=_guard(paths_denied=[install.as_posix()]),
    ).collect()
    assert not any(
        node.properties.get("kind_detail") == "cursor" for node in result.nodes
    )


def test_mcp_nested_providers_are_independently_gated(tmp_path: Path):
    inventory = tmp_path / "inventory.yaml"
    inventory.write_text(
        """servers:
  - name: denied-backing
    provider: mcp-platform
    tools: [query]
    backing_nhi: {provider: aws, identifier: prod-role}
  - name: denied-resource
    provider: mcp-platform
    backing_nhi: {provider: gcp, identifier: svc}
    accessible_resources:
      - {provider: aws, kind: s3_bucket, identifier: prod-data}
"""
    )
    result = MCPCollector(
        inventory_path=inventory,
        guard=_guard(providers_denied=["aws"]),
    ).collect()

    assert any(node.kind.value == "MCPServer" for node in result.nodes)
    assert not any(node.properties.get("provider") == "aws" for node in result.nodes)


@pytest.mark.parametrize(
    ("collector_cls", "provider"),
    [
        (AWSIAMCollector, "aws"),
        (GCPIAMCollector, "gcp"),
        (AzureRBACCollector, "azure"),
    ],
)
def test_cloud_provider_denial_happens_before_read(collector_cls, provider, tmp_path: Path):
    missing = tmp_path / f"{provider}.json"
    result = collector_cls(
        missing,
        guard=_guard(providers_denied=[provider]),
    ).collect()
    assert result.nodes == [] and result.edges == []


@pytest.mark.parametrize(
    ("collector_cls", "provider"),
    [
        (AWSIAMCollector, "aws"),
        (GCPIAMCollector, "gcp"),
        (AzureRBACCollector, "azure"),
    ],
)
def test_cloud_path_denial_happens_before_read(collector_cls, provider, tmp_path: Path):
    missing = tmp_path / f"{provider}.json"
    result = collector_cls(
        missing,
        guard=_guard(paths_denied=[missing.as_posix()]),
    ).collect()
    assert result.nodes == [] and result.edges == []


# --- CLI activation gates (SCOPE-04 / SCOPE-13 startup behavior) -------------

def _write_scope(path: Path, *, audit_log: str | None = None, windows=None) -> Path:
    lines = ["engagement: e", f'authorized_until: "{FUTURE}"']
    if audit_log is not None:
        # Single-quote so Windows backslashes aren't read as YAML escapes.
        lines.append(f"audit_log: '{audit_log}'")
    if windows:
        lines.append("time_windows:")
        lines.append("  - days: [mon, tue, wed, thu, fri]")
        lines.append('    start: "09:00"')
        lines.append('    end: "17:00"')
        lines.append("    tz: America/New_York")
    path.write_text("\n".join(lines) + "\n")
    return path


def test_activate_no_scope_is_noop():
    from agenthound.cli import _activate_scope

    assert _activate_scope(None) == (None, None)


def test_scope04_cli_expired_aborts():
    from agenthound.cli import _activate_scope

    with pytest.raises(click.ClickException):
        _activate_scope(FIXTURES / "scope_expired.yaml")


def test_activate_malformed_scope_aborts(tmp_path: Path):
    # A scope file that fails validation must abort cleanly, not traceback.
    from agenthound.cli import _activate_scope

    bad = tmp_path / "bad.yaml"
    bad.write_text("engagement: x\nauthorized_until: not-a-date\n")
    with pytest.raises(click.ClickException):
        _activate_scope(bad)


@freeze_time("2026-06-06 14:00:00")  # Saturday — outside the window
def test_scope13_outside_window_refuses_and_audits(tmp_path: Path, monkeypatch):
    from agenthound.cli import _activate_scope

    audit_path = tmp_path / "audit.jsonl"
    scope_yaml = _write_scope(
        tmp_path / "scope.yaml", audit_log=str(audit_path), windows=True
    )
    monkeypatch.setenv("AGENTHOUND_AUDIT_KEY", "k")
    with pytest.raises(click.ClickException):
        _activate_scope(scope_yaml)
    entries = [json.loads(ln) for ln in audit_path.read_text().splitlines() if ln.strip()]
    assert any(e["decision"] == "SKIPPED" for e in entries)


def test_audit09_missing_key_refuses(tmp_path: Path, monkeypatch):
    from agenthound.cli import _activate_scope

    monkeypatch.delenv("AGENTHOUND_AUDIT_KEY", raising=False)
    scope_yaml = _write_scope(tmp_path / "scope.yaml", audit_log=str(tmp_path / "a.jsonl"))
    with pytest.raises(click.ClickException):
        _activate_scope(scope_yaml)


@freeze_time("2026-06-01 14:00:00")  # Monday, in-window
def test_audit10_skipped_entry_recorded_on_denied_provider(fake_home: Path, tmp_path: Path):
    from agenthound.audit import AuditLog

    audit_path = tmp_path / "audit.jsonl"
    audit = AuditLog(audit_path, "k")
    guard = _guard(providers_denied=["aws"])
    LocalCollector(home=fake_home, hostname="host", guard=guard, audit=audit).collect()
    entries = [json.loads(ln) for ln in audit_path.read_text().splitlines() if ln.strip()]
    assert any(e["decision"] == "SKIPPED" and "aws" in e["reason"] for e in entries)


def test_allowed_scope_decisions_are_audited(fake_home: Path, tmp_path: Path):
    from agenthound.audit import AuditLog

    audit_path = tmp_path / "audit.jsonl"
    LocalCollector(
        home=fake_home,
        hostname="host",
        guard=_guard(),
        audit=AuditLog(audit_path, "k"),
    ).collect()
    entries = [json.loads(line) for line in audit_path.read_text().splitlines()]
    assert any(entry["decision"] == "ALLOW" for entry in entries)
