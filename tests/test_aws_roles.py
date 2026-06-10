"""Phase 2a — local AWS assume-role topology (CAN_ASSUME).

The local collector reads ``~/.aws/config``'s assume-role wiring (``role_arn`` +
``source_profile``) and emits the role as its own NHI plus a ``CAN_ASSUME`` edge
from the source profile's NHI. Topology only, no secret values, purely additive
— existing profile NHIs are unchanged.
"""

from __future__ import annotations

from pathlib import Path

from agenthound.cli import _result_from_json
from agenthound.collectors.local import (
    LocalCollector,
    _aws_assume_roles,
    _parse_role_arn,
)
from agenthound.schema import build_payload
from agenthound.schema.edges import PermissionEdgeKind
from agenthound.schema.nodes import nhi_node
from agenthound.scope import EngagementScope, ScopeGuard

CONFIG = """\
[default]
region = us-east-1

[profile prod-readonly]
role_arn = arn:aws:iam::111122223333:role/ReadOnlyAuditor
source_profile = default

[profile prod-admin]
role_arn = arn:aws:iam::111122223333:role/team/OrgAdmin
source_profile = default
mfa_serial = arn:aws:iam::111122223333:mfa/alice
"""


def _home_with_config(tmp_path: Path, config: str = CONFIG) -> Path:
    home = tmp_path / "home"
    aws = home / ".aws"
    aws.mkdir(parents=True)
    (aws / "config").write_text(config)
    (aws / "credentials").write_text("[default]\n")
    return home


def _collect(tmp_path: Path, config: str = CONFIG, guard=None):
    return LocalCollector(
        home=_home_with_config(tmp_path, config), hostname="host", guard=guard
    ).collect()


def _roles(nodes):
    return [n for n in nodes if n.properties.get("nhi_type") == "assumed_role"]


def _can_assume(edges):
    return [e for e in edges if e.kind == PermissionEdgeKind.CAN_ASSUME]


# --- ARN parsing -------------------------------------------------------------

def test_parse_role_arn_basic():
    assert _parse_role_arn("arn:aws:iam::111122223333:role/OrgAdmin") == (
        "111122223333", "OrgAdmin", "aws",
    )


def test_parse_role_arn_with_path():
    assert _parse_role_arn("arn:aws:iam::111122223333:role/team/sub/Admin") == (
        "111122223333", "Admin", "aws",
    )


def test_parse_role_arn_govcloud_partition():
    assert _parse_role_arn("arn:aws-us-gov:iam::999:role/X") == ("999", "X", "aws-us-gov")


def test_parse_role_arn_rejects_non_role():
    assert _parse_role_arn("arn:aws:s3:::my-bucket") == (None, None, None)
    assert _parse_role_arn("not-an-arn") == (None, None, None)


# --- config parsing ----------------------------------------------------------

def test_aws_assume_roles_parses(tmp_path: Path):
    p = tmp_path / "config"
    p.write_text(CONFIG)
    by_profile = {e["profile"]: e for e in _aws_assume_roles(p)}
    # [default] declares no role_arn, so it is not an assume-role entry.
    assert set(by_profile) == {"prod-readonly", "prod-admin"}
    assert by_profile["prod-readonly"]["source_profile"] == "default"
    assert "mfa_serial" not in by_profile["prod-readonly"]
    assert by_profile["prod-admin"]["mfa_serial"].endswith("mfa/alice")


def test_aws_assume_roles_missing_file(tmp_path: Path):
    assert _aws_assume_roles(tmp_path / "nope") == []


# --- emission ----------------------------------------------------------------

def test_collector_emits_role_nhi_and_can_assume(tmp_path: Path):
    result = _collect(tmp_path)
    roles = _roles(result.nodes)
    assert {r.properties.get("role_name") for r in roles} == {"ReadOnlyAuditor", "OrgAdmin"}
    assert len(_can_assume(result.edges)) == 2
    for r in roles:
        assert r.properties["account_id"] == "111122223333"
        assert r.properties["provider"] == "aws"
        assert "partition" not in r.properties  # standard aws partition is implicit


def test_can_assume_joins_existing_profile_nhi(tmp_path: Path):
    result = _collect(tmp_path)
    default_nhi = nhi_node(provider="aws", identifier="default", nhi_type="aws_profile")
    assert default_nhi.objectid in {n.objectid for n in result.nodes}
    assert all(e.source_id == default_nhi.objectid for e in _can_assume(result.edges))


def test_requires_mfa_recorded(tmp_path: Path):
    result = _collect(tmp_path)
    by_node = {n.objectid: n for n in result.nodes}
    mfa_by_role = {
        by_node[e.target_id].properties["role_name"]: e.properties["requires_mfa"]
        for e in _can_assume(result.edges)
    }
    assert mfa_by_role["OrgAdmin"] is True
    assert mfa_by_role["ReadOnlyAuditor"] is False


def test_credential_source_only_role_skipped(tmp_path: Path):
    # A role assumed from instance metadata has no local source profile to anchor
    # the edge, so this slice skips it rather than emit an orphan.
    config = (
        "[profile ec2]\n"
        "role_arn = arn:aws:iam::111122223333:role/InstanceRole\n"
        "credential_source = Ec2InstanceMetadata\n"
    )
    result = _collect(tmp_path, config=config)
    assert _roles(result.nodes) == []
    assert _can_assume(result.edges) == []


# --- scope -------------------------------------------------------------------

def _deny_aws_guard() -> ScopeGuard:
    return ScopeGuard(
        EngagementScope.model_validate(
            {
                "engagement": "t",
                "authorized_until": "2099-01-01T00:00:00Z",
                "providers_denied": ["aws"],
            }
        )
    )


def test_scope_deny_aws_suppresses_roles(tmp_path: Path):
    result = _collect(tmp_path, guard=_deny_aws_guard())
    assert _roles(result.nodes) == []
    assert _can_assume(result.edges) == []


# --- behaviour preservation --------------------------------------------------

def test_no_role_arn_means_no_can_assume_edges(tmp_path: Path):
    config = "[default]\nregion = us-east-1\n\n[profile work]\nregion = us-west-2\n"
    result = _collect(tmp_path, config=config)
    assert _can_assume(result.edges) == []
    assert _roles(result.nodes) == []
    # The plain profile NHIs are still emitted exactly as before.
    profiles = {
        n.properties.get("identifier")
        for n in result.nodes
        if n.properties.get("nhi_type") == "aws_profile"
    }
    assert {"default", "work"} <= profiles


# --- round-trip --------------------------------------------------------------

def test_can_assume_survives_emit_roundtrip(tmp_path: Path):
    result = _collect(tmp_path)
    payload = build_payload(result.nodes, result.edges).to_dict()
    restored = _result_from_json(payload)
    assert any(e.kind == PermissionEdgeKind.CAN_ASSUME for e in restored.edges)


def test_govcloud_role_records_partition(tmp_path: Path):
    # A non-aws partition (gov/cn) is an isolation boundary worth surfacing.
    config = (
        "[profile gov]\n"
        "role_arn = arn:aws-us-gov:iam::1:role/GovAdmin\n"
        "source_profile = default\n"
    )
    role = _roles(_collect(tmp_path, config=config).nodes)[0]
    assert role.properties.get("partition") == "aws-us-gov"
