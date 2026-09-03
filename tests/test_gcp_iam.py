"""GCP IAM policy resolver (real permissions, upload-only).

The ``gcp`` collector ingests a ``gcloud asset search-all-iam-policies`` JSON
export (a file the operator uploads — AgentHound never calls GCP) and emits
members as NHIs, the resources their bindings grant, evidence-based admin flags
(``roles/owner``), and ``CAN_ASSUME`` edges for service-account impersonation.
Admin-ness comes from the role id, never from a member or role name.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from agenthound.cli import main
from agenthound.collectors.gcp_iam import (
    GCPIAMCollector,
    _parse_member,
    _resource_kind,
    _service_account_from_resource,
)
from agenthound.schema import build_payload
from agenthound.schema.edges import PermissionEdgeKind
from agenthound.schema.nodes import NodeKind, nhi_node
from agenthound.scope import EngagementScope, ScopeGuard

EXAMPLE = Path(__file__).parent.parent / "examples" / "gcp_iam_policies.example.json"


def _collect(tmp_path: Path, data, guard=None):
    p = tmp_path / "gcp.json"
    p.write_text(json.dumps(data))
    return GCPIAMCollector(p, guard=guard).collect()


def _members(nodes) -> dict:
    # Rich member nodes carry principal_name; impersonation-target placeholders
    # and Resource nodes do not.
    return {n.properties["principal_name"]: n for n in nodes if "principal_name" in n.properties}


def _grants(edges):
    return [e for e in edges if e.kind == PermissionEdgeKind.GRANTS_ACCESS]


def _can_assume(edges):
    return [e for e in edges if e.kind == PermissionEdgeKind.CAN_ASSUME]


# --- helpers -----------------------------------------------------------------

def test_parse_member_forms():
    assert _parse_member("user:a@b.com") == ("a@b.com", "gcp_user")
    assert _parse_member("serviceAccount:sa@p.iam.gserviceaccount.com") == (
        "sa@p.iam.gserviceaccount.com",
        "gcp_service_account",
    )
    assert _parse_member("group:eng@b.com") == ("eng@b.com", "gcp_group")
    assert _parse_member("allUsers") == ("allUsers", "gcp_public")
    # deleted principals keep their identifier, drop the ?uid= suffix
    assert _parse_member("deleted:user:gone@b.com?uid=123") == ("gone@b.com", "gcp_user")
    assert _parse_member("serviceAccount:") is None


def test_resource_kind_and_sa_extraction():
    assert _resource_kind("//cloudresourcemanager.googleapis.com/projects/p") == "project"
    assert _resource_kind("//cloudresourcemanager.googleapis.com/folders/123") == "folder"
    assert _resource_kind("//storage.googleapis.com/projects/_/buckets/b") == "storage"
    sa = _service_account_from_resource(
        "//iam.googleapis.com/projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com"
    )
    assert sa == "sa@p.iam.gserviceaccount.com"
    no_sa = _service_account_from_resource("//cloudresourcemanager.googleapis.com/projects/p")
    assert no_sa is None


# --- members -----------------------------------------------------------------

def test_export_emits_members():
    members = _members(GCPIAMCollector(EXAMPLE).collect().nodes)
    assert set(members) == {
        "ci-deployer@acme-prod.iam.gserviceaccount.com",
        "auditor@example.com",
        "dev@example.com",
    }
    assert members["ci-deployer@acme-prod.iam.gserviceaccount.com"].properties["nhi_type"] == (
        "gcp_service_account"
    )
    assert members["auditor@example.com"].properties["nhi_type"] == "gcp_user"


# --- evidence-based admin (names are not verdicts) ---------------------------

def test_owner_is_full_access():
    members = _members(GCPIAMCollector(EXAMPLE).collect().nodes)
    assert members["ci-deployer@acme-prod.iam.gserviceaccount.com"].properties[
        "grants_full_access"
    ] is True
    assert members["auditor@example.com"].properties["grants_full_access"] is False
    assert members["dev@example.com"].properties["grants_full_access"] is False


def test_full_access_is_role_id_independent(tmp_path: Path):
    data = [
        {
            "resource": "//cloudresourcemanager.googleapis.com/projects/p",
            "policy": {
                "bindings": [
                    # A custom role that *sounds* like admin is NOT roles/owner.
                    {
                        "role": "projects/p/roles/superDuperAdmin",
                        "members": ["user:loud@b.com"],
                    },
                    # A blandly-named member with the actual owner role IS admin.
                    {"role": "roles/owner", "members": ["user:quiet@b.com"]},
                ]
            },
        }
    ]
    members = _members(_collect(tmp_path, data).nodes)
    assert members["loud@b.com"].properties["grants_full_access"] is False
    assert members["quiet@b.com"].properties["grants_full_access"] is True


# --- resources / GrantsAccess ------------------------------------------------

def test_grants_access_to_resource():
    result = GCPIAMCollector(EXAMPLE).collect()
    auditor = _members(result.nodes)["auditor@example.com"]
    granted = {e.target_id for e in _grants(result.edges) if e.source_id == auditor.objectid}
    bucket = next(
        n for n in result.nodes if n.kind == NodeKind.RESOURCE and "acme-prod-data" in n.name
    )
    project = next(
        n for n in result.nodes if n.kind == NodeKind.RESOURCE and n.name.endswith("acme-prod")
    )
    assert bucket.objectid in granted
    assert bucket.properties["resource_kind"] == "storage"
    assert project.properties["resource_kind"] == "project"


# --- CAN_ASSUME via service-account impersonation ----------------------------

def test_impersonation_emits_can_assume():
    result = GCPIAMCollector(EXAMPLE).collect()
    members = _members(result.nodes)
    dev = members["dev@example.com"]
    ci_deployer = members["ci-deployer@acme-prod.iam.gserviceaccount.com"]
    assumable = {e.target_id for e in _can_assume(result.edges) if e.source_id == dev.objectid}
    # dev can impersonate the ci-deployer SA, which is roles/owner — escalation.
    assert ci_deployer.objectid in assumable


def test_impersonation_target_joins_member_node():
    # The SA is keyed on its email both as a grantee and as the impersonation
    # target resource, so the CAN_ASSUME target is the same node as the member.
    result = GCPIAMCollector(EXAMPLE).collect()
    target = nhi_node(
        provider="gcp",
        identifier="ci-deployer@acme-prod.iam.gserviceaccount.com",
        nhi_type="gcp_service_account",
    )
    member = _members(result.nodes)["ci-deployer@acme-prod.iam.gserviceaccount.com"]
    assert target.objectid == member.objectid


def test_impersonated_sa_keeps_full_access_after_emit():
    # ci-deployer is both an owner grantee and an impersonation target (so a
    # placeholder node shares its objectid). After build_payload's later-wins
    # merge, the rich grantee node must win: grants_full_access stays true.
    result = GCPIAMCollector(EXAMPLE).collect()
    payload = build_payload(result.nodes, result.edges).to_dict()
    sa = next(
        n
        for n in payload["graph"]["nodes"]
        if n["properties"].get("principal_name")
        == "ci-deployer@acme-prod.iam.gserviceaccount.com"
    )
    assert sa["properties"]["grants_full_access"] is True


# --- alternate input shapes --------------------------------------------------

def test_results_wrapper_accepted(tmp_path: Path):
    data = {
        "results": [
            {
                "resource": "//cloudresourcemanager.googleapis.com/projects/p",
                "policy": {"bindings": [{"role": "roles/owner", "members": ["user:a@b.com"]}]},
            }
        ]
    }
    members = _members(_collect(tmp_path, data).nodes)
    assert members["a@b.com"].properties["grants_full_access"] is True


def test_bare_policy_document_warns_and_skips_grants(tmp_path: Path):
    data = {"bindings": [{"role": "roles/owner", "members": ["user:a@b.com"]}]}
    result = _collect(tmp_path, data)
    members = _members(result.nodes)
    assert members["a@b.com"].properties["grants_full_access"] is True
    assert _grants(result.edges) == []  # no resource name in a bare document
    assert any("get-iam-policy" in w for w in result.warnings)


# --- scope -------------------------------------------------------------------

def test_scope_deny_gcp_yields_nothing():
    guard = ScopeGuard(
        EngagementScope.model_validate(
            {
                "engagement": "t",
                "authorized_until": "2099-01-01T00:00:00Z",
                "providers_denied": ["gcp"],
            }
        )
    )
    result = GCPIAMCollector(EXAMPLE, guard=guard).collect()
    assert result.nodes == []
    assert result.edges == []


# --- fail-soft CLI -----------------------------------------------------------

def test_malformed_export_raises_clickexception(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ not valid json")
    res = CliRunner().invoke(main, ["gcp", "-i", str(bad)])
    assert res.exit_code != 0
    assert "Could not read GCP IAM export" in res.output


def test_non_container_root_raises_clickexception(tmp_path: Path):
    bad = tmp_path / "scalar.json"
    bad.write_text("42")
    res = CliRunner().invoke(main, ["gcp", "-i", str(bad)])
    assert res.exit_code != 0
    assert "Could not read GCP IAM export" in res.output


def test_cli_writes_graph(tmp_path: Path):
    out = tmp_path / "gcp_graph.json"
    res = CliRunner().invoke(main, ["gcp", "-i", str(EXAMPLE), "-o", str(out)])
    assert res.exit_code == 0, res.output
    payload = json.loads(out.read_text())
    assert payload["graph"]["nodes"] and payload["graph"]["edges"]


# --- schema gate -------------------------------------------------------------

def test_emitted_payload_validates(node_schema, edge_schema):
    jsonschema = pytest.importorskip("jsonschema")
    result = GCPIAMCollector(EXAMPLE).collect()
    payload = build_payload(result.nodes, result.edges).to_dict()
    for n in payload["graph"]["nodes"]:
        jsonschema.validate(n, node_schema)
    for e in payload["graph"]["edges"]:
        jsonschema.validate(e, edge_schema)
