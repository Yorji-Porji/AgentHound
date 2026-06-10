"""Phase 2b — AWS IAM export resolver (real permissions, upload-only).

The ``aws-iam`` collector ingests an ``aws iam get-account-authorization-details``
JSON export (a file the operator uploads — AgentHound never calls AWS) and emits
identities, the resources their policies grant, evidence-based admin flags, and
CAN_ASSUME edges from role trust policies. Admin-ness comes from policy *content*,
never from a role's name.
"""

from __future__ import annotations

import json
import urllib.parse
from pathlib import Path

import pytest
from click.testing import CliRunner

from agenthound.cli import main
from agenthound.collectors.aws_iam import AWSIAMCollector, _as_document, _is_full_access
from agenthound.schema import build_payload
from agenthound.schema.edges import PermissionEdgeKind
from agenthound.schema.nodes import NodeKind, nhi_node
from agenthound.scope import EngagementScope, ScopeGuard

EXAMPLE = Path(__file__).parent.parent / "examples" / "aws_iam_export.example.json"


def _collect(tmp_path: Path, data: dict, guard=None):
    p = tmp_path / "iam.json"
    p.write_text(json.dumps(data))
    return AWSIAMCollector(p, guard=guard).collect()


def _principals(nodes) -> dict:
    return {
        n.properties.get("principal_name"): n
        for n in nodes
        if n.properties.get("nhi_type") in {"iam_user", "iam_role"}
    }


def _grants(edges):
    return [e for e in edges if e.kind == PermissionEdgeKind.GRANTS_ACCESS]


def _can_assume(edges):
    return [e for e in edges if e.kind == PermissionEdgeKind.CAN_ASSUME]


# --- helpers -----------------------------------------------------------------

def test_is_full_access_helper():
    assert _is_full_access({"Effect": "Allow", "Action": "*", "Resource": "*"})
    assert not _is_full_access({"Effect": "Allow", "Action": "s3:*", "Resource": "*"})
    assert not _is_full_access({"Effect": "Deny", "Action": "*", "Resource": "*"})


def test_as_document_dict_string_and_garbage():
    assert _as_document({"a": 1}) == {"a": 1}
    assert _as_document("not a document") is None
    assert _as_document(123) is None


# --- principals --------------------------------------------------------------

def test_export_emits_principals():
    result = AWSIAMCollector(EXAMPLE).collect()
    principals = _principals(result.nodes)
    assert set(principals) == {"ci-deployer", "OrgAdmin", "ReadOnlyAuditor"}
    assert principals["ci-deployer"].properties["nhi_type"] == "iam_user"
    assert principals["OrgAdmin"].properties["nhi_type"] == "iam_role"
    assert principals["OrgAdmin"].properties["account_id"] == "111122223333"


# --- evidence-based admin (names are not verdicts) ---------------------------

def test_admin_by_managed_policy_arn():
    principals = _principals(AWSIAMCollector(EXAMPLE).collect().nodes)
    assert principals["OrgAdmin"].properties["grants_full_access"] is True


def test_admin_by_inline_wildcard():
    principals = _principals(AWSIAMCollector(EXAMPLE).collect().nodes)
    assert principals["ci-deployer"].properties["grants_full_access"] is True


def test_admin_is_name_independent(tmp_path: Path):
    data = {
        "RoleDetailList": [
            {
                "RoleName": "totally-not-admin",
                "Arn": "arn:aws:iam::1:role/totally-not-admin",
                "AttachedManagedPolicies": [
                    {
                        "PolicyName": "AdministratorAccess",
                        "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    }
                ],
            },
            {
                "RoleName": "AdminSupreme",
                "Arn": "arn:aws:iam::1:role/AdminSupreme",
                "RolePolicyList": [
                    {
                        "PolicyName": "p",
                        "PolicyDocument": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "s3:GetObject",
                                    "Resource": "arn:aws:s3:::b/*",
                                }
                            ]
                        },
                    }
                ],
            },
        ]
    }
    principals = _principals(_collect(tmp_path, data).nodes)
    # The name says "not admin" but the policy says admin — policy wins.
    assert principals["totally-not-admin"].properties["grants_full_access"] is True
    # The name screams admin but the policy is just one read action — not admin.
    assert principals["AdminSupreme"].properties["grants_full_access"] is False


# --- resources / GrantsAccess ------------------------------------------------

def test_scoped_role_grants_access_to_resource():
    result = AWSIAMCollector(EXAMPLE).collect()
    auditor = _principals(result.nodes)["ReadOnlyAuditor"]
    assert auditor.properties["grants_full_access"] is False
    granted = {e.target_id for e in _grants(result.edges) if e.source_id == auditor.objectid}
    bucket = next(
        n for n in result.nodes if n.kind == NodeKind.RESOURCE and "acme-prod-data" in n.name
    )
    assert bucket.objectid in granted
    assert bucket.properties["resource_kind"] == "s3"


def test_wildcard_resource_emitted():
    result = AWSIAMCollector(EXAMPLE).collect()
    wildcards = [
        n
        for n in result.nodes
        if n.kind == NodeKind.RESOURCE and n.properties.get("wildcard")
    ]
    assert wildcards and wildcards[0].properties["resource_kind"] == "*"


# --- CAN_ASSUME from trust policies ------------------------------------------

def test_can_assume_from_trust_policy():
    result = AWSIAMCollector(EXAMPLE).collect()
    principals = _principals(result.nodes)
    deployer = principals["ci-deployer"]
    assumable = {e.target_id for e in _can_assume(result.edges) if e.source_id == deployer.objectid}
    assert principals["OrgAdmin"].objectid in assumable
    assert principals["ReadOnlyAuditor"].objectid in assumable


def test_role_nhi_joins_local_assumed_role():
    # The export keys a role NHI on its ARN — the same key the local collector
    # uses for its assumed_role NHI — so the two views are one node.
    result = AWSIAMCollector(EXAMPLE).collect()
    org_admin = _principals(result.nodes)["OrgAdmin"]
    local_role = nhi_node(
        provider="aws",
        identifier="arn:aws:iam::111122223333:role/OrgAdmin",
        nhi_type="assumed_role",
    )
    assert org_admin.objectid == local_role.objectid


# --- url-encoded documents ---------------------------------------------------

def test_url_encoded_policy_document(tmp_path: Path):
    doc = urllib.parse.quote(
        json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    )
    data = {
        "RoleDetailList": [
            {
                "RoleName": "r",
                "Arn": "arn:aws:iam::1:role/r",
                "RolePolicyList": [{"PolicyName": "p", "PolicyDocument": doc}],
            }
        ]
    }
    principals = _principals(_collect(tmp_path, data).nodes)
    assert principals["r"].properties["grants_full_access"] is True


# --- scope -------------------------------------------------------------------

def test_scope_deny_aws_yields_nothing():
    guard = ScopeGuard(
        EngagementScope.model_validate(
            {
                "engagement": "t",
                "authorized_until": "2099-01-01T00:00:00Z",
                "providers_denied": ["aws"],
            }
        )
    )
    result = AWSIAMCollector(EXAMPLE, guard=guard).collect()
    assert result.nodes == []
    assert result.edges == []


# --- fail-soft CLI -----------------------------------------------------------

def test_malformed_export_raises_clickexception(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ not valid json")
    res = CliRunner().invoke(main, ["aws-iam", "-i", str(bad)])
    assert res.exit_code != 0
    assert "Could not read AWS IAM export" in res.output


def test_non_object_root_raises_clickexception(tmp_path: Path):
    bad = tmp_path / "list.json"
    bad.write_text("[1, 2, 3]")
    res = CliRunner().invoke(main, ["aws-iam", "-i", str(bad)])
    assert res.exit_code != 0
    assert "Could not read AWS IAM export" in res.output


def test_cli_writes_graph(tmp_path: Path):
    out = tmp_path / "iam_graph.json"
    res = CliRunner().invoke(main, ["aws-iam", "-i", str(EXAMPLE), "-o", str(out)])
    assert res.exit_code == 0, res.output
    payload = json.loads(out.read_text())
    assert payload["graph"]["nodes"] and payload["graph"]["edges"]


# --- schema gate -------------------------------------------------------------

def test_emitted_payload_validates(node_schema, edge_schema):
    jsonschema = pytest.importorskip("jsonschema")
    result = AWSIAMCollector(EXAMPLE).collect()
    payload = build_payload(result.nodes, result.edges).to_dict()
    for n in payload["graph"]["nodes"]:
        jsonschema.validate(n, node_schema)
    for e in payload["graph"]["edges"]:
        jsonschema.validate(e, edge_schema)


# --- managed-policy resolution + edge cases ----------------------------------

def test_managed_policy_default_version_resolved(tmp_path: Path):
    # A role attaches a customer-managed policy. Its v1 grants *:* but v2 (the
    # default) is scoped — the resolver must read the DEFAULT version only.
    data = {
        "RoleDetailList": [
            {
                "RoleName": "app",
                "Arn": "arn:aws:iam::1:role/app",
                "AttachedManagedPolicies": [
                    {"PolicyName": "team", "PolicyArn": "arn:aws:iam::1:policy/team"}
                ],
            }
        ],
        "Policies": [
            {
                "PolicyName": "team",
                "Arn": "arn:aws:iam::1:policy/team",
                "DefaultVersionId": "v2",
                "PolicyVersionList": [
                    {
                        "VersionId": "v1",
                        "IsDefaultVersion": False,
                        "Document": {
                            "Statement": [
                                {"Effect": "Allow", "Action": "*", "Resource": "*"}
                            ]
                        },
                    },
                    {
                        "VersionId": "v2",
                        "IsDefaultVersion": True,
                        "Document": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "dynamodb:GetItem",
                                    "Resource": "arn:aws:dynamodb:us-east-1:1:table/Orders",
                                }
                            ]
                        },
                    },
                ],
            }
        ],
    }
    result = _collect(tmp_path, data)
    app = _principals(result.nodes)["app"]
    # The default (v2) is scoped, so the role is NOT admin despite v1's wildcard.
    assert app.properties["grants_full_access"] is False
    granted_ids = {e.target_id for e in _grants(result.edges) if e.source_id == app.objectid}
    granted = [n for n in result.nodes if n.kind == NodeKind.RESOURCE and n.objectid in granted_ids]
    assert any("Orders" in n.name for n in granted)
    assert any(n.properties.get("resource_kind") == "dynamodb" for n in granted)


def test_principal_without_arn_skipped(tmp_path: Path):
    result = _collect(tmp_path, {"RoleDetailList": [{"RoleName": "noarn"}]})
    assert _principals(result.nodes) == {}
    assert any("no Arn" in w for w in result.warnings)
