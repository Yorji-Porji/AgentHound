"""Azure RBAC resolver (real permissions, upload-only).

The ``azure`` collector ingests an Azure RBAC export (role assignments, and
optionally role definitions — files the operator uploads; AgentHound never calls
Azure) and emits principals as NHIs, the scopes their assignments grant, and an
evidence-based admin flag (action ``*`` with no ``notActions`` = the built-in
Owner). Admin-ness comes from the role definition, never from a role name.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from agenthound.cli import main
from agenthound.collectors.azure_rbac import (
    AzureRBACCollector,
    _role_def_full_access,
    _scope_resource_kind,
)
from agenthound.schema import build_payload
from agenthound.schema.edges import PermissionEdgeKind
from agenthound.schema.nodes import NodeKind
from agenthound.scope import EngagementScope, ScopeGuard

EXAMPLE = Path(__file__).parent.parent / "examples" / "azure_role_assignments.example.json"


def _collect(tmp_path: Path, data, guard=None):
    p = tmp_path / "azure.json"
    p.write_text(json.dumps(data))
    return AzureRBACCollector(p, guard=guard).collect()


def _principals(nodes) -> dict:
    return {n.properties["principal_name"]: n for n in nodes if "principal_name" in n.properties}


def _grants(edges):
    return [e for e in edges if e.kind == PermissionEdgeKind.GRANTS_ACCESS]


# --- helpers -----------------------------------------------------------------

def test_role_def_full_access_helper():
    assert _role_def_full_access({"permissions": [{"actions": ["*"], "notActions": []}]})
    # '*' but with notActions (Contributor) is not full access.
    assert not _role_def_full_access(
        {"permissions": [{"actions": ["*"], "notActions": ["Microsoft.Authorization/*/Write"]}]}
    )
    assert not _role_def_full_access({"permissions": [{"actions": ["*/read"]}]})


def test_scope_resource_kind_helper():
    assert _scope_resource_kind("/providers/Microsoft.Management/managementGroups/mg") == (
        "managementGroup"
    )
    assert _scope_resource_kind("/subscriptions/abc") == "subscription"
    assert _scope_resource_kind("/subscriptions/abc/resourceGroups/rg") == "resourceGroup"
    assert _scope_resource_kind(
        "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a"
    ) == "storage"
    assert _scope_resource_kind("/") == "tenant"


# --- principals --------------------------------------------------------------

def test_export_emits_principals():
    principals = _principals(AzureRBACCollector(EXAMPLE).collect().nodes)
    assert set(principals) == {"ci-deployer-sp", "auditor@contoso.com", "acme-app-mi"}
    assert principals["ci-deployer-sp"].properties["nhi_type"] == "azure_service_principal"
    assert principals["auditor@contoso.com"].properties["nhi_type"] == "azure_user"
    assert principals["acme-app-mi"].properties["nhi_type"] == "azure_managed_identity"


# --- evidence-based admin ----------------------------------------------------

def test_owner_is_full_access_by_definition():
    principals = _principals(AzureRBACCollector(EXAMPLE).collect().nodes)
    assert principals["ci-deployer-sp"].properties["grants_full_access"] is True
    # Reader is not admin; Contributor has '*' but notActions, so also not admin.
    assert principals["auditor@contoso.com"].properties["grants_full_access"] is False
    assert principals["acme-app-mi"].properties["grants_full_access"] is False


def test_full_access_is_name_independent(tmp_path: Path):
    data = {
        "roleAssignments": [
            {
                "principalId": "p-loud",
                "principalType": "User",
                "principalName": "loud",
                "roleDefinitionName": "Owner of Everything",
                "roleDefinitionId": "/x/roleDefinitions/loud-guid",
                "scope": "/subscriptions/s",
            },
            {
                "principalId": "p-quiet",
                "principalType": "User",
                "principalName": "quiet",
                "roleDefinitionName": "blob-reader-ish",
                "roleDefinitionId": "/x/roleDefinitions/quiet-guid",
                "scope": "/subscriptions/s",
            },
        ],
        "roleDefinitions": [
            # The loud name carries notActions, so it is NOT full access.
            {
                "roleName": "Owner of Everything",
                "name": "loud-guid",
                "permissions": [
                    {"actions": ["*"], "notActions": ["Microsoft.Authorization/*/Write"]}
                ],
            },
            # The bland name grants '*' with no exclusions — it IS full access.
            {
                "roleName": "blob-reader-ish",
                "name": "quiet-guid",
                "permissions": [{"actions": ["*"], "notActions": []}],
            },
        ],
    }
    principals = _principals(_collect(tmp_path, data).nodes)
    assert principals["loud"].properties["grants_full_access"] is False
    assert principals["quiet"].properties["grants_full_access"] is True


def test_full_access_name_fallback_without_definitions(tmp_path: Path):
    # A bare assignment list (no definitions) falls back to the fixed built-in
    # name 'Owner' — Microsoft's own role id, not a customer label.
    data = [
        {
            "principalId": "p1",
            "principalType": "ServicePrincipal",
            "principalName": "sp1",
            "roleDefinitionName": "Owner",
            "scope": "/subscriptions/s",
        },
        {
            "principalId": "p2",
            "principalType": "ServicePrincipal",
            "principalName": "sp2",
            "roleDefinitionName": "Contributor",
            "scope": "/subscriptions/s",
        },
    ]
    principals = _principals(_collect(tmp_path, data).nodes)
    assert principals["sp1"].properties["grants_full_access"] is True
    assert principals["sp2"].properties["grants_full_access"] is False


# --- resources / GrantsAccess ------------------------------------------------

def test_grants_access_to_scope():
    result = AzureRBACCollector(EXAMPLE).collect()
    principals = _principals(result.nodes)
    owner = principals["ci-deployer-sp"]
    granted = {e.target_id for e in _grants(result.edges) if e.source_id == owner.objectid}
    subscription = next(
        n
        for n in result.nodes
        if n.kind == NodeKind.RESOURCE and n.properties["resource_kind"] == "subscription"
    )
    assert subscription.objectid in granted
    kinds = {
        n.properties["resource_kind"] for n in result.nodes if n.kind == NodeKind.RESOURCE
    }
    assert {"subscription", "resourceGroup", "storage"} <= kinds


# --- ARM REST shape ----------------------------------------------------------

def test_arm_rest_properties_shape(tmp_path: Path):
    # The raw ARM REST shape nests fields under `properties`; accept it too.
    data = [
        {
            "id": "/.../roleAssignments/x",
            "properties": {
                "principalId": "p-nested",
                "principalType": "ServicePrincipal",
                "roleDefinitionName": "Owner",
                "scope": "/subscriptions/s",
            },
        }
    ]
    principals = _principals(_collect(tmp_path, data).nodes)
    assert "p-nested" in principals  # principalName missing -> falls back to id
    assert principals["p-nested"].properties["grants_full_access"] is True


def test_assignment_without_principal_id_skipped(tmp_path: Path):
    result = _collect(tmp_path, [{"roleDefinitionName": "Owner", "scope": "/subscriptions/s"}])
    assert _principals(result.nodes) == {}
    assert any("no principalId" in w for w in result.warnings)


# --- scope -------------------------------------------------------------------

def test_scope_deny_azure_yields_nothing():
    guard = ScopeGuard(
        EngagementScope.model_validate(
            {
                "engagement": "t",
                "authorized_until": "2099-01-01T00:00:00Z",
                "providers_denied": ["azure"],
            }
        )
    )
    result = AzureRBACCollector(EXAMPLE, guard=guard).collect()
    assert result.nodes == []
    assert result.edges == []


# --- fail-soft CLI -----------------------------------------------------------

def test_malformed_export_raises_clickexception(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ not valid json")
    res = CliRunner().invoke(main, ["azure", "-i", str(bad)])
    assert res.exit_code != 0
    assert "Could not read Azure RBAC export" in res.output


def test_non_container_root_raises_clickexception(tmp_path: Path):
    bad = tmp_path / "scalar.json"
    bad.write_text("\"just a string\"")
    res = CliRunner().invoke(main, ["azure", "-i", str(bad)])
    assert res.exit_code != 0
    assert "Could not read Azure RBAC export" in res.output


def test_cli_writes_graph(tmp_path: Path):
    out = tmp_path / "azure_graph.json"
    res = CliRunner().invoke(main, ["azure", "-i", str(EXAMPLE), "-o", str(out)])
    assert res.exit_code == 0, res.output
    payload = json.loads(out.read_text())
    assert payload["graph"]["nodes"] and payload["graph"]["edges"]


# --- schema gate -------------------------------------------------------------

def test_emitted_payload_validates(node_schema, edge_schema):
    jsonschema = pytest.importorskip("jsonschema")
    result = AzureRBACCollector(EXAMPLE).collect()
    payload = build_payload(result.nodes, result.edges).to_dict()
    for n in payload["graph"]["nodes"]:
        jsonschema.validate(n, node_schema)
    for e in payload["graph"]["edges"]:
        jsonschema.validate(e, edge_schema)
