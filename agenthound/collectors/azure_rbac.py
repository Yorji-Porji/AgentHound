"""Azure RBAC collector.

Resolves *real* Azure permissions from an uploaded RBAC export — the Azure
analogue of the ``aws`` collector. You run read-only ``az`` commands yourself
and hand AgentHound the JSON, so the tool stays network-free and air-gappable.
**AgentHound never calls Azure.**

The intended input combines the two read-only listings into one file::

    {
      "roleAssignments": <az role assignment list --all -o json>,
      "roleDefinitions": <az role definition list -o json>
    }

The role definitions are optional but recommended: with them, the admin flag is
set from policy *content* (a permission of action ``*`` with no ``notActions``);
without them, it falls back to Azure's fixed built-in role *name* ``Owner``. A
bare ``az role assignment list`` array (no definitions) is also accepted.

Emitted subgraph (all under the ``azure`` scope gate):

- each assignment **principal** -> an ``NHI`` keyed on its ``principalId`` (the
  stable directory object id), typed from ``principalType`` (service principal,
  managed identity, user, group).
- **evidence-based admin flag**: ``grants_full_access`` is set when the assigned
  role grants action ``*`` with no ``notActions`` (the built-in **Owner**
  definition) — never from a customer-chosen role name. This reflects *granted*
  role, not the *effective* set after deny assignments or Azure Policy.
- ``NHI -> Resource`` ``GRANTS_ACCESS`` edges from each assignment to its
  **scope** (a management group, subscription, resource group, or resource).

What this does *not* yet model: managed-identity attachment as a ``CAN_ASSUME``
edge (the Azure analogue of GCP impersonation) needs action-level analysis of who
can attach an identity to a workload, which a role-assignment listing alone does
not give. Tracked as future work; the AWS/GCP collectors carry the cross-identity
edges today.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agenthound.collectors.base import CollectionResult, Collector, as_list

if TYPE_CHECKING:
    from agenthound.audit import AuditLog
    from agenthound.scope import ScopeGuard
from agenthound.schema.edges import Edge, PermissionEdgeKind
from agenthound.schema.nodes import Node, nhi_node, resource_node

# Azure's own built-in role granting full access (action ``*``, no exclusions).
# Used as the name-based fallback only when role *definitions* are absent from
# the export; with definitions present, admin-ness is read from policy content.
FULL_ACCESS_BUILTIN_ROLES = frozenset({"Owner"})

# principalType -> NHI type. Humans and groups are modelled as NHIs too (as the
# AWS collector models IAM users), so the whole identity surface is one graph.
_PRINCIPAL_NHI_TYPE = {
    "ServicePrincipal": "azure_service_principal",
    "MSI": "azure_managed_identity",
    "ManagedIdentity": "azure_managed_identity",
    "User": "azure_user",
    "Group": "azure_group",
    "ForeignGroup": "azure_group",
    "Device": "azure_device",
}


class AzureRBACExportError(ValueError):
    """The uploaded file is not a usable Azure RBAC export."""


def _get(record: dict[str, Any], key: str) -> Any:
    """Read a field from the top level or the ARM-REST ``properties`` sub-object.

    The ``az`` CLI flattens fields to the top level; the raw ARM REST shape nests
    them under ``properties``. Accept both.
    """
    if key in record:
        return record[key]
    props = record.get("properties")
    if isinstance(props, dict):
        return props.get(key)
    return None


def _principal_nhi_type(principal_type: Any) -> str:
    if isinstance(principal_type, str):
        return _PRINCIPAL_NHI_TYPE.get(principal_type, "azure_principal")
    return "azure_principal"


def _role_def_full_access(definition: dict[str, Any]) -> bool:
    """True if a role definition grants action ``*`` with no ``notActions``.

    This is exactly the built-in Owner definition; Contributor also has ``*`` but
    carries ``notActions`` removing the access-management verbs, so it is not
    flagged — the Azure parallel to the AWS ``Allow *`` on ``*`` test.
    """
    for perm in as_list(definition.get("permissions")):
        if not isinstance(perm, dict):
            continue
        actions = [a for a in as_list(perm.get("actions")) if isinstance(a, str)]
        not_actions = [a for a in as_list(perm.get("notActions")) if isinstance(a, str)]
        if "*" in actions and not not_actions:
            return True
    return False


def _scope_resource_kind(scope: str) -> str:
    """Derive a resource kind from an RBAC scope string."""
    if scope.strip() in ("", "/"):
        return "tenant"
    parts = [p for p in scope.split("/") if p]
    if "managementGroups" in parts:
        return "managementGroup"
    if "providers" in parts:
        i = parts.index("providers")
        ns = parts[i + 1] if i + 1 < len(parts) else ""
        short = ns.split(".", 1)[1].lower() if "." in ns else ns.lower()
        return short or "resource"
    if "resourceGroups" in parts:
        return "resourceGroup"
    if parts[:1] == ["subscriptions"]:
        return "subscription"
    return "resource"


class AzureRBACCollector(Collector):
    """Resolve an uploaded Azure RBAC export into the graph."""

    def __init__(
        self,
        import_path: Path,
        *,
        guard: ScopeGuard | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        super().__init__(guard=guard, audit=audit)
        self.import_path = Path(import_path)

    def collect(self) -> CollectionResult:
        result = CollectionResult()
        if not self.allow_provider("azure", f"azure:{self.import_path}"):
            return result
        if not self.allow_path(self.import_path, f"azure:{self.import_path}"):
            return result
        # JSONDecodeError / OSError propagate to the CLI, which turns them into a
        # clean ClickException (matching the fail-soft posture elsewhere).
        data = json.loads(self.import_path.read_text(encoding="utf-8"))
        if not isinstance(data, (list, dict)):
            raise AzureRBACExportError(
                "export root must be a JSON array (a role-assignment list) or "
                "object ({roleAssignments, roleDefinitions})"
            )

        assignments, definitions = _split_export(data)
        if not assignments:
            result.warnings.append("No role assignments found in export.")
        full_by_guid, full_by_name = _index_role_definitions(definitions)

        # Aggregate per principal across every assignment, so each identity is one
        # node carrying the union of its grants (mirrors the AWS per-principal node).
        principals: dict[str, dict[str, Any]] = {}
        grants: set[tuple[str, str]] = set()  # (principalId, scope)
        scope_kinds: dict[str, str] = {}  # scope -> kind

        for assignment in assignments:
            if not isinstance(assignment, dict):
                continue
            principal_id = _get(assignment, "principalId")
            if not isinstance(principal_id, str) or not principal_id:
                result.warnings.append("Skipping role assignment with no principalId.")
                continue
            role_name = _get(assignment, "roleDefinitionName")
            scope = _get(assignment, "scope")
            full = _assignment_full_access(
                role_name, _get(assignment, "roleDefinitionId"), full_by_guid, full_by_name
            )
            rec = principals.setdefault(
                principal_id,
                {
                    "nhi_type": _principal_nhi_type(_get(assignment, "principalType")),
                    "name": _get(assignment, "principalName")
                    or _get(assignment, "displayName")
                    or principal_id,
                    "full_access": False,
                },
            )
            if full:
                rec["full_access"] = True
            if isinstance(scope, str) and scope:
                grants.add((principal_id, scope))
                scope_kinds.setdefault(scope, _scope_resource_kind(scope))

        self._emit(principals, grants, scope_kinds, result)
        return result

    def _emit(
        self,
        principals: dict[str, dict[str, Any]],
        grants: set[tuple[str, str]],
        scope_kinds: dict[str, str],
        result: CollectionResult,
    ) -> None:
        principal_nodes: dict[str, Node] = {}
        for principal_id, rec in principals.items():
            nhi = nhi_node(provider="azure", identifier=principal_id, nhi_type=rec["nhi_type"])
            nhi.properties["principal_name"] = rec["name"]
            nhi.properties["grants_full_access"] = rec["full_access"]
            principal_nodes[principal_id] = nhi
            result.nodes.append(nhi)

        resource_nodes: dict[str, Node] = {}
        for scope, kind in scope_kinds.items():
            rn = resource_node(provider="azure", kind=kind, identifier=scope)
            resource_nodes[scope] = rn
            result.nodes.append(rn)

        for principal_id, scope in sorted(grants):
            result.edges.append(
                Edge(
                    PermissionEdgeKind.GRANTS_ACCESS,
                    principal_nodes[principal_id].objectid,
                    resource_nodes[scope].objectid,
                )
            )


def _split_export(data: list[Any] | dict[str, Any]) -> tuple[list[Any], list[Any]]:
    """Return ``(assignments, definitions)`` from the supported root shapes."""
    if isinstance(data, list):
        return data, []
    assignments = data.get("roleAssignments")
    definitions = data.get("roleDefinitions")
    if isinstance(assignments, list) or isinstance(definitions, list):
        return as_list(assignments), as_list(definitions)
    value = data.get("value")  # ARM REST list wrapper
    if isinstance(value, list):
        return value, []
    if _get(data, "principalId"):  # a single assignment object
        return [data], []
    return [], []


def _index_role_definitions(
    definitions: list[Any],
) -> tuple[dict[str, bool], dict[str, bool]]:
    """Map role-definition guid and roleName to whether it grants full access."""
    by_guid: dict[str, bool] = {}
    by_name: dict[str, bool] = {}
    for definition in definitions:
        if not isinstance(definition, dict):
            continue
        full = _role_def_full_access(definition)
        guid = definition.get("name")
        if isinstance(guid, str) and guid:
            by_guid[guid.lower()] = full
        full_id = definition.get("id")
        if isinstance(full_id, str) and full_id:
            by_guid[full_id.rsplit("/", 1)[-1].lower()] = full
        role_name = definition.get("roleName")
        if isinstance(role_name, str) and role_name:
            by_name[role_name] = full
    return by_guid, by_name


def _assignment_full_access(
    role_name: Any,
    role_def_id: Any,
    full_by_guid: dict[str, bool],
    full_by_name: dict[str, bool],
) -> bool:
    """Resolve an assignment's admin-ness from definitions, then by built-in name."""
    if isinstance(role_def_id, str) and role_def_id:
        guid = role_def_id.rsplit("/", 1)[-1].lower()
        if guid in full_by_guid:
            return full_by_guid[guid]
    if isinstance(role_name, str):
        if role_name in full_by_name:
            return full_by_name[role_name]
        return role_name in FULL_ACCESS_BUILTIN_ROLES
    return False
