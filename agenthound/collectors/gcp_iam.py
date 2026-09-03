"""GCP IAM policy collector.

Resolves *real* GCP permissions from an uploaded Cloud Asset Inventory IAM-policy
export — the GCP analogue of the ``aws`` collector. You run a read-only
command yourself and hand AgentHound the JSON, so the tool stays network-free
and air-gappable. **AgentHound never calls GCP.**

The intended input is::

    gcloud asset search-all-iam-policies \\
        --scope=organizations/ORG_ID --format=json > gcp_iam.json

i.e. one org/folder/project-wide dump of every IAM *binding* and the resource it
is attached to. A bare ``gcloud projects get-iam-policy`` document (a single
``{bindings: [...]}`` object) is also accepted, but it carries no resource name,
so only the principals and their admin flag are emitted (no ``GRANTS_ACCESS``).

Emitted subgraph (all under the ``gcp`` scope gate):

- each binding **member** -> an ``NHI`` keyed on its identifier (a service
  account email, user email, group, domain, or workload-identity principal). A
  service account is keyed on its **email**, so it joins the same node whether it
  appears as a grantee or as an impersonation target.
- **evidence-based admin flag**: ``grants_full_access`` is set when a member
  holds ``roles/owner`` — GCP's *own* basic role that grants every permission on
  a resource (including IAM), not a customer-chosen label. This reflects
  *granted* role, not the *effective* set after deny policies, org-policy
  constraints, or IAM conditions; the role's underlying permission set lives in
  the role definition, which this export does not contain.
- ``NHI -> Resource`` ``GRANTS_ACCESS`` edges from each binding to the resource
  its policy is attached to (a project, bucket, dataset, …).
- ``NHI -> NHI`` ``CAN_ASSUME`` edges for **service-account impersonation** —
  GCP's analogue of AWS assume-role. A member granted an impersonation role
  (``roles/iam.serviceAccountTokenCreator``, ``roles/iam.serviceAccountUser``,
  ``roles/iam.workloadIdentityUser``) *on a service-account resource* can act as
  that service account, so it is a privilege-escalation edge into the SA's NHI.

This collector resolves *what an identity can do* and *who can become whom* for
GCP; both compose into the same graph as the AWS collectors (same node/edge
kinds).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agenthound.collectors.base import CollectionResult, Collector, as_list

if TYPE_CHECKING:
    from agenthound.audit import AuditLog
    from agenthound.scope import ScopeGuard
from agenthound.schema.edges import Edge, PermissionEdgeKind
from agenthound.schema.nodes import Node, nhi_node, resource_node

# ``roles/owner`` is GCP's own basic role granting every permission (incl. IAM)
# on a resource. Admin-ness keys on this fixed role id, never on what a customer
# named a custom role — mirroring how the AWS collector keys on the managed
# AdministratorAccess ARN rather than a role's name.
FULL_ACCESS_ROLES = frozenset({"roles/owner"})

# Holding any of these *on a service-account resource* lets the member act as
# that service account — GCP's assume-role analogue (a CAN_ASSUME edge).
IMPERSONATION_ROLES = frozenset(
    {
        "roles/iam.serviceAccountTokenCreator",
        "roles/iam.serviceAccountUser",
        "roles/iam.workloadIdentityUser",
    }
)

# Member-prefix -> NHI type. Humans and groups are modelled as NHIs too (as the
# AWS collector models IAM users), so the whole identity surface is one graph.
_MEMBER_NHI_TYPE = {
    "serviceAccount": "gcp_service_account",
    "user": "gcp_user",
    "group": "gcp_group",
    "domain": "gcp_domain",
    "principal": "gcp_federated",
    "principalSet": "gcp_federated",
    "principalHierarchy": "gcp_federated",
}

# Asset-resource service label -> friendlier resource kind. Anything not listed
# falls back to the raw service label (e.g. ``storage``, ``compute``).
_RESOURCE_KIND_BY_PATH = {
    "projects": "project",
    "folders": "folder",
    "organizations": "organization",
}


class GCPIAMExportError(ValueError):
    """The uploaded file is not a usable GCP IAM-policy export."""


def _parse_member(member: str) -> tuple[str, str] | None:
    """Split an IAM ``members[]`` entry into ``(identifier, nhi_type)``.

    Handles the ``deleted:`` wrapper and the ``?uid=`` suffix GCP adds to deleted
    principals, and the prefix-less ``allUsers`` / ``allAuthenticatedUsers``. The
    identifier is the email / domain / principal URL — never a secret. Returns
    ``None`` for an empty or prefix-only entry.
    """
    m = member.strip()
    if m.startswith("deleted:"):
        m = m[len("deleted:") :]
    m = m.split("?", 1)[0].strip()  # drop the ?uid=... on deleted principals
    if not m:
        return None
    if m in ("allUsers", "allAuthenticatedUsers"):
        return m, "gcp_public"
    if ":" not in m:
        return m, "gcp_member"
    prefix, _, rest = m.partition(":")
    rest = rest.strip()
    if not rest:
        return None
    return rest, _MEMBER_NHI_TYPE.get(prefix, "gcp_member")


def _strip_scheme(resource: str) -> list[str]:
    """``//service.googleapis.com/a/b/c`` -> ``['service.googleapis.com','a','b','c']``."""
    r = resource[2:] if resource.startswith("//") else resource
    return [p for p in r.split("/") if p]


def _resource_kind(resource: str) -> str:
    """Derive a resource kind from a full asset resource name.

    Uses the API service label, refining the cloudresourcemanager hierarchy
    (project / folder / organization) from the path so the graph reads naturally.
    """
    parts = _strip_scheme(resource)
    if not parts:
        return "gcp"
    service = parts[0].split(".", 1)[0]
    if service == "cloudresourcemanager" and len(parts) > 1:
        return _RESOURCE_KIND_BY_PATH.get(parts[1], "project")
    return service or "gcp"


def _service_account_from_resource(resource: str) -> str | None:
    """Extract a service-account identifier from a ``.../serviceAccounts/X`` name.

    Returns the SA *email* when the resource uses it (the same key a member
    ``serviceAccount:email`` produces, so the two views join), or the numeric
    unique id when that is all the export carries (which will not join an
    email-keyed node — the analogue of the AWS user/role join nuance).
    """
    parts = _strip_scheme(resource)
    if "serviceAccounts" in parts:
        i = parts.index("serviceAccounts")
        if i + 1 < len(parts):
            return parts[i + 1] or None
    return None


class GCPIAMCollector(Collector):
    """Resolve an uploaded GCP IAM-policy export into the graph."""

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
        if not self.allow_provider("gcp", f"gcp:{self.import_path}"):
            return result
        if not self.allow_path(self.import_path, f"gcp:{self.import_path}"):
            return result
        # JSONDecodeError / OSError propagate to the CLI, which turns them into a
        # clean ClickException (matching the fail-soft posture elsewhere).
        data = json.loads(self.import_path.read_text(encoding="utf-8"))
        if not isinstance(data, (list, dict)):
            raise GCPIAMExportError(
                "export root must be a JSON array (from `gcloud asset "
                "search-all-iam-policies`) or object (a get-iam-policy document)"
            )

        # Aggregate per member across every binding, so each identity is one node
        # carrying the union of its grants (mirrors the AWS per-principal node).
        members: dict[str, dict[str, Any]] = {}
        grants: set[tuple[str, str]] = set()  # (member, resource)
        impersonations: set[tuple[str, str]] = set()  # (member, sa_identifier)
        resource_kinds: dict[str, str] = {}  # resource -> kind

        for resource, role, member_list in _iter_bindings(data, result.warnings):
            is_full = role in FULL_ACCESS_ROLES
            sa_target = (
                _service_account_from_resource(resource)
                if resource and role in IMPERSONATION_ROLES
                else None
            )
            if resource:
                resource_kinds.setdefault(resource, _resource_kind(resource))
            for raw_member in member_list:
                parsed = _parse_member(raw_member)
                if parsed is None:
                    result.warnings.append(f"Skipping unparseable IAM member '{raw_member}'.")
                    continue
                identifier, nhi_type = parsed
                rec = members.setdefault(
                    raw_member,
                    {"identifier": identifier, "nhi_type": nhi_type, "full_access": False},
                )
                if is_full:
                    rec["full_access"] = True
                if resource:
                    grants.add((raw_member, resource))
                if sa_target:
                    impersonations.add((raw_member, sa_target))

        self._emit(members, grants, impersonations, resource_kinds, result)
        return result

    def _emit(
        self,
        members: dict[str, dict[str, Any]],
        grants: set[tuple[str, str]],
        impersonations: set[tuple[str, str]],
        resource_kinds: dict[str, str],
        result: CollectionResult,
    ) -> None:
        # Phase 1: impersonation-target placeholders first. A target SA that is
        # also a grantee gets a rich node in phase 2 with the same objectid; built
        # last, that rich node wins build_payload's later-wins property merge
        # (the AWS collector uses the same ordering for trust principals).
        for _member, sa_identifier in sorted(impersonations):
            result.nodes.append(
                nhi_node(provider="gcp", identifier=sa_identifier, nhi_type="gcp_service_account")
            )

        # Phase 2: the rich member definitions, emitted last so they win.
        member_nodes: dict[str, Node] = {}
        for raw_member, rec in members.items():
            nhi = nhi_node(provider="gcp", identifier=rec["identifier"], nhi_type=rec["nhi_type"])
            nhi.properties["principal_name"] = rec["identifier"]
            nhi.properties["grants_full_access"] = rec["full_access"]
            member_nodes[raw_member] = nhi
            result.nodes.append(nhi)

        resource_nodes: dict[str, Node] = {}
        for resource, kind in resource_kinds.items():
            rn = resource_node(provider="gcp", kind=kind, identifier=resource)
            resource_nodes[resource] = rn
            result.nodes.append(rn)

        for raw_member, resource in sorted(grants):
            result.edges.append(
                Edge(
                    PermissionEdgeKind.GRANTS_ACCESS,
                    member_nodes[raw_member].objectid,
                    resource_nodes[resource].objectid,
                )
            )

        for raw_member, sa_identifier in sorted(impersonations):
            target = nhi_node(
                provider="gcp", identifier=sa_identifier, nhi_type="gcp_service_account"
            )
            result.edges.append(
                Edge(
                    PermissionEdgeKind.CAN_ASSUME,
                    member_nodes[raw_member].objectid,
                    target.objectid,
                    properties={"via": "impersonation"},
                )
            )


def _iter_bindings(
    data: list[Any] | dict[str, Any], warnings: list[str]
) -> Iterator[tuple[str | None, str, list[str]]]:
    """Yield ``(resource, role, members)`` for every binding in the export.

    Accepts the ``search-all-iam-policies`` list (or ``{results: [...]}`` wrapper),
    a single search result, or a bare ``get-iam-policy`` document. ``resource`` is
    ``None`` for a bare document (no attached resource name in that shape).
    """
    for res in _normalize_results(data, warnings):
        if not isinstance(res, dict):
            continue
        resource = res.get("resource")
        resource = resource if isinstance(resource, str) and resource else None
        policy = res.get("policy")
        if not isinstance(policy, dict):
            policy = res if "bindings" in res else None
        if not isinstance(policy, dict):
            continue
        for binding in as_list(policy.get("bindings")):
            if not isinstance(binding, dict):
                continue
            role = binding.get("role")
            if not isinstance(role, str) or not role:
                continue
            member_list = [m for m in as_list(binding.get("members")) if isinstance(m, str)]
            yield resource, role, member_list


def _normalize_results(data: list[Any] | dict[str, Any], warnings: list[str]) -> list[Any]:
    """Normalize the supported root shapes to a list of search-result-like dicts."""
    if isinstance(data, list):
        return data
    results = data.get("results")
    if isinstance(results, list):
        return results
    if "bindings" in data:
        warnings.append(
            "Input looks like a single get-iam-policy document (no attached "
            "resource); emitting principals and admin flags without GRANTS_ACCESS. "
            "Use `gcloud asset search-all-iam-policies` for resource attribution."
        )
        return [data]
    if "policy" in data:
        return [data]
    warnings.append("No IAM bindings found in export (expected `bindings` or `results`).")
    return []
