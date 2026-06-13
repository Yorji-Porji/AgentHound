"""AWS IAM export collector.

Resolves *real* AWS permissions from an uploaded ``aws iam
get-account-authorization-details`` export — the single dump that contains every
user, role, group, and their attached + inline policies. **AgentHound never
calls AWS:** you run that read-only command yourself and hand AgentHound the
JSON, so the tool stays network-free and air-gappable.

Emitted subgraph (all under the ``aws`` scope gate):

- each user / role -> an ``NHI`` keyed on its **ARN**, so a role here joins the
  ``assumed_role`` NHI the ``local`` collector draws from ``~/.aws/config`` (the
  local-config view and the authoritative IAM view attach to the same node).
  Note this join is at the **role** level (both key roles by ARN); the *assuming*
  identity does not join — ``local`` keys it by profile name and ``aws-iam`` by
  ARN, and resolving one to the other needs an API call this tool never makes.
- **evidence-based admin flag**: ``grants_full_access`` is set from policy
  *content* — the managed ``AdministratorAccess`` ARN, or an ``Allow`` of action
  ``*`` on resource ``*`` — **never from the principal's name**. This reflects
  *granted* policy, not the *effective* set after explicit ``Deny``, permission
  boundaries, or SCPs; ``iam:SimulatePrincipalPolicy`` is the authoritative oracle.
- ``NHI -> Resource`` ``GRANTS_ACCESS`` edges from each ``Allow`` statement's
  resource ARNs (wildcard ``*`` becomes one ``aws:*:*`` resource).
- ``CAN_ASSUME`` edges from each role's trust policy (its authoritative assumers).

This collector resolves *what an identity can do*; ``local`` resolves *who can
become whom*. Both emit the same node/edge kinds, so they compose into one graph.
"""

from __future__ import annotations

import json
import urllib.parse
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agenthound.collectors.base import CollectionResult, Collector

if TYPE_CHECKING:
    from agenthound.audit import AuditLog
    from agenthound.scope import ScopeGuard
from agenthound.schema.edges import Edge, PermissionEdgeKind
from agenthound.schema.nodes import Node, nhi_node, resource_node

# The one role/policy name that means "admin" in *every* AWS account, because it
# is AWS's own managed policy, not a customer label. Admin-ness keys on this ARN
# (and on Action:* Resource:* statements), never on what a customer named a role.
ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


class AWSIAMExportError(ValueError):
    """The uploaded file is not a usable IAM authorization-details export."""


def _as_list(value: Any) -> list[Any]:
    """IAM fields are a scalar or a list; normalize to a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _as_document(value: Any) -> dict[str, Any] | None:
    """A policy document is a JSON object, or a URL-encoded JSON string."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            decoded = json.loads(urllib.parse.unquote(value))
        except (json.JSONDecodeError, ValueError):
            return None
        return decoded if isinstance(decoded, dict) else None
    return None


def _statements(document: Any) -> list[dict[str, Any]]:
    doc = _as_document(document)
    if not doc:
        return []
    return [s for s in _as_list(doc.get("Statement")) if isinstance(s, dict)]


def _arn_account(arn: str) -> str | None:
    parts = arn.split(":")
    return parts[4] if len(parts) > 4 and parts[4] else None


def _arn_service(arn: str) -> str:
    parts = arn.split(":")
    return parts[2] if len(parts) > 2 and parts[2] else "*"


def _is_full_access(statement: dict[str, Any]) -> bool:
    """An Allow of action ``*`` on resource ``*`` — the real definition of admin."""
    if statement.get("Effect") != "Allow":
        return False
    actions = set(_as_list(statement.get("Action")))
    resources = set(_as_list(statement.get("Resource")))
    return "*" in actions and "*" in resources


class AWSIAMCollector(Collector):
    """Resolve an uploaded IAM authorization-details export into the graph."""

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
        # JSONDecodeError / OSError propagate to the CLI, which turns them into a
        # clean ClickException (matching the fail-soft posture elsewhere).
        data = json.loads(self.import_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise AWSIAMExportError(
                "export root must be a JSON object "
                "(from `aws iam get-account-authorization-details`)"
            )

        # One provider gate for the whole export: scoped-out 'aws' -> nothing.
        if not self.allow_provider("aws", f"aws-iam:{self.import_path}"):
            return result

        managed = _index_managed_policies(_as_list(data.get("Policies")))
        roles = [r for r in _as_list(data.get("RoleDetailList")) if isinstance(r, dict)]
        users = [u for u in _as_list(data.get("UserDetailList")) if isinstance(u, dict)]

        # Phase 1: trust placeholders + CAN_ASSUME edges first. A role's objectid
        # is deterministic from its ARN, so trust edges can be wired before the
        # rich role node exists. Emitting the (possibly placeholder) assumers now
        # means the rich principal nodes in phase 2 win build_payload's later-wins
        # property merge — a user that is also a trust principal keeps its
        # iam_user identity instead of being clobbered to aws_principal.
        for role in roles:
            arn = role.get("Arn")
            if isinstance(arn, str) and arn:
                target = nhi_node(provider="aws", identifier=arn, nhi_type="iam_role")
                self._emit_trust(role, target, result)

        # Phase 2: the rich principal definitions, emitted last so they win.
        for user in users:
            self._emit_principal(user, "iam_user", managed, result)
        for role in roles:
            self._emit_principal(role, "iam_role", managed, result)

        return result

    def _emit_principal(
        self,
        principal: dict[str, Any],
        nhi_type: str,
        managed: dict[str, Any],
        result: CollectionResult,
    ) -> None:
        arn = principal.get("Arn")
        if not isinstance(arn, str) or not arn:
            result.warnings.append(f"Skipping IAM {nhi_type} with no Arn.")
            return

        nhi = nhi_node(provider="aws", identifier=arn, nhi_type=nhi_type)
        nhi.properties["principal_name"] = (
            principal.get("RoleName") or principal.get("UserName") or arn
        )
        account = _arn_account(arn)
        if account:
            nhi.properties["account_id"] = account

        # Inline policy documents (role or user) plus resolved managed docs.
        documents: list[Any] = [
            inline.get("PolicyDocument")
            for inline in _as_list(principal.get("RolePolicyList"))
            + _as_list(principal.get("UserPolicyList"))
            if isinstance(inline, dict)
        ]
        full_access = False
        for att in _as_list(principal.get("AttachedManagedPolicies")):
            if not isinstance(att, dict):
                continue
            policy_arn = att.get("PolicyArn")
            if policy_arn == ADMIN_POLICY_ARN:
                full_access = True
            if policy_arn in managed:
                documents.append(managed[policy_arn])

        resources_allowed: set[str] = set()
        for doc in documents:
            for stmt in _statements(doc):
                if _is_full_access(stmt):
                    full_access = True
                if stmt.get("Effect") == "Allow":
                    resources_allowed.update(
                        r for r in _as_list(stmt.get("Resource")) if isinstance(r, str)
                    )

        # An admin reaches everything; guarantee a reachability edge even when the
        # granting policy's body isn't in the export (e.g. AWS-managed
        # AdministratorAccess, whose document is often omitted).
        if full_access:
            resources_allowed.add("*")

        nhi.properties["grants_full_access"] = full_access
        result.nodes.append(nhi)
        self._emit_resources(nhi, resources_allowed, result)

    def _emit_resources(
        self, nhi: Node, resources: set[str], result: CollectionResult
    ) -> None:
        for res in sorted(resources):
            if res == "*":
                resource = resource_node(provider="aws", kind="*", identifier="*")
                resource.properties["wildcard"] = True
            else:
                resource = resource_node(
                    provider="aws", kind=_arn_service(res), identifier=res
                )
            result.nodes.append(resource)
            result.edges.append(
                Edge(PermissionEdgeKind.GRANTS_ACCESS, nhi.objectid, resource.objectid)
            )

    def _emit_trust(
        self, role: dict[str, Any], role_nhi: Node, result: CollectionResult
    ) -> None:
        """CAN_ASSUME edges from a role's trust policy (its authoritative assumers)."""
        for stmt in _statements(role.get("AssumeRolePolicyDocument")):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal")
            if not isinstance(principal, dict):
                continue
            for assumer_arn in _as_list(principal.get("AWS")):
                if not isinstance(assumer_arn, str):
                    continue
                assumer = nhi_node(
                    provider="aws", identifier=assumer_arn, nhi_type="aws_principal"
                )
                result.nodes.append(assumer)
                result.edges.append(
                    Edge(
                        PermissionEdgeKind.CAN_ASSUME,
                        assumer.objectid,
                        role_nhi.objectid,
                        properties={"via": "trust_policy"},
                    )
                )


def _index_managed_policies(policies: list[Any]) -> dict[str, Any]:
    """Map a managed-policy ARN to its default-version document, for inline expansion."""
    out: dict[str, Any] = {}
    for pol in policies:
        if not isinstance(pol, dict):
            continue
        arn = pol.get("Arn")
        if not isinstance(arn, str) or not arn:
            continue
        default_version = pol.get("DefaultVersionId")
        for ver in _as_list(pol.get("PolicyVersionList")):
            if not isinstance(ver, dict):
                continue
            if ver.get("VersionId") == default_version or ver.get("IsDefaultVersion"):
                if ver.get("Document") is not None:
                    out[arn] = ver["Document"]
                break
    return out
