"""Base collector interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agenthound.schema.edges import Edge
from agenthound.schema.nodes import Node

if TYPE_CHECKING:
    from agenthound.audit import AuditLog
    from agenthound.scope import ScopeGuard


def as_list(value: Any) -> list[Any]:
    """Normalize a cloud-export field that may be a scalar or a list to a list.

    IAM/RBAC exports represent single-element fields as either a bare value or a
    one-element list; the AWS, GCP, and Azure collectors all need this.
    """
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


@dataclass
class CollectionResult:
    """Output of a collector run."""

    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def extend(self, other: CollectionResult) -> None:
        self.nodes.extend(other.nodes)
        self.edges.extend(other.edges)
        self.warnings.extend(other.warnings)


class Collector(ABC):
    """Base class for collectors.

    Scope enforcement is opt-in: when ``guard`` is ``None`` every check passes
    and nothing is audited, so unscoped runs behave exactly as before. When a
    guard is attached, subclasses call :meth:`allow_provider` / :meth:`allow_path`
    before touching a provider or filesystem path; every decision is audited and
    an out-of-scope target yields no node/edge.
    """

    def __init__(
        self,
        *,
        guard: ScopeGuard | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.guard = guard
        self.audit = audit

    @abstractmethod
    def collect(self) -> CollectionResult:
        """Run the collector and return all nodes and edges discovered."""

    # -- Scope enforcement helpers --------------------------------------------

    def allow_provider(self, provider: str, target: str) -> bool:
        """True if ``provider`` is in scope. Audit either outcome."""
        if self.guard is None:
            return True
        if self.guard.check_provider(provider):
            self._audit_decision(
                "collect", target, "ALLOW", f"provider '{provider}' in scope"
            )
            return True
        self._audit_decision(
            "collect", target, "SKIPPED", f"provider '{provider}' out of scope"
        )
        return False

    def allow_path(self, path: str | Path, target: str) -> bool:
        """True if ``path`` is not denied by scope. Audit either outcome."""
        if self.guard is None:
            return True
        if self.guard.check_path(path):
            self._audit_decision("collect", target, "ALLOW", f"path '{path}' in scope")
            return True
        self._audit_decision(
            "collect", target, "SKIPPED", f"path '{path}' out of scope"
        )
        return False

    def _audit_decision(self, op: str, target: str, decision: str, reason: str) -> None:
        if self.audit is not None:
            self.audit.record(op, target, decision, reason)
