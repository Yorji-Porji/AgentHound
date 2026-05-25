"""Base collector interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from agenthound.schema.edges import Edge
from agenthound.schema.nodes import Node


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
    """Base class for collectors."""

    name: str = "base"

    @abstractmethod
    def collect(self) -> CollectionResult:
        """Run the collector and return all nodes and edges discovered."""
