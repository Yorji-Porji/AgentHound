"""OpenGraph JSON emission.

Converts the internal Node/Edge representation into a payload that BloodHound
CE's OpenGraph ingestion API can consume. Schema field names target the v8/v9
OpenGraph payload shape; if SpecterOps changes the wire format upstream, this
module is the only place that needs to change.

See https://specterops.io/opengraph/ and the BloodHound CE OpenAPI docs for
the current ingestion contract.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agenthound.schema.edges import Edge
from agenthound.schema.nodes import Node

SOURCE_KIND = "AgentHound"
SCHEMA_VERSION = "0.1.0"


@dataclass
class OpenGraphPayload:
    """A complete OpenGraph ingestion payload."""

    metadata: dict[str, Any] = field(default_factory=dict)
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata,
            "graph": {"nodes": self.nodes, "edges": self.edges},
        }

    def write(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))


def _serialize_node(node: Node) -> dict[str, Any]:
    return {
        "id": node.objectid,
        "kinds": [node.kind.value, SOURCE_KIND],
        "properties": {
            "name": node.name,
            "objectid": node.objectid,
            **node.properties,
        },
    }


def _serialize_edge(edge: Edge) -> dict[str, Any]:
    return {
        "kind": edge.kind.value,
        "start": {"value": edge.source_id, "match_by": "id"},
        "end": {"value": edge.target_id, "match_by": "id"},
        "properties": {
            "is_coercion": edge.is_coercion,
            **edge.properties,
        },
    }


def build_payload(nodes: list[Node], edges: list[Edge]) -> OpenGraphPayload:
    """Build an OpenGraph payload from internal nodes and edges.

    De-duplicates nodes by objectid (collectors may emit the same node from
    multiple sources) and edges by (kind, source_id, target_id). Edge dedup
    keeps the *first* occurrence, so if two collectors disagree on edge
    properties, the earlier one wins; this matches BloodHound's own
    last-write-wins-on-ingest semantics if reversed.
    """
    seen_nodes: dict[str, Node] = {}
    for n in nodes:
        if n.objectid not in seen_nodes:
            seen_nodes[n.objectid] = n
        else:
            # Merge properties: later writes augment earlier ones, last write wins per key
            merged = dict(seen_nodes[n.objectid].properties)
            merged.update(n.properties)
            seen_nodes[n.objectid] = Node(
                kind=n.kind, name=n.name, stable_id=n.stable_id, properties=merged
            )

    seen_edges: dict[tuple[str, str, str], Edge] = {}
    for e in edges:
        key = (e.kind.value, e.source_id, e.target_id)
        seen_edges.setdefault(key, e)

    return OpenGraphPayload(
        metadata={
            "source_kind": SOURCE_KIND,
            "schema_version": SCHEMA_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "node_count": len(seen_nodes),
            "edge_count": len(seen_edges),
        },
        nodes=[_serialize_node(n) for n in seen_nodes.values()],
        edges=[_serialize_edge(e) for e in seen_edges.values()],
    )
