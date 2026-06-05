"""OpenGraph JSON emission.

Converts the internal Node/Edge representation into a payload that BloodHound
CE's OpenGraph ingestion API can consume. Schema field names target the v8/v9
OpenGraph payload shape; if SpecterOps changes the wire format upstream, this
module is the only place that needs to change.

See https://specterops.io/opengraph/ and the BloodHound CE OpenAPI docs for
the current ingestion contract.
"""

from __future__ import annotations

import re
import warnings
from dataclasses import dataclass, field
from typing import Any

from agenthound.schema.edges import Edge
from agenthound.schema.nodes import Node

SOURCE_KIND = "AgentHound"

# BloodHound built-in edge kinds — warn loudly if we collide with one
RESERVED_KINDS = {
    "AdminTo", "Owns", "MemberOf", "DCSync", "HasSession",
    "CanRDP", "CanPSRemote", "ExecuteDCOM", "AllowedToDelegate",
    "AllowedToAct", "GenericAll", "GenericWrite", "WriteOwner",
    "WriteDacl", "AddMember", "ForceChangePassword", "ReadLAPSPassword",
}


@dataclass
class OpenGraphPayload:
    """A complete OpenGraph ingestion payload.

    `metadata` is what BloodHound validates on ingest — it is kept strictly to
    the fields BloodHound allows (currently just `source_kind`). Counts and
    timestamps are deliberately omitted; BloodHound's strict metadata schema
    (additionalProperties: false) rejects anything beyond `source_kind`.
    """

    metadata: dict[str, Any] = field(default_factory=dict)
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata,
            "graph": {"nodes": self.nodes, "edges": self.edges},
        }


def _sanitize_kind(s: str) -> str:
    """Convert a raw kind string to PascalCase, stripping non-alphanumeric characters.

    Covers: OG-08, OG-09, OG-10, OG-11
    """
    tokens = re.split(r"[^A-Za-z0-9]+", s)

    def _title_case(token: str) -> str:
        # Preserve tokens that already have mixed case (e.g. "InjectableInput")
        if token.isupper() or token.islower():
            return token[0].upper() + token[1:].lower()
        return token

    result = "".join(_title_case(token) for token in tokens if token)

    if result in RESERVED_KINDS:
        warnings.warn(
            f"Kind '{result}' (from '{s}') collides with a reserved BloodHound "
            f"edge kind — this edge may silently conflict on ingest.",
            stacklevel=2,
        )

    return result


def _flatten_properties(props: dict) -> dict:
    """Flatten and sanitize a properties dict for OpenGraph ingestion.

    Covers: OG-12, OG-13, OG-14, OG-15
    """
    out: dict[str, Any] = {}

    for raw_key, value in props.items():
        key = raw_key.lower()

        if value is None or isinstance(value, (str, int, float, bool)):
            out[key] = value

        elif isinstance(value, list):
            if len(value) == 0:
                out[key] = value
            else:
                first_type = type(value[0])
                if (
                    first_type in (str, int, float, bool)
                    and all(type(v) is first_type for v in value)
                ):
                    out[key] = value
                else:
                    warnings.warn(
                        f"Property '{raw_key}' is a heterogeneous or non-primitive "
                        f"array — dropped to avoid ingest failure.",
                        stacklevel=2,
                    )

        elif isinstance(value, dict):
            warnings.warn(
                f"Property '{raw_key}' is a nested object — dropped. "
                f"Flatten it before passing to the exporter.",
                stacklevel=2,
            )

        else:
            warnings.warn(
                f"Property '{raw_key}' has unrecognized type {type(value)} — dropped.",
                stacklevel=2,
            )

    return out


def _serialize_node(node: Node, strip_branding: bool) -> dict[str, Any]:
    """Serialize a single Node to the OpenGraph wire format.

    Covers: OG-03, OG-04, OG-16, OG-17, OG-18
    """
    objectid = node.objectid

    if strip_branding and objectid.startswith("AH-"):
        objectid = objectid[3:]

    kinds = [_sanitize_kind(node.kind.value)]

    if not strip_branding:
        kinds.append(SOURCE_KIND)

    # NOTE: `objectid` deliberately does NOT go in properties. BloodHound's
    # generic-ingest node schema forbids it there (`property_map` carries a
    # `not: {required: [objectid]}` clause) because objectid is derived from the
    # top-level `id`. Emitting it as a property fails schema validation on ingest.
    raw_props = {
        "name": node.name,
        "stable_id": node.stable_id,
        **node.properties,
    }

    return {
        "id": objectid,
        "kinds": kinds,
        "properties": _flatten_properties(raw_props),
    }


def _serialize_edge(edge: Edge, strip_branding: bool, known_ids: set[str]) -> dict[str, Any] | None:
    """Serialize a single Edge to the OpenGraph wire format.

    Returns ``None`` if the edge is dangling (one or both endpoints missing
    from the node set). Covers: OG-05, OG-06, OG-07
    """
    source_id = edge.source_id
    target_id = edge.target_id

    if strip_branding:
        if source_id.startswith("AH-"):
            source_id = source_id[3:]
        if target_id.startswith("AH-"):
            target_id = target_id[3:]

    if source_id not in known_ids or target_id not in known_ids:
        warnings.warn(
            f"Edge {edge.kind.value} ({edge.source_id} → {edge.target_id}) "
            f"references a node not in this export — edge dropped.",
            stacklevel=2,
        )
        return None

    raw_edge_props = {
        "is_coercion": edge.is_coercion,
        **edge.properties,
    }

    return {
        "kind": _sanitize_kind(edge.kind.value),
        "start": {"value": source_id, "match_by": "id"},
        "end": {"value": target_id, "match_by": "id"},
        "properties": _flatten_properties(raw_edge_props),
    }


def build_payload(
    nodes: list[Node], edges: list[Edge], strip_branding: bool = False
) -> OpenGraphPayload:
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
            merged = dict(seen_nodes[n.objectid].properties)
            merged.update(n.properties)
            seen_nodes[n.objectid] = Node(
                kind=n.kind, name=n.name, stable_id=n.stable_id, properties=merged
            )

    def effective_id(oid: str) -> str:
        return oid[3:] if (strip_branding and oid.startswith("AH-")) else oid

    known_ids = {effective_id(n.objectid) for n in seen_nodes.values()}

    seen_edges: dict[tuple[str, str, str], Edge] = {}
    for e in edges:
        key = (e.kind.value, e.source_id, e.target_id)
        seen_edges.setdefault(key, e)

    serialized_nodes = [
        _serialize_node(n, strip_branding)
        for n in seen_nodes.values()
    ]
    serialized_edges = []
    for e in seen_edges.values():
        serialized = _serialize_edge(e, strip_branding, known_ids)
        if serialized is not None:
            serialized_edges.append(serialized)

    # BloodHound's ingest metadata schema is strict (additionalProperties: false)
    # and currently permits exactly ONE optional field: `source_kind`. Counts,
    # timestamps, and tool/version are deliberately omitted — emitting them fails
    # validation on upload. See schemas/metadata.json.
    metadata: dict[str, Any] = {}
    if not strip_branding:
        metadata["source_kind"] = SOURCE_KIND

    return OpenGraphPayload(
        metadata=metadata,
        nodes=serialized_nodes,
        edges=serialized_edges,
    )
