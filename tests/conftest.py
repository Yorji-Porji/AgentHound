"""Shared fixtures for the AgentHound test suite.

Implements the fixtures named in `testplans.md` §0. Native graphs are built in
AgentHound's internal Node/Edge model (where nested props are allowed); the
OpenGraph exporter is what flattens/sanitizes them on the way out.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agenthound.schema.edges import CoercionEdgeKind, Edge, PermissionEdgeKind
from agenthound.schema.nodes import Node, NodeKind

FIXTURE_DIR = Path(__file__).parent / "fixtures"
SCHEMA_DIR = Path(__file__).parent.parent / "schemas"


# --- Vendored BloodHound schemas ---------------------------------------------

@pytest.fixture(scope="session")
def node_schema() -> dict:
    return json.loads((SCHEMA_DIR / "node.json").read_text())


@pytest.fixture(scope="session")
def edge_schema() -> dict:
    return json.loads((SCHEMA_DIR / "edge.json").read_text())


@pytest.fixture(scope="session")
def metadata_schema() -> dict:
    return json.loads((SCHEMA_DIR / "metadata.json").read_text())


# --- Native (internal-model) graphs ------------------------------------------

@pytest.fixture
def native_graph_min() -> tuple[list[Node], list[Edge]]:
    """2 nodes + 1 edge — the smallest meaningful graph (P1-W1-OG-01/05)."""
    agent = Node(
        kind=NodeKind.AGENT,
        name="cursor@host",
        stable_id="cursor:cursor@host",
        properties={"agent_kind": "cursor"},
    )
    runtime = Node(
        kind=NodeKind.AGENT_RUNTIME,
        name="host",
        stable_id="workstation:host",
        properties={"runtime_kind": "workstation"},
    )
    edge = Edge(PermissionEdgeKind.RUNS_AS, agent.objectid, runtime.objectid)
    return [agent, runtime], [edge]


@pytest.fixture
def native_graph_full() -> tuple[list[Node], list[Edge]]:
    """agent → MCP tool → NHI → resource, plus a coercion edge (P1-W1-OG-22).

    The COERCES edge carries an ``attck`` property so OG-06 can assert it
    survives export.
    """
    agent = Node(
        NodeKind.AGENT, "claude@host", "claude_code:claude@host", {"agent_kind": "claude_code"}
    )
    tool = Node(
        NodeKind.MCP_TOOL,
        "fetch/fetch_url",
        "mcp_tool:fetch:fetch_url",
        {"server": "fetch", "tool": "fetch_url", "classification": ["url_fetcher"]},
    )
    nhi = Node(
        NodeKind.NHI, "salesforce:oauth_app_42", "nhi:salesforce:oauth_app_42",
        {"provider": "salesforce", "nhi_type": "oauth_app"},
    )
    resource = Node(
        NodeKind.RESOURCE, "salesforce:object:Account", "resource:salesforce:object:Account",
        {"provider": "salesforce", "tier": "production"},
    )
    inj = Node(
        NodeKind.INJECTABLE_INPUT, "web_fetch:fetch/remote_url", "inj:web_fetch:fetch/remote_url",
        {"source_kind": "web_fetch"},
    )

    nodes = [agent, tool, nhi, resource, inj]
    edges = [
        Edge(PermissionEdgeKind.CALLS_TOOL, agent.objectid, tool.objectid),
        Edge(PermissionEdgeKind.AUTHENTICATES_AS, tool.objectid, nhi.objectid),
        Edge(PermissionEdgeKind.GRANTS_ACCESS, nhi.objectid, resource.objectid),
        Edge(
            CoercionEdgeKind.COERCES,
            inj.objectid,
            agent.objectid,
            properties={"injection_class": "direct", "attck": "T1059"},
        ),
    ]
    return nodes, edges


@pytest.fixture
def native_graph_dirty() -> tuple[list[Node], list[Edge]]:
    """Node properties that exercise the flattener/sanitizer (P1-W1-OG-12..15).

    Includes a nested object, a heterogeneous array, a homogeneous array, and a
    mixed-case key. The exporter must flatten/drop/lowercase these.
    """
    node = Node(
        kind=NodeKind.MCP_SERVER,
        name="dirty-server",
        stable_id="mcp:dirty-server",
        properties={
            "NestedObj": {"should": "drop"},          # OG-12 nested → drop
            "HeteroArray": [1, "a", True],            # OG-13 heterogeneous → drop
            "transports": ["smb", "https"],           # OG-14 homogeneous → keep
            "DisplayName": "Dirty Server",            # OG-15 mixed-case key → lowercase
            "count": 3,                               # primitive → keep
        },
    )
    return [node], []


# --- OpenGraph JSON fixtures on disk -----------------------------------------

@pytest.fixture(scope="session")
def og_minimal() -> dict:
    return json.loads((FIXTURE_DIR / "og_minimal.json").read_text())


def _load_malformed(name: str) -> dict:
    return json.loads((FIXTURE_DIR / name).read_text())


@pytest.fixture(scope="session")
def malformed_nodes() -> dict[str, dict]:
    """name -> a single malformed *node* object that must fail node.json."""
    return {
        "missing_kinds": _load_malformed("og_malformed_missing_kinds.json"),
        "four_kinds": _load_malformed("og_malformed_four_kinds.json"),
        "nested_prop": _load_malformed("og_malformed_nested_prop.json"),
        "objectid_prop": _load_malformed("og_malformed_objectid_prop.json"),
    }


@pytest.fixture(scope="session")
def malformed_edges() -> dict[str, dict]:
    """name -> a single malformed *edge* object that must fail edge.json."""
    return {
        "string_endpoints": _load_malformed("og_malformed_string_endpoints.json"),
    }
