"""Node kinds for the AgentHound graph.

Each node represents a distinct entity in the AI agent ecosystem. The taxonomy
is deliberately separated from BloodHound's existing AD/Azure/GitHub kinds so
the AgentHound subgraph can be stitched into a larger BloodHound graph without
namespace collisions.

All node kinds are prefixed `AH` when emitted to OpenGraph (see opengraph.py)
so an analyst can immediately tell which subgraph a node came from.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NodeKind(str, Enum):
    """Entity types in the AgentHound graph."""

    # AI agent layer
    AGENT = "Agent"
    AGENT_RUNTIME = "AgentRuntime"

    # MCP / tool layer
    MCP_SERVER = "MCPServer"
    MCP_TOOL = "MCPTool"

    # Identity and resource layer
    NHI = "NHI"  # non-human identity (OAuth app, service account, API key, cert)
    RESOURCE = "Resource"  # reachable backend object (bucket, repo, table, channel)

    # Trust / coercion sources
    DEVELOPER = "Developer"
    INJECTABLE_INPUT = "InjectableInput"


@dataclass
class Node:
    """A graph node.

    `kind` is the primary type. `properties` carry arbitrary metadata that
    Cypher queries can filter on (e.g. `tier='production'` on a Resource).

    `objectid` is computed from a stable identifier so collectors run on the
    same host produce the same graph across runs.
    """

    kind: NodeKind
    name: str
    stable_id: str  # human-meaningful identifier used to derive objectid
    properties: dict[str, Any] = field(default_factory=dict)

    @property
    def objectid(self) -> str:
        """Stable, deterministic ID. SHA-1 of `{kind}:{stable_id}`."""
        digest = hashlib.sha1(
            f"{self.kind.value}:{self.stable_id}".encode(), usedforsecurity=False
        ).hexdigest()
        return f"AH-{self.kind.value}-{digest[:16]}"


def agent_node(name: str, kind_detail: str, install_path: str | None = None) -> Node:
    """Build an Agent node for a detected AI assistant."""
    props: dict[str, Any] = {"agent_kind": kind_detail}
    if install_path:
        props["install_path"] = install_path
    return Node(kind=NodeKind.AGENT, name=name, stable_id=f"{kind_detail}:{name}", properties=props)


def runtime_node(hostname: str, runtime_kind: str, os_name: str | None = None) -> Node:
    """Build an AgentRuntime node for the environment hosting an agent."""
    props: dict[str, Any] = {"runtime_kind": runtime_kind}
    if os_name:
        props["os"] = os_name
    return Node(
        kind=NodeKind.AGENT_RUNTIME,
        name=hostname,
        stable_id=f"{runtime_kind}:{hostname}",
        properties=props,
    )


def mcp_server_node(name: str, transport: str, config_source: str) -> Node:
    """Build an MCPServer node.

    Identity is `name`-only so two collectors observing the same logical server
    (e.g. a local config scan and a documented inventory) produce the same
    objectid and join into one node. `config_source` becomes a property on the
    node, listing every observation site.
    """
    return Node(
        kind=NodeKind.MCP_SERVER,
        name=name,
        stable_id=f"mcp:{name}",
        properties={"transport": transport, "config_source": config_source},
    )


def mcp_tool_node(server_name: str, tool_name: str, classification: list[str]) -> Node:
    """Build an MCPTool node, annotated with its injection-vector classification.

    `classification` is a list of tags from the injection taxonomy:
    `url_fetcher`, `file_reader`, `rag_retriever`, `mail_reader`, `shell_executor`,
    `code_writer`, `cloud_mutator`, `query_runner`.
    """
    return Node(
        kind=NodeKind.MCP_TOOL,
        name=f"{server_name}/{tool_name}",
        stable_id=f"mcp_tool:{server_name}:{tool_name}",
        properties={
            "server": server_name,
            "tool": tool_name,
            "classification": classification,
        },
    )


def nhi_node(provider: str, identifier: str, nhi_type: str) -> Node:
    """Build an NHI node.

    `provider` is the upstream system (github, aws, gcp, slack, salesforce, npm...).
    `identifier` is a stable reference within that provider (account ID,
    public-key filename, OAuth app ID). Never the credential value itself.
    """
    return Node(
        kind=NodeKind.NHI,
        name=f"{provider}:{identifier}",
        stable_id=f"nhi:{provider}:{identifier}",
        properties={"provider": provider, "nhi_type": nhi_type, "identifier": identifier},
    )


def resource_node(provider: str, kind: str, identifier: str, tier: str = "unknown") -> Node:
    """Build a Resource node.

    `tier` is one of `production`, `staging`, `dev`, `unknown`. Production-tier
    tagging drives the headline reachability query.
    """
    return Node(
        kind=NodeKind.RESOURCE,
        name=f"{provider}:{kind}:{identifier}",
        stable_id=f"resource:{provider}:{kind}:{identifier}",
        properties={"provider": provider, "resource_kind": kind, "tier": tier},
    )


def developer_node(username: str, hostname: str) -> Node:
    """Build a Developer node."""
    return Node(
        kind=NodeKind.DEVELOPER,
        name=f"{username}@{hostname}",
        stable_id=f"dev:{username}@{hostname}",
        properties={"username": username, "host": hostname},
    )


def injectable_input_node(source_kind: str, descriptor: str) -> Node:
    """Build an InjectableInput node.

    `source_kind` describes the channel: `web_fetch`, `rag_index`, `email`,
    `filesystem`. `descriptor` is a short label for the specific source
    (e.g. URL pattern, index name).
    """
    return Node(
        kind=NodeKind.INJECTABLE_INPUT,
        name=f"{source_kind}:{descriptor}",
        stable_id=f"inj:{source_kind}:{descriptor}",
        properties={"source_kind": source_kind, "descriptor": descriptor},
    )
