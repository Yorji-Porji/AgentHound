"""Coercion edge inference.

This module takes a collected set of nodes and edges and derives the coercion
edges that make AgentHound's graph distinctive. The inputs are the permission
edges produced by collectors; the outputs are the novel coercion edges plus
the InjectableInput nodes that anchor them.

The classification taxonomy is:

| Tag              | Role     | Why                                        |
|------------------|----------|--------------------------------------------|
| `url_fetcher`    | source   | Pulls in remote content of unknown origin  |
| `rag_retriever`  | source   | Returns indexed docs that may be poisoned  |
| `mail_reader`    | source   | Classic indirect-prompt-injection vector   |
| `file_reader`    | source   | Returns file content that may be untrusted |
| `shell_executor` | sink     | Runs commands the agent decides on         |
| `code_writer`    | sink     | Writes code that will execute              |
| `cloud_mutator`  | sink     | Mutates cloud state                        |
| `query_runner`   | both     | Reads possibly-poisoned data and writes it |
| `unclassified`   | unknown  | Surface as warning; assume both pessimistically |

A tool tagged as a *source* gets an `IS_INJECTION_SOURCE` edge to a new
InjectableInput node. A tool tagged as a *sink* is the target of the
attacker's intended chain. The headline `COERCES` edge runs from the
InjectableInput through the calling Agent.

Injection technique class (recorded on each coercion edge):

- `direct` — the source brings text the attacker controls directly into
  context (web fetch of attacker-controlled URL)
- `indirect` — the source brings text the attacker poisoned into context
  via an intermediary the user trusts (poisoned README in a starred repo,
  malicious comment on a Jira ticket the agent reads)
- `stored` — content sits at rest in a system the agent reads from (RAG
  index entries, memory store)
- `shadow` — a malicious MCP tool description influences a peer tool's
  invocation (Adversa's cross-server shadowing pattern)
"""

from __future__ import annotations

from agenthound.collectors.base import CollectionResult
from agenthound.schema.edges import CoercionEdgeKind, Edge, PermissionEdgeKind
from agenthound.schema.nodes import Node, NodeKind, injectable_input_node

SOURCE_TAGS = {"url_fetcher", "rag_retriever", "mail_reader", "file_reader"}
SINK_TAGS = {"shell_executor", "code_writer", "cloud_mutator"}
BOTH_TAGS = {"query_runner"}

TAG_TO_INJECTION_CLASS: dict[str, str] = {
    "url_fetcher": "direct",
    "rag_retriever": "stored",
    "mail_reader": "indirect",
    "file_reader": "indirect",
    "query_runner": "stored",
}

TAG_TO_SOURCE_DESCRIPTOR: dict[str, tuple[str, str]] = {
    "url_fetcher": ("web_fetch", "remote_url"),
    "rag_retriever": ("rag_index", "indexed_documents"),
    "mail_reader": ("email", "inbox"),
    "file_reader": ("filesystem", "workspace_files"),
    "query_runner": ("rag_index", "database_rows"),
}


class CoercionInferencer:
    """Compute coercion edges over a collected graph."""

    def infer(self, collected: CollectionResult) -> CollectionResult:
        """Return a new CollectionResult containing only the newly-derived
        edges and nodes (InjectableInput nodes, COERCES/IS_INJECTION_SOURCE/
        ESCALATES_VIA edges, and any propagated CALLS_TOOL edges). The caller
        merges this with the input to produce the final graph.
        """
        derived = CollectionResult()

        # Step 1: propagate CALLS_TOOL across MCPServer boundaries.
        #
        # An agent observed calling any tool of server S can in practice call
        # every tool S exposes — once the MCP client is connected to S, all
        # of S's tools are in the agent's reachable tool list. Different
        # collectors observe different subsets of S's tools (the local config
        # scan may only know the server exists; the inventory collector knows
        # the full tool surface). Joining at the server level recovers the
        # full graph.
        self._propagate_calls_tool(collected, derived)

        # Re-derive the combined CALLS_TOOL adjacency including just-emitted edges.
        callers_of: dict[str, list[str]] = {}
        for e in collected.edges + derived.edges:
            if e.kind == PermissionEdgeKind.CALLS_TOOL:
                callers_of.setdefault(e.target_id, []).append(e.source_id)

        # Step 2: walk every MCPTool, derive coercion role from classification.
        for node in collected.nodes:
            if node.kind != NodeKind.MCP_TOOL:
                continue
            tags = set(node.properties.get("classification", []))
            if not tags:
                continue

            is_source = bool(tags & (SOURCE_TAGS | BOTH_TAGS))
            is_sink = bool(tags & (SINK_TAGS | BOTH_TAGS))
            is_unclassified = "unclassified" in tags

            # Unclassified tools are treated pessimistically as both source
            # and sink — the conservative posture for offensive analysis.
            if is_unclassified:
                is_source = True
                is_sink = True

            if is_source:
                self._emit_source(node, tags, callers_of, derived)
            if is_sink:
                self._mark_sink(node, callers_of, derived)

        return derived

    # -- CALLS_TOOL and AUTHENTICATES_AS propagation ---------------------------

    def _propagate_calls_tool(
        self, collected: CollectionResult, derived: CollectionResult
    ) -> None:
        """Two propagations live here:

        1. Agents that call any tool of server S also reach every tool S
           exposes (different collectors observe different subsets).
        2. Tools inherit their server's AUTHENTICATES_AS edges — the agent's
           Cypher reachability query traverses MCPTool→NHI directly without
           needing to ricochet through the server node.
        """
        # server_id -> {tool_id}
        tools_on_server: dict[str, set[str]] = {}
        for e in collected.edges:
            if e.kind == PermissionEdgeKind.EXPOSES:
                tools_on_server.setdefault(e.source_id, set()).add(e.target_id)

        # tool_id -> server_id (one tool belongs to exactly one server)
        server_of_tool: dict[str, str] = {}
        for server_id, tools in tools_on_server.items():
            for t in tools:
                server_of_tool[t] = server_id

        # server_id -> {nhi_id}
        nhis_of_server: dict[str, set[str]] = {}
        for e in collected.edges:
            if e.kind == PermissionEdgeKind.AUTHENTICATES_AS:
                nhis_of_server.setdefault(e.source_id, set()).add(e.target_id)

        # agent_id -> {tool_id} actually observed
        agent_tools: dict[str, set[str]] = {}
        for e in collected.edges:
            if e.kind == PermissionEdgeKind.CALLS_TOOL:
                agent_tools.setdefault(e.source_id, set()).add(e.target_id)

        # (1) Fan out CALLS_TOOL across server boundaries.
        for agent_id, observed_tools in agent_tools.items():
            servers_in_reach: set[str] = set()
            for t in observed_tools:
                if t in server_of_tool:
                    servers_in_reach.add(server_of_tool[t])
            for server_id in servers_in_reach:
                for t in tools_on_server.get(server_id, set()):
                    if t not in observed_tools:
                        derived.edges.append(
                            Edge(
                                PermissionEdgeKind.CALLS_TOOL,
                                agent_id,
                                t,
                                properties={"inferred": True, "via_server": server_id},
                            )
                        )

        # (2) Each tool inherits its server's AUTHENTICATES_AS edges.
        for server_id, tools in tools_on_server.items():
            for nhi_id in nhis_of_server.get(server_id, set()):
                for tool_id in tools:
                    derived.edges.append(
                        Edge(
                            PermissionEdgeKind.AUTHENTICATES_AS,
                            tool_id,
                            nhi_id,
                            properties={"inferred": True, "via_server": server_id},
                        )
                    )

    # -- Source side -----------------------------------------------------------

    def _emit_source(
        self,
        tool: Node,
        tags: set[str],
        callers_of: dict[str, list[str]],
        derived: CollectionResult,
    ) -> None:
        """Create an InjectableInput per source tag and wire it to callers."""
        for tag in tags & (SOURCE_TAGS | BOTH_TAGS):
            source_kind, descriptor = TAG_TO_SOURCE_DESCRIPTOR.get(
                tag, ("unknown", tool.properties.get("tool", "unknown"))
            )
            injection_class = TAG_TO_INJECTION_CLASS.get(tag, "indirect")

            inj = injectable_input_node(
                source_kind=source_kind,
                descriptor=f"{tool.properties.get('server', 'unknown')}/{descriptor}",
            )
            derived.nodes.append(inj)

            # Source tool → injectable input
            derived.edges.append(
                Edge(
                    CoercionEdgeKind.IS_INJECTION_SOURCE,
                    tool.objectid,
                    inj.objectid,
                    properties={"tag": tag, "injection_class": injection_class},
                )
            )

            # Injectable input → every agent that can call this source tool.
            # This is the headline COERCES edge.
            for agent_id in callers_of.get(tool.objectid, []):
                derived.edges.append(
                    Edge(
                        CoercionEdgeKind.COERCES,
                        inj.objectid,
                        agent_id,
                        properties={
                            "via_tool": tool.objectid,
                            "injection_class": injection_class,
                            "tag": tag,
                        },
                    )
                )

    # -- Sink side -------------------------------------------------------------

    def _mark_sink(
        self,
        tool: Node,
        callers_of: dict[str, list[str]],
        derived: CollectionResult,
    ) -> None:
        """Record the agent → sink_tool relationship as ESCALATES_VIA.

        The CALLS_TOOL edge already exists from collection. ESCALATES_VIA is a
        narrower marker: "this is a tool the agent could be steered into
        invoking with attacker-chosen arguments." It lets queries filter for
        sink-tool reachability without re-classifying every CALLS_TOOL hop.
        """
        for agent_id in callers_of.get(tool.objectid, []):
            derived.edges.append(
                Edge(
                    CoercionEdgeKind.ESCALATES_VIA,
                    agent_id,
                    tool.objectid,
                    properties={"classification": tool.properties.get("classification", [])},
                )
            )
