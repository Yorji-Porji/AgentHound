"""MCP collector.

For v0, AgentHound does not yet connect live to MCP servers to introspect
their tool surface. That requires speaking the MCP protocol over stdio or
SSE, handling auth, and dealing with servers that gate tool listing behind
authentication. It's on the roadmap.

What v0 *does* support is analyzing a curated inventory file describing MCP
servers — useful when you're auditing a target you have docs about, or when
you want to model a fleet of MCP servers without touching each developer's
machine. The inventory is a YAML/JSON file with this shape:

    servers:
      - name: salesforce-mcp
        transport: http
        url: https://mcp.example.com/salesforce
        provider: salesforce
        tools:
          - name: search_records
            classification: [rag_retriever, query_runner]
          - name: update_record
            classification: [cloud_mutator]
        backing_nhi:
          provider: salesforce
          identifier: oauth_app_42
          nhi_type: oauth_app
        accessible_resources:
          - provider: salesforce
            kind: object
            identifier: Account
            tier: production
          - provider: salesforce
            kind: object
            identifier: Opportunity
            tier: production

Future versions will replace this with live introspection and a known-server
intelligence feed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from agenthound.collectors.base import CollectionResult, Collector

if TYPE_CHECKING:
    from agenthound.audit import AuditLog
    from agenthound.scope import ScopeGuard
from agenthound.schema.edges import Edge, PermissionEdgeKind
from agenthound.schema.nodes import (
    mcp_server_node,
    mcp_tool_node,
    nhi_node,
    resource_node,
)


class MCPCollector(Collector):
    """Read a curated MCP server inventory and emit the corresponding subgraph."""

    def __init__(
        self,
        inventory_path: Path,
        *,
        guard: ScopeGuard | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        super().__init__(guard=guard, audit=audit)
        self.inventory_path = inventory_path

    def collect(self) -> CollectionResult:
        result = CollectionResult()
        if not self.allow_path(self.inventory_path, f"mcp-inventory:{self.inventory_path}"):
            return result
        try:
            text = self.inventory_path.read_text()
        except OSError as e:
            result.warnings.append(f"Could not read inventory: {e}")
            return result

        try:
            if self.inventory_path.suffix in {".yaml", ".yml"}:
                data = yaml.safe_load(text)
            else:
                data = json.loads(text)
        except (yaml.YAMLError, json.JSONDecodeError) as e:
            result.warnings.append(f"Could not parse inventory: {e}")
            return result

        if not isinstance(data, dict):
            result.warnings.append("Inventory root must be a mapping with a 'servers' key.")
            return result

        servers = data.get("servers", [])
        if servers is None:
            servers = []
        if not isinstance(servers, list):
            result.warnings.append("Inventory 'servers' must be a list.")
            return result
        for index, server in enumerate(servers):
            if not isinstance(server, dict):
                result.warnings.append(
                    f"Skipping server entry at index {index}; expected a mapping."
                )
                continue
            self._emit_server(server, result)

        return result

    def _emit_server(self, server: dict[str, Any], result: CollectionResult) -> None:
        name = server.get("name")
        if not isinstance(name, str) or not name:
            result.warnings.append("Skipping server with no 'name' field.")
            return

        # Scope: a denied provider produces no node and no edge for this server.
        provider = server.get("provider") or "unknown"
        if not isinstance(provider, str):
            result.warnings.append(f"MCP server '{name}' has an invalid provider; using 'unknown'.")
            provider = "unknown"
        if not self.allow_provider(provider, f"mcp:{name}"):
            return

        transport = server.get("transport", "stdio")
        if not isinstance(transport, str):
            result.warnings.append(f"MCP server '{name}' has an invalid transport; using 'stdio'.")
            transport = "stdio"
        server_node = mcp_server_node(
            name=name, transport=transport, config_source=str(self.inventory_path)
        )
        result.nodes.append(server_node)

        # Backing NHI (the identity the server authenticates as upstream).
        backing = server.get("backing_nhi")
        nhi = None
        if isinstance(backing, dict):
            backing_provider = backing.get("provider", "unknown")
            identifier = backing.get("identifier", name)
            nhi_type = backing.get("nhi_type", "service_account")
            if not all(
                isinstance(value, str) for value in (backing_provider, identifier, nhi_type)
            ):
                result.warnings.append(
                    f"MCP server '{name}' has an invalid backing_nhi; skipping it."
                )
            elif self.allow_provider(backing_provider, f"mcp:{name}:backing_nhi"):
                nhi = nhi_node(
                    provider=backing_provider,
                    identifier=identifier,
                    nhi_type=nhi_type,
                )
                result.nodes.append(nhi)
                result.edges.append(
                    Edge(PermissionEdgeKind.AUTHENTICATES_AS, server_node.objectid, nhi.objectid)
                )
        elif backing is not None:
            result.warnings.append(
                f"MCP server '{name}' has a non-mapping backing_nhi; skipping it."
            )

        # Tools and their classifications.
        tools = server.get("tools", [])
        if tools is None:
            tools = []
        if not isinstance(tools, list):
            result.warnings.append(f"MCP server '{name}' has a non-list tools field; ignoring it.")
            tools = []
        for tool in tools:
            if not isinstance(tool, (dict, str)):
                result.warnings.append(
                    f"MCP server '{name}' has an invalid tool entry; skipping it."
                )
                continue
            tool_name = tool.get("name") if isinstance(tool, dict) else tool
            classification = (
                tool.get("classification", ["unclassified"])
                if isinstance(tool, dict)
                else ["unclassified"]
            )
            if not isinstance(tool_name, str) or not tool_name:
                result.warnings.append(
                    f"MCP server '{name}' has a tool with no valid name; skipping it."
                )
                continue
            if not isinstance(classification, list) or not all(
                isinstance(item, str) for item in classification
            ):
                result.warnings.append(
                    f"MCP tool on server '{name}' has an invalid classification; "
                    "using 'unclassified'."
                )
                classification = ["unclassified"]
            tool_node = mcp_tool_node(name, tool_name, classification=classification)
            result.nodes.append(tool_node)
            result.edges.append(
                Edge(PermissionEdgeKind.EXPOSES, server_node.objectid, tool_node.objectid)
            )

        # Accessible resources downstream of the backing NHI.
        if nhi is None:
            return
        resources = server.get("accessible_resources", [])
        if resources is None:
            resources = []
        if not isinstance(resources, list):
            result.warnings.append(
                f"MCP server '{name}' has a non-list accessible_resources field; ignoring it."
            )
            return
        for res in resources:
            if not isinstance(res, dict):
                result.warnings.append(
                    f"MCP server '{name}' has a non-mapping resource entry; skipping it."
                )
                continue
            resource_provider = res.get("provider", "unknown")
            kind = res.get("kind", "object")
            identifier = res.get("identifier", "unknown")
            tier = res.get("tier", "unknown")
            if not all(
                isinstance(value, str)
                for value in (resource_provider, kind, identifier, tier)
            ):
                result.warnings.append(
                    f"MCP server '{name}' has an invalid resource entry; skipping it."
                )
                continue
            if not self.allow_provider(resource_provider, f"mcp:{name}:resource"):
                continue
            resource = resource_node(
                provider=resource_provider,
                kind=kind,
                identifier=identifier,
                tier=tier,
            )
            result.nodes.append(resource)
            result.edges.append(
                Edge(PermissionEdgeKind.GRANTS_ACCESS, nhi.objectid, resource.objectid)
            )
