"""Edge kinds for the AgentHound graph.

Two edge classes:

- **PermissionEdgeKind** — standard authority. "Identity X is allowed to do Y."
  Maps cleanly to how BloodHound, Pathfinder, and the CIEM tools already think.

- **CoercionEdgeKind** — the novel contribution. "Identity X can be *made* to
  do Y by untrusted input reaching its context." These edges encode prompt-
  injection reachability as a first-class graph relationship.

Reachability queries combining the two classes answer questions no existing
attack path tool can answer today.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PermissionEdgeKind(str, Enum):
    """Edges that encode actual permissions an identity holds."""

    RUNS_AS = "RUNS_AS"  # Agent → AgentRuntime
    HOSTED_ON = "HOSTED_ON"  # AgentRuntime → Developer machine context
    TRUSTS = "TRUSTS"  # Developer → Agent (the agent inherits dev authority)
    HAS_SYSTEM_PROMPT = "HAS_SYSTEM_PROMPT"  # Agent → SystemPrompt
    CALLS_TOOL = "CALLS_TOOL"  # Agent → MCPTool
    EXPOSES = "EXPOSES"  # MCPServer → MCPTool
    AUTHENTICATES_AS = "AUTHENTICATES_AS"  # MCPServer/MCPTool → NHI
    GRANTS_ACCESS = "GRANTS_ACCESS"  # NHI → Resource
    CAN_READ_CRED = "CAN_READ_CRED"  # AgentRuntime → NHI (cred pickup)
    CONFIGURED_BY = "CONFIGURED_BY"  # MCPServer → Developer


class CoercionEdgeKind(str, Enum):
    """Edges that encode coercion reachability — the prompt injection model."""

    COERCES = "COERCES"  # InjectableInput → Agent
    IS_INJECTION_SINK = "IS_INJECTION_SINK"  # MCPTool → Agent (surfaces back to ctx)
    IS_INJECTION_SOURCE = "IS_INJECTION_SOURCE"  # MCPTool → InjectableInput
    SHADOWED_BY = "SHADOWED_BY"  # MCPTool → MCPTool (cross-server description shadowing)
    ESCALATES_VIA = "ESCALATES_VIA"  # Agent → MCPTool (induced privileged invocation)


EdgeKind = PermissionEdgeKind | CoercionEdgeKind


@dataclass
class Edge:
    """A graph edge.

    `source_id` and `target_id` are node objectids (see Node.objectid).

    Coercion edges carry an `injection_class` property naming the technique
    (direct, indirect, stored, shadow, schema_poisoning, tool_poisoning). This
    is how Cypher queries can rank paths by exploit difficulty.
    """

    kind: EdgeKind
    source_id: str
    target_id: str
    properties: dict[str, Any] = field(default_factory=dict)

    @property
    def is_coercion(self) -> bool:
        return isinstance(self.kind, CoercionEdgeKind)
