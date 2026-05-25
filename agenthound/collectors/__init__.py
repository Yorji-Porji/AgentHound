"""Collectors: modules that scan the world and emit nodes and edges."""

from agenthound.collectors.base import CollectionResult, Collector
from agenthound.collectors.local import AGENT_KINDS, CRED_PROVIDERS, LocalCollector
from agenthound.collectors.mcp import MCPCollector

__all__ = [
    "Collector",
    "CollectionResult",
    "LocalCollector",
    "MCPCollector",
    "AGENT_KINDS",
    "CRED_PROVIDERS",
]
