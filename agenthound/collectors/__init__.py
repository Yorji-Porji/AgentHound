"""Collectors: modules that scan the world and emit nodes and edges."""

from agenthound.collectors.aws_iam import AWSIAMCollector
from agenthound.collectors.azure_rbac import AzureRBACCollector
from agenthound.collectors.base import CollectionResult, Collector
from agenthound.collectors.gcp_iam import GCPIAMCollector
from agenthound.collectors.local import LocalCollector
from agenthound.collectors.mcp import MCPCollector

__all__ = [
    "Collector",
    "CollectionResult",
    "LocalCollector",
    "MCPCollector",
    "AWSIAMCollector",
    "GCPIAMCollector",
    "AzureRBACCollector",
]
