"""AgentHound CLI.

Four subcommands chain together to produce a BloodHound OpenGraph payload:

    agenthound local [--home DIR] [--known-servers FILE] [--output FILE]
        Scan the current machine. Without --output, JSON goes to stdout.

    agenthound mcp --input INVENTORY [--output FILE]
        Analyze a curated MCP server inventory file (YAML or JSON).

    agenthound infer INPUT [INPUT ...] [--output FILE]
        Run coercion inference over one or more collection result files,
        emit the merged graph plus derived edges.

    agenthound emit INPUT [--output FILE]
        Convert a collection result into BloodHound OpenGraph JSON, ready
        for ingestion via the BloodHound CE upload UI.

Output goes to stdout by default; pass --output FILE to write a file instead.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from agenthound import __version__
from agenthound.collectors.base import CollectionResult
from agenthound.collectors.local import LocalCollector
from agenthound.collectors.mcp import MCPCollector
from agenthound.inference import CoercionInferencer
from agenthound.schema import build_payload
from agenthound.schema.edges import CoercionEdgeKind, Edge, EdgeKind, PermissionEdgeKind
from agenthound.schema.nodes import Node, NodeKind
from agenthound.schema.opengraph import _sanitize_kind

# --- Internal serialization for intermediate files ----------------------------

# Kind values are sanitized to PascalCase on OpenGraph emission (e.g. NHI -> Nhi,
# RUNS_AS -> RunsAs). That transform is lossy, so reading an emitted payload back
# into the internal model requires a reverse lookup keyed on the sanitized form.
_NODEKIND_BY_SANITIZED = {_sanitize_kind(k.value): k for k in NodeKind}
_EDGEKIND_BY_SANITIZED: dict[str, EdgeKind] = {
    _sanitize_kind(k.value): k for k in (*PermissionEdgeKind, *CoercionEdgeKind)
}


def _resolve_node_kind(value: str) -> NodeKind:
    """Resolve a node kind from either a raw enum value or its sanitized form."""
    try:
        return NodeKind(value)
    except ValueError:
        return _NODEKIND_BY_SANITIZED[value]


def _resolve_edge_kind(value: str) -> EdgeKind:
    """Resolve an edge kind from either a raw enum value or its sanitized form."""
    for enum_cls in (PermissionEdgeKind, CoercionEdgeKind):
        try:
            return enum_cls(value)
        except ValueError:
            continue
    return _EDGEKIND_BY_SANITIZED[value]


def _result_to_json(result: CollectionResult, strip_branding: bool = False) -> dict:
    return build_payload(result.nodes, result.edges, strip_branding=strip_branding).to_dict()


def _result_from_json(data: dict) -> CollectionResult:
    result = CollectionResult()

    # Support OpenGraph format or legacy intermediate format
    if "graph" in data:
        nodes_data = data["graph"].get("nodes", [])
        edges_data = data["graph"].get("edges", [])
    else:
        nodes_data = data.get("nodes", [])
        edges_data = data.get("edges", [])

    for raw in nodes_data:
        if "kinds" in raw:
            # OpenGraph node
            kinds = raw.get("kinds", [])
            kind_str = [k for k in kinds if k != "AgentHound"][0]
            kind = _resolve_node_kind(kind_str)
            props = raw.get("properties", {})
            name = props.get("name", "Unknown")
            stable_id = props.get("stable_id", raw["id"])
        else:
            kind = _resolve_node_kind(raw["kind"])
            name = raw["name"]
            stable_id = raw["stable_id"]
            props = raw.get("properties", {})

        result.nodes.append(
            Node(
                kind=kind,
                name=name,
                stable_id=stable_id,
                properties=props,
            )
        )

    for raw in edges_data:
        if "start" in raw:
            # OpenGraph edge
            kind_value = raw["kind"]
            source_id = raw["start"]["value"]
            target_id = raw["end"]["value"]
            props = raw.get("properties", {})
        else:
            kind_value = raw["kind"]
            source_id = raw["source_id"]
            target_id = raw["target_id"]
            props = raw.get("properties", {})

        edge_kind = _resolve_edge_kind(kind_value)

        result.edges.append(
            Edge(
                kind=edge_kind,
                source_id=source_id,
                target_id=target_id,
                properties=props,
            )
        )

    result.warnings = data.get("warnings", []) if "warnings" in data else []
    return result


# --- Output handling ----------------------------------------------------------

def _write_bytes(data: bytes, output: Path | None) -> None:
    """Write to stdout (default) or to a file when --output is given."""
    if output is None:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.write(b"\n")
        sys.stdout.buffer.flush()
    else:
        output.write_bytes(data)


def _write_result(
    result: CollectionResult, output: Path | None, strip_branding: bool = False
) -> None:
    payload = json.dumps(_result_to_json(result, strip_branding), indent=2).encode()
    _write_bytes(payload, output)
    if output is not None:
        click.echo(
            f"Wrote {len(result.nodes)} nodes, {len(result.edges)} edges → {output}",
            err=True,
        )
    for w in result.warnings:
        click.echo(f"  warning: {w}", err=True)


# --- Click command group ------------------------------------------------------

@click.group()
@click.version_option(version=__version__, prog_name="agenthound")
def main() -> None:
    """AgentHound — graph-based attack path mapping for AI agent ecosystems."""


@main.command("local")
@click.option("--home", type=click.Path(path_type=Path), default=None, help="Home dir to scan.")
@click.option("--hostname", type=str, default=None, help="Override detected hostname.")
@click.option(
    "--known-servers",
    type=click.Path(path_type=Path, exists=True),
    default=None,
    help="Path to a YAML registry overlay extending the bundled known-servers list.",
)
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--no-branding", is_flag=True, help="Strip AgentHound branding for clean merges.")
def cmd_local(
    home: Path | None,
    hostname: str | None,
    known_servers: Path | None,
    output: Path | None,
    no_branding: bool,
) -> None:
    """Scan the current machine for AI agents and reachable NHIs."""
    collector = LocalCollector(home=home, hostname=hostname, known_servers=known_servers)
    _write_result(collector.collect(), output, strip_branding=no_branding)


@main.command("mcp")
@click.option(
    "--input", "-i", "inventory",
    type=click.Path(path_type=Path, exists=True), required=True,
)
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--no-branding", is_flag=True, help="Strip AgentHound branding for clean merges.")
def cmd_mcp(inventory: Path, output: Path | None, no_branding: bool) -> None:
    """Analyze a curated MCP server inventory file (YAML or JSON)."""
    collector = MCPCollector(inventory_path=inventory)
    _write_result(collector.collect(), output, strip_branding=no_branding)


@main.command("infer")
@click.argument("inputs", nargs=-1, type=click.Path(path_type=Path, exists=True), required=True)
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--no-branding", is_flag=True, help="Strip AgentHound branding for clean merges.")
def cmd_infer(inputs: tuple[Path, ...], output: Path | None, no_branding: bool) -> None:
    """Merge collection results and derive coercion edges."""
    merged = CollectionResult()
    for path in inputs:
        data = json.loads(path.read_text())
        merged.extend(_result_from_json(data))

    derived = CoercionInferencer().infer(merged)
    merged.extend(derived)
    _write_result(merged, output, strip_branding=no_branding)


@main.command("emit")
@click.argument("input_path", type=click.Path(path_type=Path, exists=True))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--no-branding", is_flag=True, help="Strip AgentHound branding for clean merges.")
def cmd_emit(input_path: Path, output: Path | None, no_branding: bool) -> None:
    """Emit a BloodHound OpenGraph JSON payload."""
    data = json.loads(input_path.read_text())
    result = _result_from_json(data)
    payload = build_payload(result.nodes, result.edges, strip_branding=no_branding)
    payload_bytes = json.dumps(payload.to_dict(), indent=2).encode("utf-8")
    _write_bytes(payload_bytes, output)
    if output is not None:
        click.echo(
            f"Wrote OpenGraph payload: {len(payload.nodes)} nodes, "
            f"{len(payload.edges)} edges → {output}",
            err=True,
        )


if __name__ == "__main__":
    sys.exit(main())
