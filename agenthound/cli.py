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
from agenthound.schema.edges import CoercionEdgeKind, Edge, PermissionEdgeKind
from agenthound.schema.nodes import Node, NodeKind


# --- Internal serialization for intermediate files ----------------------------

def _result_to_json(result: CollectionResult) -> dict:
    return {
        "nodes": [
            {
                "kind": n.kind.value,
                "name": n.name,
                "stable_id": n.stable_id,
                "properties": n.properties,
            }
            for n in result.nodes
        ],
        "edges": [
            {
                "kind": e.kind.value,
                "source_id": e.source_id,
                "target_id": e.target_id,
                "properties": e.properties,
            }
            for e in result.edges
        ],
        "warnings": result.warnings,
    }


def _result_from_json(data: dict) -> CollectionResult:
    result = CollectionResult()
    for raw in data.get("nodes", []):
        kind = NodeKind(raw["kind"])
        result.nodes.append(
            Node(
                kind=kind,
                name=raw["name"],
                stable_id=raw["stable_id"],
                properties=raw.get("properties", {}),
            )
        )
    for raw in data.get("edges", []):
        kind_value = raw["kind"]
        try:
            kind = PermissionEdgeKind(kind_value)
        except ValueError:
            kind = CoercionEdgeKind(kind_value)
        result.edges.append(
            Edge(
                kind=kind,
                source_id=raw["source_id"],
                target_id=raw["target_id"],
                properties=raw.get("properties", {}),
            )
        )
    result.warnings = data.get("warnings", [])
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


def _write_result(result: CollectionResult, output: Path | None) -> None:
    payload = json.dumps(_result_to_json(result), indent=2).encode("utf-8")
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
@click.option("--home", type=click.Path(path_type=Path), default=None, help="Home directory to scan.")
@click.option("--hostname", type=str, default=None, help="Override detected hostname.")
@click.option(
    "--known-servers",
    type=click.Path(path_type=Path, exists=True),
    default=None,
    help="Path to a YAML registry overlay extending the bundled known-servers list.",
)
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
def cmd_local(
    home: Path | None,
    hostname: str | None,
    known_servers: Path | None,
    output: Path | None,
) -> None:
    """Scan the current machine for AI agents and reachable NHIs."""
    collector = LocalCollector(home=home, hostname=hostname, known_servers=known_servers)
    _write_result(collector.collect(), output)


@main.command("mcp")
@click.option("--input", "-i", "inventory", type=click.Path(path_type=Path, exists=True), required=True)
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
def cmd_mcp(inventory: Path, output: Path | None) -> None:
    """Analyze a curated MCP server inventory file (YAML or JSON)."""
    collector = MCPCollector(inventory_path=inventory)
    _write_result(collector.collect(), output)


@main.command("infer")
@click.argument("inputs", nargs=-1, type=click.Path(path_type=Path, exists=True), required=True)
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
def cmd_infer(inputs: tuple[Path, ...], output: Path | None) -> None:
    """Merge collection results and derive coercion edges."""
    merged = CollectionResult()
    for path in inputs:
        data = json.loads(path.read_text())
        merged.extend(_result_from_json(data))

    derived = CoercionInferencer().infer(merged)
    merged.extend(derived)
    _write_result(merged, output)


@main.command("emit")
@click.argument("input_path", type=click.Path(path_type=Path, exists=True))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
def cmd_emit(input_path: Path, output: Path | None) -> None:
    """Emit a BloodHound OpenGraph JSON payload."""
    data = json.loads(input_path.read_text())
    result = _result_from_json(data)
    payload = build_payload(result.nodes, result.edges)
    payload_bytes = json.dumps(payload.to_dict(), indent=2).encode("utf-8")
    _write_bytes(payload_bytes, output)
    if output is not None:
        click.echo(
            f"Wrote OpenGraph payload: {payload.metadata['node_count']} nodes, "
            f"{payload.metadata['edge_count']} edges → {output}",
            err=True,
        )


if __name__ == "__main__":
    sys.exit(main())
