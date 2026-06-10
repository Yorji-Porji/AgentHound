"""AgentHound CLI.

Four subcommands chain together to produce a BloodHound OpenGraph payload:

    agenthound local [--home DIR] [--known-servers FILE] [--output FILE]
        Scan the current machine. Without --output, JSON goes to stdout.

    agenthound offline ARCHIVE [--hostname NAME] [--output FILE]
        Analyze a captured snapshot of an *offline* host (a tarball of its
        config/credential paths), instead of scanning a live machine you're on.
        "Offline" = the target host, not the tool (which is network-free either
        way). Same graph as `local`; untrusted archives are extracted safely.

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
import os
import sys
import tarfile
from pathlib import Path

import click
import yaml
from pydantic import ValidationError

from agenthound import __version__
from agenthound.audit import AuditError, AuditLog, verify_audit_log
from agenthound.collectors.aws_iam import AWSIAMCollector
from agenthound.collectors.base import CollectionResult
from agenthound.collectors.local import LocalCollector
from agenthound.collectors.mcp import MCPCollector
from agenthound.inference import CoercionInferencer
from agenthound.offline import UnsafeArchiveError, extracted_home
from agenthound.schema import build_payload
from agenthound.schema.edges import CoercionEdgeKind, Edge, EdgeKind, PermissionEdgeKind
from agenthound.schema.nodes import Node, NodeKind
from agenthound.schema.opengraph import _sanitize_kind
from agenthound.scope import EngagementScope, ScopeExpired, ScopeGuard

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
    """Read an emitted OpenGraph payload back into the internal model.

    Accepts the shape AgentHound itself writes — a top-level ``graph`` wrapper
    (or a bare ``{nodes, edges}``). Malformed input raises here and is turned
    into a clean error by :func:`_load_collection_file`.
    """
    result = CollectionResult()
    graph = data.get("graph", data)
    for raw in graph.get("nodes", []):
        kind = _resolve_node_kind([k for k in raw.get("kinds", []) if k != "AgentHound"][0])
        props = raw.get("properties", {})
        result.nodes.append(
            Node(
                kind=kind,
                name=props.get("name", "Unknown"),
                stable_id=props.get("stable_id", raw["id"]),
                properties=props,
            )
        )
    for raw in graph.get("edges", []):
        result.edges.append(
            Edge(
                kind=_resolve_edge_kind(raw["kind"]),
                source_id=raw["start"]["value"],
                target_id=raw["end"]["value"],
                properties=raw.get("properties", {}),
            )
        )
    result.warnings = data.get("warnings", [])
    return result


def _load_collection_file(path: Path) -> CollectionResult:
    """Read an intermediate collection/graph JSON file, failing cleanly on garbage.

    ``infer``/``emit`` take operator-provided files; a malformed or wrong-shaped
    one should produce a clean error, not a traceback — matching the fail-soft
    posture the collectors already hold.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return _result_from_json(data)
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        KeyError,
        IndexError,
        TypeError,
        AttributeError,
    ) as exc:
        raise click.ClickException(f"Could not read collection file {path}: {exc}") from exc


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


# --- Scope & audit activation -------------------------------------------------

AUDIT_KEY_ENV = "AGENTHOUND_AUDIT_KEY"


def _activate_scope(
    scope_path: Path | None,
) -> tuple[ScopeGuard | None, AuditLog | None]:
    """Load a scope file (opt-in) and enforce the startup gates.

    Returns ``(guard, audit)`` — both ``None`` when no ``--scope`` was given, so
    unscoped runs behave exactly as before. Raises ``click.ClickException`` on
    any refusal (expired authorization, missing audit key, outside time window)
    so the CLI exits non-zero *before* any collector runs.
    """
    if scope_path is None:
        return None, None

    try:
        scope = EngagementScope.from_yaml(scope_path)
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        raise click.ClickException(f"Invalid scope file {scope_path}: {exc}") from exc

    try:
        guard = ScopeGuard(scope)
    except ScopeExpired as exc:
        raise click.ClickException(str(exc)) from exc

    audit: AuditLog | None = None
    if scope.audit_log:
        try:
            audit = AuditLog(scope.audit_log, os.environ.get(AUDIT_KEY_ENV, ""))
        except AuditError as exc:
            raise click.ClickException(str(exc)) from exc

    # Startup time-window gate: refuse to run outside an authorized window.
    if not guard.check_time():
        if audit is not None:
            audit.record("run", scope.engagement, "SKIPPED", "outside authorized time window")
        raise click.ClickException(
            f"Engagement '{scope.engagement}': outside an authorized time window; refusing to run."
        )

    if audit is not None:
        audit.record("run", scope.engagement, "ALLOW", "scope active; run authorized")

    return guard, audit


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
@click.option(
    "--scope",
    type=click.Path(path_type=Path, exists=True),
    default=None,
    help="Engagement scope YAML. Enforces provider/path/time limits and audit logging.",
)
def cmd_local(
    home: Path | None,
    hostname: str | None,
    known_servers: Path | None,
    output: Path | None,
    no_branding: bool,
    scope: Path | None,
) -> None:
    """Scan the current machine for AI agents and reachable NHIs."""
    guard, audit = _activate_scope(scope)
    collector = LocalCollector(
        home=home, hostname=hostname, known_servers=known_servers, guard=guard, audit=audit
    )
    _write_result(collector.collect(), output, strip_branding=no_branding)


@main.command("offline")
@click.argument("archive", type=click.Path(path_type=Path, exists=True))
@click.option(
    "--hostname",
    type=str,
    default="offline",
    show_default=True,
    help="Hostname for the captured host. Set this to the real host for stable node identity.",
)
@click.option(
    "--known-servers",
    type=click.Path(path_type=Path, exists=True),
    default=None,
    help="Path to a YAML registry overlay extending the bundled known-servers list.",
)
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--no-branding", is_flag=True, help="Strip AgentHound branding for clean merges.")
@click.option(
    "--scope",
    type=click.Path(path_type=Path, exists=True),
    default=None,
    help="Engagement scope YAML. Enforces provider/path/time limits and audit logging.",
)
def cmd_offline(
    archive: Path,
    hostname: str,
    known_servers: Path | None,
    output: Path | None,
    no_branding: bool,
    scope: Path | None,
) -> None:
    """Analyze a captured (offline) host from a tarball, not a live machine.

    "Offline" refers to the *target*: you analyze a captured snapshot of a host
    rather than one you're sitting on. (The whole tool is already network-free;
    this is about *where the data comes from*, not network behavior.)

    ARCHIVE is a .tar(.gz/.bz2/.xz) of the paths the local collector scans
    (.aws/, .ssh/, .config/Claude/, .npmrc, ...), laid out as under a home
    directory. Untrusted archives are extracted defensively (no path traversal
    or escaping links). Produces the same graph a live `local` run would; the
    value is the capture / clean-room workflow, not a different analysis.

    For a host you ARE on, use `local` (or `local --home DIR`).
    """
    guard, audit = _activate_scope(scope)
    try:
        with extracted_home(archive) as home:
            collector = LocalCollector(
                home=home,
                hostname=hostname,
                known_servers=known_servers,
                guard=guard,
                audit=audit,
            )
            result = collector.collect()
    except (UnsafeArchiveError, tarfile.TarError, OSError) as exc:
        raise click.ClickException(f"Could not analyze archive {archive}: {exc}") from exc
    _write_result(result, output, strip_branding=no_branding)


@main.command("mcp")
@click.option(
    "--input", "-i", "inventory",
    type=click.Path(path_type=Path, exists=True), required=True,
)
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--no-branding", is_flag=True, help="Strip AgentHound branding for clean merges.")
@click.option(
    "--scope",
    type=click.Path(path_type=Path, exists=True),
    default=None,
    help="Engagement scope YAML. Enforces provider/path/time limits and audit logging.",
)
def cmd_mcp(inventory: Path, output: Path | None, no_branding: bool, scope: Path | None) -> None:
    """Analyze a curated MCP server inventory file (YAML or JSON)."""
    guard, audit = _activate_scope(scope)
    collector = MCPCollector(inventory_path=inventory, guard=guard, audit=audit)
    _write_result(collector.collect(), output, strip_branding=no_branding)


@main.command("aws-iam")
@click.option(
    "--import", "-i", "import_path",
    type=click.Path(path_type=Path, exists=True), required=True,
    help="An `aws iam get-account-authorization-details` JSON export to resolve.",
)
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--no-branding", is_flag=True, help="Strip AgentHound branding for clean merges.")
@click.option(
    "--scope",
    type=click.Path(path_type=Path, exists=True),
    default=None,
    help="Engagement scope YAML. Enforces provider/path/time limits and audit logging.",
)
def cmd_aws_iam(
    import_path: Path, output: Path | None, no_branding: bool, scope: Path | None
) -> None:
    """Resolve real AWS permissions from an uploaded IAM export (network-free).

    Run `aws iam get-account-authorization-details > iam.json` yourself, then
    feed the file here — AgentHound never calls AWS. Emits the identities, the
    resources their policies grant, evidence-based admin flags, and CAN_ASSUME
    edges from role trust policies.
    """
    guard, audit = _activate_scope(scope)
    try:
        collector = AWSIAMCollector(import_path, guard=guard, audit=audit)
        result = collector.collect()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise click.ClickException(
            f"Could not read AWS IAM export {import_path}: {exc}"
        ) from exc
    _write_result(result, output, strip_branding=no_branding)


@main.command("infer")
@click.argument("inputs", nargs=-1, type=click.Path(path_type=Path, exists=True), required=True)
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--no-branding", is_flag=True, help="Strip AgentHound branding for clean merges.")
def cmd_infer(inputs: tuple[Path, ...], output: Path | None, no_branding: bool) -> None:
    """Merge collection results and derive coercion edges."""
    merged = CollectionResult()
    for path in inputs:
        merged.extend(_load_collection_file(path))

    derived = CoercionInferencer().infer(merged)
    merged.extend(derived)
    _write_result(merged, output, strip_branding=no_branding)


@main.command("emit")
@click.argument("input_path", type=click.Path(path_type=Path, exists=True))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--no-branding", is_flag=True, help="Strip AgentHound branding for clean merges.")
def cmd_emit(input_path: Path, output: Path | None, no_branding: bool) -> None:
    """Emit a BloodHound OpenGraph JSON payload."""
    result = _load_collection_file(input_path)
    payload = build_payload(result.nodes, result.edges, strip_branding=no_branding)
    payload_bytes = json.dumps(payload.to_dict(), indent=2).encode("utf-8")
    _write_bytes(payload_bytes, output)
    if output is not None:
        click.echo(
            f"Wrote OpenGraph payload: {len(payload.nodes)} nodes, "
            f"{len(payload.edges)} edges → {output}",
            err=True,
        )


@main.command("verify-audit")
@click.argument("path", type=click.Path(path_type=Path, exists=True))
def cmd_verify_audit(path: Path) -> None:
    """Verify the HMAC hash-chain of an audit log written during a run.

    Reads the signing key from the AGENTHOUND_AUDIT_KEY environment variable —
    the same key the run used. Exits non-zero and names the first broken line
    if the log was edited, truncated, or reordered.
    """
    key = os.environ.get(AUDIT_KEY_ENV, "")
    if not key:
        raise click.ClickException(
            f"{AUDIT_KEY_ENV} is not set; cannot verify the audit signature."
        )
    ok, bad_index, message = verify_audit_log(path, key)
    if ok:
        click.echo(f"AUDIT OK: {message} ({path}).")
        return
    raise click.ClickException(f"AUDIT TAMPERED at line {bad_index}: {message} ({path}).")


if __name__ == "__main__":
    sys.exit(main())
