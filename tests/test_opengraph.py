"""OpenGraph exporter tests — testplans.md Phase 1, Week 1 (P1-W1-OG-01..25).

OG-26 (live ingest into BloodHound CE) is a manual/E2E check documented in
tests/e2e/README.md; it is not automated here.
"""

from __future__ import annotations

import json
import warnings

import pytest

from agenthound.schema.opengraph import (
    SOURCE_KIND,
    _flatten_properties,
    _sanitize_kind,
    build_payload,
)

jsonschema = pytest.importorskip("jsonschema")


# --- Helpers -----------------------------------------------------------------

def _validate(obj: dict, schema: dict) -> None:
    jsonschema.validate(instance=obj, schema=schema)


def _all_properties(payload: dict):
    for n in payload["graph"]["nodes"]:
        yield n.get("properties") or {}
    for e in payload["graph"]["edges"]:
        yield e.get("properties") or {}


# --- OG — envelope & structure -----------------------------------------------

def test_og01_envelope_shape(native_graph_min):
    """OG-01: top-level `graph` with `nodes` + `edges`, no stray node/edge keys."""
    nodes, edges = native_graph_min
    payload = build_payload(nodes, edges).to_dict()
    assert set(payload.keys()) == {"metadata", "graph"}
    assert set(payload["graph"].keys()) == {"nodes", "edges"}
    assert isinstance(payload["graph"]["nodes"], list)
    assert isinstance(payload["graph"]["edges"], list)


def test_og02_metadata_source_kind(native_graph_min):
    """OG-02: metadata.source_kind defaults to 'AgentHound' (branding on)."""
    nodes, edges = native_graph_min
    payload = build_payload(nodes, edges).to_dict()
    assert payload["metadata"]["source_kind"] == SOURCE_KIND


def test_og03_node_structure(native_graph_min):
    """OG-03: each node has `id` (str) + `kinds` (1-3 strings); name lives in
    properties; objectid is NOT duplicated inside properties (schema forbids it)."""
    nodes, edges = native_graph_min
    payload = build_payload(nodes, edges).to_dict()
    for n in payload["graph"]["nodes"]:
        assert isinstance(n["id"], str)
        assert 1 <= len(n["kinds"]) <= 3
        assert all(isinstance(k, str) for k in n["kinds"])
        assert "name" in n["properties"]
        assert "objectid" not in n["properties"]


def test_og04_kinds_capped_at_three(native_graph_min):
    """OG-04: nodes never emit more than MAX_KINDS (3) kinds."""
    nodes, edges = native_graph_min
    payload = build_payload(nodes, edges).to_dict()
    for n in payload["graph"]["nodes"]:
        assert len(n["kinds"]) <= 3


# --- OG — edge remap ---------------------------------------------------------

def test_og05_edge_endpoints_are_objects(native_graph_min):
    """OG-05: native source/target strings become start/end objects."""
    nodes, edges = native_graph_min
    payload = build_payload(nodes, edges).to_dict()
    for e in payload["graph"]["edges"]:
        assert e["start"]["match_by"] == "id"
        assert e["end"]["match_by"] == "id"
        assert isinstance(e["start"]["value"], str)
        assert isinstance(e["end"]["value"], str)


def test_og06_attck_preserved(native_graph_full):
    """OG-06: edge properties.attck survives export."""
    nodes, edges = native_graph_full
    payload = build_payload(nodes, edges).to_dict()
    coerces = [e for e in payload["graph"]["edges"] if e["kind"] == "Coerces"]
    assert coerces, "expected a Coerces edge"
    assert coerces[0]["properties"]["attck"] == "T1059"


def test_og07_dangling_edge_dropped(native_graph_min):
    """OG-07: an edge to a non-existent node id is dropped with a warning."""
    from agenthound.schema.edges import Edge, PermissionEdgeKind

    nodes, edges = native_graph_min
    edges = [*edges, Edge(PermissionEdgeKind.CALLS_TOOL, nodes[0].objectid, "AH-Nonexistent-000")]
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        payload = build_payload(nodes, edges).to_dict()
    assert len(payload["graph"]["edges"]) == 1  # only the valid RUNS_AS survives
    assert any("not in this export" in str(w.message) for w in caught)


# --- OG — kind sanitizer -----------------------------------------------------

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("can-coerce", "CanCoerce"),
        ("RUNS_AS", "RunsAs"),
        ("GRANTS_ACCESS", "GrantsAccess"),
        ("InvokesTool", "InvokesTool"),       # OG-10 already-clean passthrough
        ("foo bar.baz$qux", "FooBarBazQux"),
    ],
)
def test_og08_10_sanitize_kind(raw, expected):
    """OG-08/09/10: sanitizer produces PascalCase matching ^[A-Za-z0-9_]+$."""
    import re

    result = _sanitize_kind(raw)
    assert result == expected
    assert re.fullmatch(r"[A-Za-z0-9_]+", result)


def test_og11_reserved_kind_warns():
    """OG-11: emitting a reserved BloodHound kind raises a loud warning."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = _sanitize_kind("admin-to")
    assert result == "AdminTo"
    assert any("reserved" in str(w.message).lower() for w in caught)


# --- OG — property flattener -------------------------------------------------

def test_og12_nested_object_dropped():
    """OG-12: nested-object property never emitted as an object."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        out = _flatten_properties({"config": {"nested": "object"}})
    assert "config" not in out


def test_og13_heterogeneous_array_dropped():
    """OG-13: heterogeneous array property is rejected."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        out = _flatten_properties({"mixed": [1, "a", True]})
    assert "mixed" not in out


def test_og14_homogeneous_array_preserved():
    """OG-14: homogeneous primitive array is preserved."""
    out = _flatten_properties({"transports": ["smb", "https"]})
    assert out["transports"] == ["smb", "https"]


def test_og15_keys_lowercased():
    """OG-15: all property keys are lowercased."""
    out = _flatten_properties({"DisplayName": "x", "Count": 3})
    assert set(out.keys()) == {"displayname", "count"}


def test_og12_15_via_dirty_graph(native_graph_dirty):
    """OG-12..15 end-to-end through build_payload on the dirty fixture."""
    nodes, edges = native_graph_dirty
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        payload = build_payload(nodes, edges).to_dict()
    props = payload["graph"]["nodes"][0]["properties"]
    assert "nestedobj" not in props          # nested dropped
    assert "heteroarray" not in props        # heterogeneous dropped
    assert props["transports"] == ["smb", "https"]  # homogeneous kept
    assert "displayname" in props            # key lowercased
    assert all(k == k.lower() for k in props)
    assert all(not isinstance(v, dict) for v in props.values())


# --- OG — branding & output --------------------------------------------------

def test_og16_no_branding_strips_prefix(native_graph_min):
    """OG-16: --no-branding strips the AH- objectid prefix from node ids."""
    nodes, edges = native_graph_min
    payload = build_payload(nodes, edges, strip_branding=True).to_dict()
    assert all(not n["id"].startswith("AH-") for n in payload["graph"]["nodes"])
    for e in payload["graph"]["edges"]:
        assert not e["start"]["value"].startswith("AH-")
        assert not e["end"]["value"].startswith("AH-")


def test_og17_no_branding_drops_tool(native_graph_min):
    """OG-17: --no-branding drops metadata.tool and source_kind."""
    nodes, edges = native_graph_min
    payload = build_payload(nodes, edges, strip_branding=True).to_dict()
    assert "tool" not in payload["metadata"]
    assert "source_kind" not in payload["metadata"]


def test_og18_branding_on_keeps_prefix_and_tool(native_graph_min):
    """OG-18: branding on (default) keeps AH- prefix, source kind, and tool."""
    nodes, edges = native_graph_min
    payload = build_payload(nodes, edges).to_dict()
    assert any(n["id"].startswith("AH-") for n in payload["graph"]["nodes"])
    assert SOURCE_KIND in payload["graph"]["nodes"][0]["kinds"]
    assert "tool" in payload["metadata"]


# --- OG — stdout / file output (cli) -----------------------------------------

def test_og19_stdout_default(tmp_path, monkeypatch):
    """OG-19: absent --output writes JSON to stdout."""
    from click.testing import CliRunner

    from agenthound.cli import main

    inv = tmp_path / "inv.yaml"
    inv.write_text("servers:\n  - name: fetch\n    tools:\n      - name: fetch_url\n")
    runner = CliRunner()
    result = runner.invoke(main, ["mcp", "-i", str(inv)])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert "graph" in parsed


def test_og20_output_file(tmp_path):
    """OG-20: --output writes to file, not stdout."""
    from click.testing import CliRunner

    from agenthound.cli import main

    inv = tmp_path / "inv.yaml"
    inv.write_text("servers:\n  - name: fetch\n    tools:\n      - name: fetch_url\n")
    out = tmp_path / "out.json"
    runner = CliRunner()
    result = runner.invoke(main, ["mcp", "-i", str(inv), "-o", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    assert json.loads(out.read_text())["graph"]["nodes"]


def test_og21_utf8_no_bom(tmp_path):
    """OG-21: emitted file is UTF-8 with no BOM."""
    from click.testing import CliRunner

    from agenthound.cli import main

    inv = tmp_path / "inv.yaml"
    inv.write_text("servers:\n  - name: fetch\n    tools:\n      - name: fetch_url\n")
    out = tmp_path / "out.json"
    CliRunner().invoke(main, ["mcp", "-i", str(inv), "-o", str(out)])
    head = out.read_bytes()[:3]
    assert head != b"\xef\xbb\xbf"


# --- OG — schema validation gate ---------------------------------------------

def test_og22_full_graph_validates(native_graph_full, node_schema, edge_schema):
    """OG-22: export of native_graph_full validates against vendored schemas."""
    nodes, edges = native_graph_full
    payload = build_payload(nodes, edges).to_dict()
    for n in payload["graph"]["nodes"]:
        _validate(n, node_schema)
    for e in payload["graph"]["edges"]:
        _validate(e, edge_schema)


def test_og23_malformed_nodes_fail(malformed_nodes, node_schema):
    """OG-23: each malformed node fixture fails vendored-schema validation."""
    for obj in malformed_nodes.values():
        with pytest.raises(jsonschema.ValidationError):
            _validate(obj, node_schema)


def test_og23_malformed_edges_fail(malformed_edges, edge_schema):
    """OG-23: each malformed edge fixture fails vendored-schema validation."""
    for obj in malformed_edges.values():
        with pytest.raises(jsonschema.ValidationError):
            _validate(obj, edge_schema)


def test_og25_og_minimal_validates(og_minimal, node_schema, edge_schema):
    """OG-25: the known-good minimal payload validates against our schemas
    (sanity check that the vendored schema copies are correct)."""
    for n in og_minimal["graph"]["nodes"]:
        _validate(n, node_schema)
    for e in og_minimal["graph"]["edges"]:
        _validate(e, edge_schema)


# --- Round-trip integrity ----------------------------------------------------
# Regression: sanitized OpenGraph kinds (NHI -> Nhi, RUNS_AS -> RunsAs) must
# reverse losslessly when an emitted payload is read back into the model.
# Previously crashed `agenthound infer`/`emit` on any file-based pipeline.

def test_roundtrip_preserves_kinds(native_graph_full):
    from agenthound.cli import _result_from_json

    nodes, edges = native_graph_full
    payload = build_payload(nodes, edges).to_dict()
    restored = _result_from_json(payload)
    assert sorted(n.kind.value for n in restored.nodes) == sorted(n.kind.value for n in nodes)
    assert sorted(e.kind.value for e in restored.edges) == sorted(e.kind.value for e in edges)


def test_cli_local_infer_emit_pipeline(tmp_path, node_schema, edge_schema):
    """Full file-based pipeline runs without crashing and emits valid OpenGraph."""
    from click.testing import CliRunner

    from agenthound.cli import main

    home = tmp_path / "home"
    (home / ".config" / "Claude").mkdir(parents=True)
    (home / ".config" / "Claude" / "claude_desktop_config.json").write_text(
        json.dumps({"mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}}})
    )
    inv = tmp_path / "inv.yaml"
    inv.write_text(
        "servers:\n"
        "  - name: fetch\n"
        "    tools:\n"
        "      - name: fetch_url\n"
        "        classification: [url_fetcher]\n"
        "    backing_nhi: {provider: x, identifier: y, nhi_type: api_key}\n"
        "    accessible_resources:\n"
        "      - {provider: x, kind: bucket, identifier: b, tier: production}\n"
    )
    local_json, mcp_json, merged, bh = (
        tmp_path / "local.json",
        tmp_path / "mcp.json",
        tmp_path / "merged.json",
        tmp_path / "bh.json",
    )
    runner = CliRunner()
    r = runner.invoke(
        main, ["local", "--home", str(home), "--hostname", "h", "-o", str(local_json)]
    )
    assert r.exit_code == 0, r.output
    r = runner.invoke(main, ["mcp", "-i", str(inv), "-o", str(mcp_json)])
    assert r.exit_code == 0, r.output
    r = runner.invoke(main, ["infer", str(local_json), str(mcp_json), "-o", str(merged)])
    assert r.exit_code == 0, r.output  # regression: used to crash here
    r = runner.invoke(main, ["emit", str(merged), "-o", str(bh)])
    assert r.exit_code == 0, r.output

    payload = json.loads(bh.read_text())
    assert payload["graph"]["nodes"] and payload["graph"]["edges"]
    for n in payload["graph"]["nodes"]:
        _validate(n, node_schema)
    for e in payload["graph"]["edges"]:
        _validate(e, edge_schema)
