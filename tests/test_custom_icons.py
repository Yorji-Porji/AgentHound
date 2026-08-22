"""Custom BloodHound icon definitions: P2-W7-VAL-05, automated half.

`bloodhound/custom-nodes.json` maps each emitted node kind to a Font Awesome icon.
BloodHound renders a `(?)` icon for any kind it cannot resolve, and it fails silently,
so the drift these tests guard against is invisible in the UI until someone looks:

- a new `NodeKind` added without an icon entry,
- an icon entry left behind after a kind is removed,
- a key written in the *internal* form (`NHI`) rather than the emitted one (`Nhi`).

The visual check that the icons actually look right in a live BloodHound instance stays
manual; see tests/e2e/README.md.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from agenthound.schema.nodes import NodeKind
from agenthound.schema.opengraph import _sanitize_kind

ICON_FILE = Path(__file__).parent.parent / "bloodhound" / "custom-nodes.json"

# BloodHound accepts #RGB or #RRGGBB.
_COLOR_RE = re.compile(r"^#(?:[0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$")


@pytest.fixture(scope="module")
def custom_types() -> dict[str, Any]:
    data = json.loads(ICON_FILE.read_text(encoding="utf-8"))
    return data["custom_types"]


def _emitted_kinds() -> set[str]:
    """The primary kind BloodHound sees, which is what an icon keys on."""
    return {_sanitize_kind(k.value) for k in NodeKind}


def test_every_node_kind_has_an_icon(custom_types: dict[str, Any]) -> None:
    missing = _emitted_kinds() - set(custom_types)
    assert not missing, f"node kinds with no icon (BloodHound will render '?'): {sorted(missing)}"


def test_no_stale_icon_entries(custom_types: dict[str, Any]) -> None:
    stale = set(custom_types) - _emitted_kinds()
    assert not stale, f"icon entries for kinds that no longer exist: {sorted(stale)}"


def test_keys_are_emitted_form_not_internal_form(custom_types: dict[str, Any]) -> None:
    """Regression: internal SCREAMING_SNAKE/upper names match nothing after emission.

    `NHI` is sanitized to `Nhi` on the way out, so an icon keyed on `NHI` never binds.
    """
    assert "Nhi" in custom_types
    assert "NHI" not in custom_types
    internal_only = {k.value for k in NodeKind} - _emitted_kinds()
    assert not (internal_only & set(custom_types)), (
        "icon keyed on an internal kind name that is never emitted"
    )


@pytest.mark.parametrize("kind", sorted(_emitted_kinds()))
def test_icon_entry_is_well_formed(custom_types: dict[str, Any], kind: str) -> None:
    icon = custom_types[kind]["icon"]
    assert icon["type"] == "font-awesome", f"{kind}: only the font-awesome set is supported"
    name = icon["name"]
    assert name and isinstance(name, str), f"{kind}: icon name must be a non-empty string"
    assert not name.startswith("fa-"), f"{kind}: drop the 'fa-' prefix, use '{name[3:]}'"
    color = icon["color"]
    assert _COLOR_RE.match(color), f"{kind}: color must be #RGB or #RRGGBB, got {color!r}"


def test_payload_shape_matches_the_api_contract(custom_types: dict[str, Any]) -> None:
    """The file is POSTed verbatim to /api/v2/custom-nodes, so the envelope must be exact."""
    data = json.loads(ICON_FILE.read_text(encoding="utf-8"))
    assert "custom_types" in data
    for kind, body in custom_types.items():
        assert set(body) == {"icon"}, f"{kind}: only an 'icon' key is allowed"
        assert set(body["icon"]) <= {"type", "name", "color"}, f"{kind}: unexpected icon field"
