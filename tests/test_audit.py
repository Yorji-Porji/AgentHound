"""Week 2 audit-log tests — P1-W2-AUDIT-01..10.

Exercises the line shape, append-only behavior, HMAC signing, the genesis
anchor, and tamper detection (edit / delete / reorder), plus the no-unsigned-mode
guarantee.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agenthound.audit import (
    GENESIS_HASH,
    AuditError,
    AuditLog,
    _sign,
    canonical_json,
    verify_audit_log,
)

_BODY_KEYS = ("ts", "op", "target", "decision", "reason", "prev_hash")


def _read(path: Path) -> list[dict]:
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


# --- format, signing, chain (AUDIT-01..05) -----------------------------------

def test_audit01_line_shape(tmp_path: Path):
    path = tmp_path / "a.jsonl"
    line = AuditLog(path, "key").record("collect", "aws", "SKIPPED", "out of scope")
    assert set(line) == {*_BODY_KEYS, "hash"}
    assert _read(path)[0] == line


def test_audit02_append_only(tmp_path: Path):
    path = tmp_path / "a.jsonl"
    log = AuditLog(path, "key")
    log.record("op", "t", "ALLOW", "first")
    prefix = path.read_bytes()
    log.record("op", "t", "ALLOW", "second")
    assert path.read_bytes().startswith(prefix)


def test_audit03_hash_recomputes(tmp_path: Path):
    line = AuditLog(tmp_path / "a.jsonl", "key").record("op", "t", "ALLOW", "r")
    body = {k: line[k] for k in _BODY_KEYS}
    assert line["hash"] == _sign(b"key", body)


def test_audit04_first_prev_hash_is_genesis(tmp_path: Path):
    line = AuditLog(tmp_path / "a.jsonl", "key").record("op", "t", "ALLOW", "r")
    assert line["prev_hash"] == GENESIS_HASH


def test_audit05_verify_untouched_passes(tmp_path: Path):
    path = tmp_path / "a.jsonl"
    log = AuditLog(path, "key")
    log.record("op", "t", "ALLOW", "one")
    log.record("op", "t", "SKIPPED", "two")
    ok, idx, _ = verify_audit_log(path, "key")
    assert ok and idx is None


# --- tamper detection (AUDIT-06..08) -----------------------------------------

def _three_line_log(tmp_path: Path) -> Path:
    path = tmp_path / "a.jsonl"
    log = AuditLog(path, "key")
    for i in range(3):
        log.record("op", "t", "ALLOW", f"line{i}")
    return path


def test_audit06_edit_middle_line_fails(tmp_path: Path):
    path = _three_line_log(tmp_path)
    lines = path.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["reason"] = "TAMPERED"
    lines[1] = json.dumps(entry)
    path.write_text("\n".join(lines) + "\n")
    ok, idx, msg = verify_audit_log(path, "key")
    assert not ok and idx == 1 and "mismatch" in msg


def test_audit07_deleted_line_breaks_chain(tmp_path: Path):
    path = _three_line_log(tmp_path)
    lines = path.read_text().splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n")
    ok, idx, _ = verify_audit_log(path, "key")
    assert not ok and idx == 1


def test_audit08_reorder_breaks_chain(tmp_path: Path):
    path = _three_line_log(tmp_path)
    lines = path.read_text().splitlines()
    lines[0], lines[1] = lines[1], lines[0]
    path.write_text("\n".join(lines) + "\n")
    ok, idx, _ = verify_audit_log(path, "key")
    assert not ok and idx == 0


# --- no unsigned mode (AUDIT-09) ---------------------------------------------

def test_audit09_empty_key_refused_on_write(tmp_path: Path):
    with pytest.raises(AuditError):
        AuditLog(tmp_path / "a.jsonl", "")


def test_verify_empty_key_refused(tmp_path: Path):
    path = tmp_path / "a.jsonl"
    AuditLog(path, "key").record("op", "t", "ALLOW", "r")
    with pytest.raises(AuditError):
        verify_audit_log(path, "")


# --- resume, encodings, edge cases (coverage) --------------------------------

def test_resume_existing_chain(tmp_path: Path):
    path = tmp_path / "a.jsonl"
    AuditLog(path, "key").record("op", "t", "ALLOW", "first")
    line = AuditLog(path, "key").record("op", "t", "ALLOW", "second")
    assert line["prev_hash"] != GENESIS_HASH
    ok, _, _ = verify_audit_log(path, "key")
    assert ok


def test_last_hash_skips_trailing_blank_line(tmp_path: Path):
    path = tmp_path / "a.jsonl"
    AuditLog(path, "key").record("op", "t", "ALLOW", "first")
    with path.open("a", encoding="utf-8") as fh:
        fh.write("\n")
    assert AuditLog(path, "key")._prev_hash != GENESIS_HASH


def test_bytes_key_accepted(tmp_path: Path):
    assert AuditLog(tmp_path / "a.jsonl", b"raw").key == b"raw"


def test_verify_non_json_line(tmp_path: Path):
    path = tmp_path / "a.jsonl"
    path.write_text("this is not json\n")
    ok, idx, msg = verify_audit_log(path, "key")
    assert not ok and idx == 0 and "JSON" in msg


def test_verify_missing_hash_field(tmp_path: Path):
    path = tmp_path / "a.jsonl"
    path.write_text(json.dumps({"prev_hash": GENESIS_HASH, "op": "x"}) + "\n")
    ok, idx, msg = verify_audit_log(path, "key")
    assert not ok and idx == 0 and "hash" in msg


def test_canonical_json_is_sorted_and_compact():
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_resume_corrupt_log_raises(tmp_path: Path):
    # A run resuming from a tampered/corrupt log must refuse, not crash.
    path = tmp_path / "a.jsonl"
    AuditLog(path, "key").record("op", "t", "ALLOW", "first")
    with path.open("a", encoding="utf-8") as fh:
        fh.write("}{ not valid json\n")
    with pytest.raises(AuditError):
        AuditLog(path, "key")


def test_resume_tampered_hmac_refuses(tmp_path: Path):
    path = _three_line_log(tmp_path)
    lines = path.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["reason"] = "tampered"
    lines[1] = json.dumps(entry)
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(AuditError, match="failed verification at line 1"):
        AuditLog(path, "key")


def test_resume_with_wrong_key_refuses(tmp_path: Path):
    path = tmp_path / "a.jsonl"
    AuditLog(path, "right-key").record("op", "t", "ALLOW", "first")
    with pytest.raises(AuditError, match="failed verification at line 0"):
        AuditLog(path, "wrong-key")


def test_verify_rejects_scalar_json_line(tmp_path: Path):
    path = tmp_path / "a.jsonl"
    path.write_text('"not-an-object"\n')
    ok, idx, msg = verify_audit_log(path, "key")
    assert not ok and idx == 0 and "object" in msg


def test_valid_suffix_truncation_is_documented_limit(tmp_path: Path):
    path = _three_line_log(tmp_path)
    path.write_text("\n".join(path.read_text().splitlines()[:2]) + "\n")
    ok, idx, msg = verify_audit_log(path, "key")
    assert ok and idx is None and msg == "audit chain verified"


def test_verify_rejects_added_field(tmp_path: Path):
    # F11: a field added to a line is not covered by the signature; verify must
    # still reject it (a genuine line carries exactly the body fields + hash).
    path = tmp_path / "a.jsonl"
    AuditLog(path, "key").record("op", "t", "ALLOW", "r")
    entry = json.loads(path.read_text().splitlines()[0])
    entry["sneaky"] = "x"
    path.write_text(json.dumps(entry) + "\n")
    ok, idx, msg = verify_audit_log(path, "key")
    assert not ok and idx == 0 and "not covered" in msg
