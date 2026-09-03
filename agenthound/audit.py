"""Tamper-evident audit log.

Every decision a run makes — what it touched, what it skipped, and why — is
appended as one JSON object per line. Each line is HMAC-signed with a
per-engagement key and chained to the previous line's hash, so edits,
insertion, interior deletion, and reordering break verification. A valid suffix
removal needs an independently retained terminal hash to detect.

Line shape::

    {"ts", "op", "target", "decision", "reason", "prev_hash", "hash"}

where ``hash = HMAC_SHA256(key, prev_hash + canonical_json(body))`` and
``body`` is the line without its own ``hash`` field. The first line chains
from :data:`GENESIS_HASH`.

There is no unsigned mode: constructing an :class:`AuditLog` without a key
raises. A run that cannot sign its audit trail must not run.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from pathlib import Path

__all__ = [
    "GENESIS_HASH",
    "AuditError",
    "AuditLog",
    "canonical_json",
    "verify_audit_log",
]

# prev_hash of the very first line. 64 zeros = sha256 hex width.
GENESIS_HASH = "0" * 64

# Fields that make up the signed body, in nothing-special order (canonical_json
# sorts them anyway). ``hash`` is explicitly NOT part of the body.
_BODY_FIELDS = ("ts", "op", "target", "decision", "reason", "prev_hash")

# A genuine line is exactly the signed body plus its hash. Any other key set
# means a field was added or removed — which the signature itself cannot cover.
_EXPECTED_LINE_KEYS = frozenset((*_BODY_FIELDS, "hash"))


class AuditError(Exception):
    """Raised on a missing key or an unreadable/instantiation failure."""


def canonical_json(body: dict) -> str:
    """Deterministic JSON: sorted keys, no whitespace. Used for signing."""
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def _sign(key: bytes, body: dict) -> str:
    msg = (body["prev_hash"] + canonical_json(body)).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _coerce_key(key: str | bytes) -> bytes:
    if not key:
        raise AuditError(
            "Audit HMAC key is missing or empty; refusing to write an unsigned log. "
            "Set AGENTHOUND_AUDIT_KEY."
        )
    return key if isinstance(key, bytes) else key.encode("utf-8")


def _verify_lines(
    lines: list[str], key: bytes
) -> tuple[bool, int | None, str, str]:
    """Verify JSONL text and return the final trusted hash as well."""
    prev = GENESIS_HASH
    for idx, raw in enumerate(lines):
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            return False, idx, "line is not valid JSON", prev
        if not isinstance(entry, dict):
            return False, idx, "line must be a JSON object", prev
        if "hash" not in entry:
            return False, idx, "line is missing its hash", prev
        if set(entry) != _EXPECTED_LINE_KEYS:
            return False, idx, "line carries fields not covered by the signature", prev
        if not all(isinstance(entry[field], str) for field in _EXPECTED_LINE_KEYS):
            return False, idx, "line fields must all be strings", prev
        stored = entry["hash"]
        body = {k: entry[k] for k in _BODY_FIELDS}
        if entry["prev_hash"] != prev:
            return False, idx, "chain broken: prev_hash does not match the prior line", prev
        if _sign(key, body) != stored:
            return False, idx, "hash mismatch: line was altered or signed with another key", prev
        prev = stored
    return True, None, "audit chain verified", prev


class AuditLog:
    """Append-only, HMAC-chained JSONL writer."""

    def __init__(self, path: str | Path, key: str | bytes) -> None:
        self.key = _coerce_key(key)
        self.path = Path(path)
        self._prev_hash = self._last_hash()

    def _last_hash(self) -> str:
        """Verify and resume an existing chain, or start at genesis."""
        if not self.path.exists():
            return GENESIS_HASH
        try:
            lines = [
                line
                for line in self.path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        except OSError as exc:
            raise AuditError(f"Could not read existing audit log {self.path}: {exc}") from exc
        ok, idx, message, last = _verify_lines(lines, self.key)
        if not ok:
            raise AuditError(
                f"Existing audit log {self.path} failed verification at line {idx}: "
                f"{message}; refusing to resume."
            )
        return last

    def record(self, op: str, target: str, decision: str, reason: str) -> dict:
        """Append one signed entry and return the written line."""
        body = {
            "ts": datetime.now(UTC).isoformat(),
            "op": op,
            "target": target,
            "decision": decision,
            "reason": reason,
            "prev_hash": self._prev_hash,
        }
        line = {**body, "hash": _sign(self.key, body)}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line) + "\n")
        self._prev_hash = line["hash"]
        return line


def verify_audit_log(path: str | Path, key: str | bytes) -> tuple[bool, int | None, str]:
    """Re-walk the chain.

    Returns ``(ok, bad_line_index, message)``. ``bad_line_index`` is the
    0-based index of the first offending line, or ``None`` when the log is
    intact.
    """
    key_bytes = _coerce_key(key)
    lines = [ln for ln in Path(path).read_text(encoding="utf-8").splitlines() if ln.strip()]
    ok, idx, message, _ = _verify_lines(lines, key_bytes)
    return ok, idx, message
