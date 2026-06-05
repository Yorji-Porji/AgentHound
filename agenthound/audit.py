"""Tamper-evident audit log.

Every decision a run makes — what it touched, what it skipped, and why — is
appended as one JSON object per line. Each line is HMAC-signed with a
per-engagement key and chained to the previous line's hash, so any edit,
deletion, or reordering breaks verification.

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


class AuditLog:
    """Append-only, HMAC-chained JSONL writer."""

    def __init__(self, path: str | Path, key: str | bytes) -> None:
        self.key = _coerce_key(key)
        self.path = Path(path)
        self._prev_hash = self._last_hash()

    def _last_hash(self) -> str:
        """Resume the chain from an existing log, or start at genesis."""
        if not self.path.exists():
            return GENESIS_HASH
        last = GENESIS_HASH
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                last = json.loads(line)["hash"]
            except (json.JSONDecodeError, KeyError) as exc:
                raise AuditError(
                    f"Existing audit log {self.path} is corrupt; cannot resume the "
                    f"chain. Verify it with `agenthound verify-audit` and archive it "
                    f"before starting a new run."
                ) from exc
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
    prev = GENESIS_HASH
    lines = [ln for ln in Path(path).read_text(encoding="utf-8").splitlines() if ln.strip()]
    for idx, raw in enumerate(lines):
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            return False, idx, "line is not valid JSON"
        if "hash" not in entry:
            return False, idx, "line is missing its hash"
        if set(entry) != _EXPECTED_LINE_KEYS:
            return False, idx, "line carries fields not covered by the signature"
        stored = entry["hash"]
        body = {k: entry[k] for k in _BODY_FIELDS if k in entry}
        if entry.get("prev_hash") != prev:
            return False, idx, "chain broken: prev_hash does not match the prior line"
        if _sign(key_bytes, body) != stored:
            return False, idx, "hash mismatch: line was altered or signed with another key"
        prev = stored
    return True, None, "audit chain verified"
