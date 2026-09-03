"""Engagement scope: the authorization boundary every run is held to.

An ``agenthound.scope.yaml`` declares *what* a run is permitted to touch and
*when*. :class:`EngagementScope` is the validated model of that file;
:class:`ScopeGuard` answers the three enforcement questions a collector asks
before it touches anything:

- ``check_provider(name)`` — is this credential/MCP provider in scope?
- ``check_path(path)`` — is this filesystem path allowed (not denied)?
- ``check_time(now)`` — are we inside an authorized time window right now?

Two rules are absolute and live in code, not in the per-call checks:

- **Expired authorization is a hard stop.** Constructing a ``ScopeGuard`` for a
  scope whose ``authorized_until`` is in the past raises :class:`ScopeExpired`
  — the tool refuses to run at all.
- **Deny wins.** A provider listed in both ``providers_allowed`` and
  ``providers_denied`` is denied.
"""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime, time
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml
from pydantic import BaseModel, ConfigDict, field_validator

__all__ = [
    "EngagementScope",
    "ScopeError",
    "ScopeExpired",
    "ScopeGuard",
    "TimeWindow",
]


class ScopeError(Exception):
    """Base class for scope problems that should abort a run."""


class ScopeExpired(ScopeError):  # noqa: N818 - reads as a state; base ScopeError carries the suffix
    """Raised when ``authorized_until`` is in the past — refuse to run at all."""


# --- Glob matching ------------------------------------------------------------
#
# Path rules need *path-aware* globbing: ``*`` must not cross a directory
# separator, while ``**`` may. ``fnmatch`` treats ``*`` as matching everything
# (separators included) and ``pathlib``'s ``full_match`` only exists on 3.13+,
# so we compile a small regex ourselves and stay correct on 3.11+.

_DOW = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a path glob to a regex, distinguishing ``*`` from ``**``."""
    out: list[str] = ["^"]
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                out.append(".*")  # ** crosses separators
                i += 2
            else:
                out.append("[^/]*")  # * stays within a segment
                i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    out.append("$")
    return re.compile("".join(out))


def _normalize_path(value: str | Path, *, resolve: bool) -> str:
    """Normalize one path for matching without resolving glob patterns."""
    raw = os.fspath(value)
    if resolve:
        raw = os.path.realpath(raw)
    return os.path.normcase(raw).replace("\\", "/")


# --- Models -------------------------------------------------------------------


class TimeWindow(BaseModel):
    """A recurring authorized window: days-of-week + a start/end clock in a tz."""

    model_config = ConfigDict(extra="forbid")

    days: list[str]
    start: str  # "HH:MM"
    end: str  # "HH:MM"
    tz: str = "UTC"

    @field_validator("days")
    @classmethod
    def _validate_days(cls, v: list[str]) -> list[str]:
        normalized = [d.strip().lower()[:3] for d in v]
        bad = [d for d in normalized if d not in _DOW]
        if bad:
            raise ValueError(f"unknown day(s): {bad}; expected mon..sun")
        return normalized

    @field_validator("start", "end")
    @classmethod
    def _validate_clock(cls, v: str) -> str:
        _parse_clock(v)  # raises ValueError on bad format
        return v

    @field_validator("tz")
    @classmethod
    def _validate_tz(cls, v: str) -> str:
        try:
            ZoneInfo(v)
        except Exception as exc:  # ZoneInfoNotFoundError is a KeyError, not a ValueError
            raise ValueError(f"unknown timezone: {v!r}") from exc
        return v

    def contains(self, now: datetime) -> bool:
        """Is ``now`` (any tz-aware instant) inside this window?"""
        local = now.astimezone(ZoneInfo(self.tz))
        allowed_days = {_DOW[d] for d in self.days}
        start, end = _parse_clock(self.start), _parse_clock(self.end)
        t = local.timetz().replace(tzinfo=None)
        if start <= end:
            return local.weekday() in allowed_days and start <= t <= end
        # Window wraps past midnight (e.g. 22:00–02:00).
        if t >= start:
            return local.weekday() in allowed_days
        if t <= end:
            return (local.weekday() - 1) % 7 in allowed_days
        return False


def _parse_clock(value: str) -> time:
    match = re.fullmatch(r"(\d{1,2}):(\d{2})", value.strip())
    if not match:
        raise ValueError(f"time must be 'HH:MM', got {value!r}")
    hh, mm = int(match.group(1)), int(match.group(2))
    if hh > 23 or mm > 59:
        raise ValueError(f"time out of range: {value!r}")
    return time(hh, mm)


class EngagementScope(BaseModel):
    """The validated contents of an ``agenthound.scope.yaml``."""

    model_config = ConfigDict(extra="forbid")

    engagement: str
    authorized_until: datetime
    providers_allowed: list[str] = []
    providers_denied: list[str] = []
    paths_denied: list[str] = []
    time_windows: list[TimeWindow] = []
    audit_log: str | None = None

    @field_validator("authorized_until")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        # RFC3339 carries an offset; if a naive value slips through, treat as UTC.
        return v if v.tzinfo is not None else v.replace(tzinfo=UTC)

    @classmethod
    def from_yaml(cls, path: str | Path) -> EngagementScope:
        # utf-8-sig tolerates a leading BOM, which Windows editors often add.
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8-sig"))
        return cls.model_validate(data)


# --- Guard --------------------------------------------------------------------


class ScopeGuard:
    """Enforces an :class:`EngagementScope`. Construction fails if expired."""

    def __init__(self, scope: EngagementScope, *, now: datetime | None = None) -> None:
        self.scope = scope
        self._denied_globs = [
            _glob_to_regex(_normalize_path(p, resolve=False)) for p in scope.paths_denied
        ]
        reference = now or datetime.now(UTC)
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=UTC)
        if scope.authorized_until < reference:
            raise ScopeExpired(
                f"Engagement '{scope.engagement}' authorization expired at "
                f"{scope.authorized_until.isoformat()}; refusing to run."
            )

    def check_provider(self, name: str) -> bool:
        """Allow unless denied; if an allowlist exists it is exclusive."""
        if name in self.scope.providers_denied:
            return False  # deny wins
        if self.scope.providers_allowed:
            return name in self.scope.providers_allowed
        return True

    def check_path(self, path: str | Path) -> bool:
        """Deny if the path matches any ``paths_denied`` glob."""
        lexical = _normalize_path(path, resolve=False)
        resolved = _normalize_path(path, resolve=True)
        return not any(
            rx.match(candidate)
            for rx in self._denied_globs
            for candidate in {lexical, resolved}
        )

    def check_time(self, now: datetime | None = None) -> bool:
        """Allow before expiry and, when declared, inside a recurring window."""
        moment = now or datetime.now(UTC)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
        if self.scope.authorized_until < moment:
            return False
        if not self.scope.time_windows:
            return True
        return any(w.contains(moment) for w in self.scope.time_windows)
