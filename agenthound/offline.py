"""Offline analysis mode.

Run the local-collector logic against a *captured tarball* instead of a live
machine. The operating model is "capture cheap on the target host, analyze in a
clean environment" — an operator tars up the config/credential paths on the
engagement host, carries the archive off-box, and analyzes it here.

The archive is expected to contain the paths the local collector scans
(``.aws/``, ``.ssh/``, ``.config/Claude/``, ``.config/Cursor/``, ``.npmrc`` …)
laid out as they appear under a home directory. It is extracted into a
temporary directory and ``LocalCollector(home=...)`` is pointed at it, so an
offline run produces the same graph a live ``local`` run would.

Security posture: the tarball is **untrusted input**. A malicious archive can
try to write outside the extraction root via absolute paths, ``..`` traversal,
or links whose target escapes the root (the classic "tarbomb"). Every member is
validated *before* anything is written; the first unsafe member aborts the
extraction with :class:`UnsafeArchiveError`. Member count, individual file size,
and total expanded data are bounded to resist archive resource exhaustion.
"""

from __future__ import annotations

import tarfile
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from shutil import rmtree

MAX_ARCHIVE_MEMBERS = 10_000
MAX_ARCHIVE_TOTAL_SIZE = 1024**3
MAX_ARCHIVE_MEMBER_SIZE = 256 * 1024**2


class UnsafeArchiveError(Exception):
    """A tarball member would extract outside the extraction root."""


def _within(root: Path, target: Path) -> bool:
    """True if ``target`` resolves to a path inside ``root``."""
    try:
        target.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _assert_safe(member: tarfile.TarInfo, dest: Path) -> None:
    """Refuse any member that would extract outside ``dest``.

    ``_within`` resolves each member path (and each hard/symlink target) and
    rejects anything landing outside the extraction root. That single check
    covers absolute paths, ``..`` traversal, and escaping links — and does it
    platform-correctly, since pathlib knows ``C:`` is a drive on Windows but a
    legal filename byte on POSIX (a string heuristic cannot tell them apart).
    """
    name = member.name
    target = dest / name
    if not _within(dest, target):
        raise UnsafeArchiveError(f"path escapes extraction root: {name!r}")

    if member.issym() or member.islnk():
        link_target = (
            target.parent / member.linkname
            if member.issym()
            else dest / member.linkname
        )
        if not _within(dest, link_target):
            raise UnsafeArchiveError(
                f"link escapes extraction root: {name!r} -> {member.linkname!r}"
            )


def _safe_extractall(tar: tarfile.TarFile, dest: Path) -> None:
    """Validate bounded member metadata, then extract only that member list."""
    members: list[tarfile.TarInfo] = []
    total_size = 0
    for member in tar:
        if len(members) >= MAX_ARCHIVE_MEMBERS:
            raise UnsafeArchiveError(
                f"archive exceeds the {MAX_ARCHIVE_MEMBERS:,}-member limit"
            )
        if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
            raise UnsafeArchiveError(f"unsupported archive member type: {member.name!r}")
        if member.size < 0:
            raise UnsafeArchiveError(f"archive member has a negative size: {member.name!r}")
        if member.size > MAX_ARCHIVE_MEMBER_SIZE:
            raise UnsafeArchiveError(
                f"archive member exceeds the {MAX_ARCHIVE_MEMBER_SIZE:,}-byte limit: "
                f"{member.name!r}"
            )
        total_size += member.size
        if total_size > MAX_ARCHIVE_TOTAL_SIZE:
            raise UnsafeArchiveError(
                f"archive exceeds the {MAX_ARCHIVE_TOTAL_SIZE:,}-byte expanded-data limit"
            )
        _assert_safe(member, dest)
        members.append(member)
    # ``filter='data'`` (Python 3.12+, backported to 3.11.4+) is defense in
    # depth on top of the pre-validation above. Fall back for runtimes that
    # predate the keyword.
    try:
        tar.extractall(dest, members=members, filter="data")  # type: ignore[call-arg]
    except TypeError:  # pragma: no cover — Python < 3.11.4 lacks the filter kwarg
        tar.extractall(dest, members=members)  # members already validated


@contextmanager
def extracted_home(archive: Path) -> Iterator[Path]:
    """Extract ``archive`` into a temporary home dir, yielded for the duration.

    The temporary directory is removed on exit, success or failure. Compression
    is auto-detected (``.tar``, ``.tar.gz``/``.tgz``, ``.tar.bz2``, ``.tar.xz``).

    Raises
    ------
    UnsafeArchiveError
        If any member would write outside the extraction root.
    tarfile.TarError
        If the archive is not a readable tar.
    """
    tmp = Path(tempfile.mkdtemp(prefix="agenthound-offline-"))
    try:
        with tarfile.open(archive, "r:*") as tar:
            _safe_extractall(tar, tmp)
        yield tmp
    finally:
        rmtree(tmp, ignore_errors=True)
