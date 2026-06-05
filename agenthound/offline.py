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
extraction with :class:`UnsafeArchiveError`.
"""

from __future__ import annotations

import tarfile
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from shutil import rmtree


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
    """Refuse any member that would escape ``dest``.

    Covers absolute paths (POSIX ``/`` and Windows drive/UNC), parent-directory
    traversal, and hard/symlinks whose target points outside the root.
    """
    name = member.name
    if name.startswith(("/", "\\")) or (len(name) > 1 and name[1] == ":"):
        raise UnsafeArchiveError(f"absolute path in archive: {name!r}")

    target = dest / name
    if not _within(dest, target):
        raise UnsafeArchiveError(f"path escapes extraction root: {name!r}")

    if member.issym() or member.islnk():
        link_target = target.parent / member.linkname
        if not _within(dest, link_target):
            raise UnsafeArchiveError(
                f"link escapes extraction root: {name!r} -> {member.linkname!r}"
            )


def _safe_extractall(tar: tarfile.TarFile, dest: Path) -> None:
    """Validate every member, then extract into ``dest``."""
    for member in tar.getmembers():
        _assert_safe(member, dest)
    # ``filter='data'`` (Python 3.12+, backported to 3.11.4+) is defense in
    # depth on top of the pre-validation above. Fall back for runtimes that
    # predate the keyword.
    try:
        tar.extractall(dest, filter="data")  # type: ignore[call-arg]
    except TypeError:
        tar.extractall(dest)  # noqa: S202 — members pre-validated by _assert_safe


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
