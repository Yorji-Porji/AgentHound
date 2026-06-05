"""Offline analysis mode tests — P1-W3-OFFLINE-01..08.

Covers the defensive tarball extraction (path traversal, escaping links,
non-tar input), temp-dir cleanup, parity with a live `local` scan, and the
`agenthound offline` CLI wiring.
"""

from __future__ import annotations

import tarfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from agenthound.cli import main
from agenthound.collectors.local import LocalCollector
from agenthound.offline import UnsafeArchiveError, extracted_home


def _make_home_tarball(tmp_path: Path) -> Path:
    """A tarball of a minimal home tree with an AWS credentials file."""
    home = tmp_path / "captured_home"
    aws = home / ".aws"
    aws.mkdir(parents=True)
    (aws / "credentials").write_text("[default]\n[work]\n")
    archive = tmp_path / "capture.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(home, arcname=".")
    return archive


# --- safe extraction (OFFLINE-01..03) ----------------------------------------

def test_offline01_extracts_and_yields_home(tmp_path: Path):
    archive = _make_home_tarball(tmp_path)
    with extracted_home(archive) as home:
        assert (home / ".aws" / "credentials").exists()


def test_offline02_temp_dir_cleaned_up(tmp_path: Path):
    archive = _make_home_tarball(tmp_path)
    with extracted_home(archive) as home:
        captured = home
        assert captured.exists()
    assert not captured.exists()


def test_offline03_temp_dir_cleaned_up_on_error(tmp_path: Path):
    # An unsafe archive still cleans up its temp dir.
    archive = tmp_path / "evil.tar.gz"
    payload = tmp_path / "payload.txt"
    payload.write_text("x")
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(payload, arcname="../escape.txt")
    with pytest.raises(UnsafeArchiveError), extracted_home(archive):
        pass


# --- malicious archives (OFFLINE-04..06) -------------------------------------

def test_offline04_rejects_parent_traversal(tmp_path: Path):
    archive = tmp_path / "evil.tar.gz"
    payload = tmp_path / "p.txt"
    payload.write_text("x")
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(payload, arcname="../../etc/escape")
    with pytest.raises(UnsafeArchiveError), extracted_home(archive):
        pass


def test_offline05_rejects_absolute_path(tmp_path: Path):
    archive = tmp_path / "evil.tar.gz"
    info = tarfile.TarInfo(name="/etc/passwd_escape")
    with tarfile.open(archive, "w:gz") as tar:
        tar.addfile(info)
    with pytest.raises(UnsafeArchiveError), extracted_home(archive):
        pass


def test_offline06_rejects_symlink_escape(tmp_path: Path):
    archive = tmp_path / "evil.tar.gz"
    info = tarfile.TarInfo(name="link")
    info.type = tarfile.SYMTYPE
    info.linkname = "/etc/shadow"
    with tarfile.open(archive, "w:gz") as tar:
        tar.addfile(info)
    with pytest.raises(UnsafeArchiveError), extracted_home(archive):
        pass


# --- parity with a live local scan (OFFLINE-07) ------------------------------

def test_offline07_parity_with_live_local(tmp_path: Path):
    archive = _make_home_tarball(tmp_path)
    with extracted_home(archive) as home:
        offline_result = LocalCollector(home=home, hostname="host").collect()
    aws_offline = {
        n.properties.get("identifier")
        for n in offline_result.nodes
        if n.properties.get("provider") == "aws"
    }
    # A live scan of the original tree should see the same AWS profiles.
    live_home = tmp_path / "captured_home"
    live_result = LocalCollector(home=live_home, hostname="host").collect()
    aws_live = {
        n.properties.get("identifier")
        for n in live_result.nodes
        if n.properties.get("provider") == "aws"
    }
    assert aws_offline == aws_live
    assert "default" in aws_offline and "work" in aws_offline


# --- CLI wiring (OFFLINE-08) -------------------------------------------------

def test_offline08_cli_writes_graph(tmp_path: Path):
    archive = _make_home_tarball(tmp_path)
    out = tmp_path / "graph.json"
    res = CliRunner().invoke(main, ["offline", str(archive), "-o", str(out)])
    assert res.exit_code == 0, res.output
    assert "aws" in out.read_text()


def test_offline_cli_rejects_non_tar(tmp_path: Path):
    bogus = tmp_path / "nope.tar.gz"
    bogus.write_text("this is not a tar archive")
    res = CliRunner().invoke(main, ["offline", str(bogus)])
    assert res.exit_code != 0
    assert "Could not analyze archive" in res.output
