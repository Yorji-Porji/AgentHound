"""Safety regression tests for the Windows bootstrap script."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


def _powershell() -> str | None:
    return shutil.which("powershell") or shutil.which("pwsh")


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_recreate_refuses_non_venv_directory(tmp_path: Path) -> None:
    target = tmp_path / "valuable-data"
    target.mkdir()
    sentinel = target / "keep.txt"
    sentinel.write_text("do not delete")
    script = Path(__file__).parents[1] / "setup.ps1"

    completed = subprocess.run(
        [
            _powershell() or "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-Recreate",
            "-VenvPath",
            str(target),
            "-Minimal",
            "-SkipTests",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode != 0
    assert "pyvenv.cfg missing" in completed.stdout + completed.stderr
    assert sentinel.read_text() == "do not delete"
