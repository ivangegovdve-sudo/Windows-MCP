from __future__ import annotations

import shutil
import json
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from windows_mcp import __main__
from windows_mcp.filesystem.index import FilesystemIndex


@pytest.fixture
def n_workspace():
    n_drive = Path("N:/")
    if not n_drive.exists():
        pytest.skip("N: is not available on this machine")
    root = n_drive / f"windows-mcp-index-acceptance-{time.time_ns()}"
    root.mkdir()
    try:
        yield root, root / "index" / "index.sqlite3"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_real_n_drive_storage_uses_wal_and_excludes_its_own_directory(n_workspace):
    root, db = n_workspace
    (root / "public.md").write_text("public", encoding="utf-8")
    (root / "index").mkdir()
    index = FilesystemIndex(str(db), [str(root)])

    try:
        index.build()
        status = index.status()
        listed = index.list_directory(str(root))
        self_search = index.search("index.sqlite3")
    finally:
        index.close()

    assert status["journal_mode"] == "wal"
    assert status["fts5"] is True
    assert "index" not in {item["name"] for item in listed["items"]}
    assert self_search["total_matches"] == 0


def test_real_directory_change_notification_is_stale_before_full_refresh(n_workspace):
    root, db = n_workspace
    file_path = root / "watched.txt"
    file_path.write_text("before", encoding="utf-8")
    old_mtime_ns = file_path.stat().st_mtime_ns
    index = FilesystemIndex(str(db), [str(root)])

    try:
        index.build()
        index.start()
        assert index.status()["freshness"] == "possibly_stale"
        time.sleep(0.25)
        file_path.write_text("after", encoding="utf-8")

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if index.status()["pending_changes"]:
                break
            time.sleep(0.05)
        before_refresh = index.search("watched.txt")
        assert before_refresh["freshness"] == "possibly_stale"
        assert before_refresh["items"][0]["mtime_ns"] == old_mtime_ns

        index.refresh(full=True)
        after_refresh = index.search("watched.txt")
    finally:
        index.close()

    assert after_refresh["freshness"] == "fresh"
    assert after_refresh["items"][0]["mtime_ns"] == file_path.stat().st_mtime_ns


def test_operator_cli_builds_real_n_drive_index(n_workspace):
    root, db = n_workspace
    (root / "one.md").write_text("one", encoding="utf-8")
    (root / "two.txt").write_text("two", encoding="utf-8")

    result = CliRunner().invoke(
        __main__.main,
        ["index", "build", "--db", str(db), "--root", str(root)],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["files"] == 2
