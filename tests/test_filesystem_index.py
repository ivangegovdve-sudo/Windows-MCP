from __future__ import annotations

import os
import time

import pytest

from windows_mcp.filesystem.index import FilesystemIndex


def make_index(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    return FilesystemIndex(":memory:", [str(root)]), root


def test_build_uses_fts_and_reports_complete_denominator(tmp_path):
    index, root = make_index(tmp_path)
    docs = root / "docs"
    docs.mkdir()
    (docs / "plan.md").write_text("plan", encoding="utf-8")
    (docs / "notes.txt").write_text("notes", encoding="utf-8")
    (root / "README.md").write_text("readme", encoding="utf-8")

    stats = index.build()
    result = index.search("*.md")

    assert stats.files == 3
    assert [item["name"] for item in result["items"]] == ["plan.md", "README.md"]
    assert result["total_matches"] == 2
    assert result["total_size"] == len("plan") + len("readme")
    assert result["truncated"] is False
    assert result["freshness"] == "fresh"
    assert result["searched_roots"] == [os.path.normpath(str(root))]
    assert result["coverage"][0]["state"] == "fresh"
    assert result["exclusions"]
    assert all(item["last_indexed_at"] for item in result["items"])
    assert result["query_ms"] >= 0


def test_list_and_live_metadata_are_read_only_and_bounded(tmp_path):
    index, root = make_index(tmp_path)
    folder = root / "folder"
    folder.mkdir()
    file_path = folder / "item.txt"
    file_path.write_text("hello", encoding="utf-8")
    index.build()

    listed = index.list_directory(str(folder))
    metadata = index.get_metadata(str(file_path))

    assert [item["name"] for item in listed["items"]] == ["item.txt"]
    assert metadata["requested_path"] == os.path.normpath(str(file_path))
    assert metadata["entry"]["name"] == "item.txt"
    assert metadata["live"]["exists"] is True
    assert metadata["live"]["mtime_ns"] == file_path.stat().st_mtime_ns
    assert metadata["fingerprint"] is None
    assert metadata["freshness"] == "fresh"


def test_service_start_fails_toward_stale_and_refresh_clears_known_change(tmp_path):
    index, root = make_index(tmp_path)
    file_path = root / "mutable.txt"
    file_path.write_text("before", encoding="utf-8")
    index.build()

    index.start(watchers=False)
    assert index.status()["freshness"] == "possibly_stale"

    time.sleep(0.01)
    file_path.write_text("after", encoding="utf-8")
    index.record_change(str(file_path), action="modified")
    before_refresh = index.search("mutable.txt")
    assert before_refresh["freshness"] == "possibly_stale"

    refresh = index.refresh(full=True)
    after_refresh = index.search("mutable.txt")

    assert refresh.changes >= 1
    assert after_refresh["freshness"] == "fresh"
    assert after_refresh["items"][0]["mtime_ns"] == file_path.stat().st_mtime_ns


def test_excluded_boundaries_are_indexed_without_descendants(tmp_path):
    index, root = make_index(tmp_path)
    ssh = root / ".ssh"
    ssh.mkdir()
    secret = ssh / "id_rsa"
    secret.write_text("private", encoding="utf-8")
    vault = root / "vault"
    vault.mkdir()
    vault_file = vault / "plan.md"
    vault_file.write_text("private", encoding="utf-8")
    env_file = root / ".env.local"
    env_file.write_text("PRIVATE=1", encoding="utf-8")
    (root / "public.md").write_text("public", encoding="utf-8")

    index.build()
    snapshot = index.list_directory(str(root))
    secret_info = index.get_metadata(str(secret))
    secret_search = index.search("id_rsa")
    vault_search = index.search("plan.md")

    boundary_names = {item["name"] for item in snapshot["items"] if item["kind"] == "boundary"}
    assert {".ssh", "vault", ".env.local"}.issubset(boundary_names)
    assert secret_info["entry"]["name"] == ".ssh"
    assert secret_info["entry"]["kind"] == "boundary"
    assert secret_info["boundary"]["path"] == os.path.normpath(str(ssh))
    assert secret_search["total_matches"] == 0
    assert vault_search["total_matches"] == 0


def test_reconciliation_does_not_index_excluded_descendants(tmp_path):
    index, root = make_index(tmp_path)
    ssh = root / ".ssh"
    ssh.mkdir()
    secret = ssh / "new.txt"
    secret.write_text("private", encoding="utf-8")

    index.build()
    secret.write_text("changed", encoding="utf-8")
    index.record_change(str(secret), action="modified")
    index.refresh()

    assert index.search("new.txt")["total_matches"] == 0
    assert index.get_metadata(str(secret))["boundary"]["path"] == os.path.normpath(str(ssh))


def test_live_unindexed_path_fails_closed_even_without_notification(tmp_path):
    index, root = make_index(tmp_path)
    index.build()
    new_file = root / "created-without-event.txt"
    new_file.write_text("new", encoding="utf-8")

    metadata = index.get_metadata(str(new_file))

    assert metadata["entry"] is None
    assert metadata["live"]["exists"] is True
    assert metadata["freshness"] == "possibly_stale"


def test_excluded_root_is_boundary_only(tmp_path):
    root = tmp_path / ".ssh"
    root.mkdir()
    (root / "id_rsa").write_text("private", encoding="utf-8")
    index = FilesystemIndex(":memory:", [str(root)])

    index.build()

    status = index.status()
    assert status["coverage"][0]["row_count"] == 1
    assert index.get_metadata(str(root))["entry"]["kind"] == "boundary"
    assert index.search("id_rsa")["total_matches"] == 0


def test_index_db_must_be_on_n_drive_except_explicit_memory_database(tmp_path):
    with pytest.raises(ValueError, match="N:"):
        FilesystemIndex(str(tmp_path / "index.sqlite3"), [str(tmp_path)])


def test_reparse_points_become_boundaries_and_are_not_traversed(tmp_path):
    index, root = make_index(tmp_path)
    target = root / "target"
    target.mkdir()
    (target / "inside.md").write_text("inside", encoding="utf-8")
    link = root / "link"
    try:
        os.symlink(target, link, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"creating a Windows reparse point is unavailable: {exc}")

    index.build()
    listed = index.list_directory(str(root))
    link_entry = next(item for item in listed["items"] if item["name"] == "link")

    assert link_entry["kind"] == "boundary"
    assert link_entry["reparse_target"]
    assert index.search("inside.md")["total_matches"] == 1
    assert index.search("link\\inside.md")["total_matches"] == 0


def test_distinct_directories_are_not_collapsed_by_identity_guard(tmp_path):
    index, root = make_index(tmp_path)
    first = root / "first"
    second = root / "second"
    first.mkdir()
    second.mkdir()
    (first / "one.md").write_text("one", encoding="utf-8")
    (second / "two.md").write_text("two", encoding="utf-8")

    index.build()

    assert index.search("*.md")["total_matches"] == 2
