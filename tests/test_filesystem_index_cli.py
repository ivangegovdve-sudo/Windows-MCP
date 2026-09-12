from __future__ import annotations

import json

from click.testing import CliRunner

from windows_mcp import __main__
from windows_mcp.filesystem.index import BuildStats


def test_index_build_command_is_operator_facing_and_uses_requested_roots(monkeypatch):
    calls: dict[str, object] = {}

    class FakeIndex:
        def __init__(self, db_path, roots, exclusions, mark_startup_stale):
            calls.update(
                db_path=db_path,
                roots=roots,
                exclusions=exclusions,
                mark_startup_stale=mark_startup_stale,
            )

        def build(self):
            return BuildStats(files=2, directories=1, boundaries=1, changes=0, duration_ms=3.5)

        def status(self):
            return {"freshness": "fresh", "searched_roots": calls["roots"]}

        def close(self):
            calls["closed"] = True

    monkeypatch.setattr(__main__, "FilesystemIndex", FakeIndex)
    result = CliRunner().invoke(
        __main__.main,
        [
            "index",
            "build",
            "--db",
            r"N:\WindowsMCP\filesystem-index\index.sqlite3",
            "--root",
            r"D:\output",
            "--exclude",
            "vault",
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls == {
        "db_path": r"N:\WindowsMCP\filesystem-index\index.sqlite3",
        "roots": (r"D:\output",),
        "exclusions": ("vault",),
        "mark_startup_stale": False,
        "closed": True,
    }
    assert json.loads(result.output)["files"] == 2


def test_index_commands_are_not_exposed_as_mcp_tools():
    class FakeMCP:
        def __init__(self):
            self.tools = {}

        def tool(self, name, **kwargs):
            def decorator(func):
                self.tools[name] = func
                return func
            return decorator

    mcp = FakeMCP()

    from windows_mcp.tools import filesystem_index
    filesystem_index.register(mcp, get_index=lambda: None, get_analytics=lambda: None)

    registered = set(mcp.tools)

    assert "IndexedFileSearch" in registered
    assert "IndexedDirectory" in registered
    assert "IndexedPathInfo" in registered
    assert "FilesystemIndexStatus" in registered

    # Verify that CLI commands aren't exposed as MCP tools
    assert "build" not in registered
    assert "refresh" not in registered
    assert "status" not in registered
