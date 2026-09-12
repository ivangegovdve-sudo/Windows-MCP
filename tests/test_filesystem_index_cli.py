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


def test_index_commands_are_not_exposed_as_mcp_tools(monkeypatch):
    help_result = CliRunner().invoke(__main__.main, ["index", "--help"])

    assert help_result.exit_code == 0
    assert "build" in help_result.output
    assert "refresh" in help_result.output
    assert "status" in help_result.output

    tools = []

    class FakeMCP:
        def __init__(self, **kwargs):
            pass

        def tool(self, **kwargs):
            def decorator(f):
                tools.append(kwargs.get("name") or f.__name__)
                return f
            return decorator

    monkeypatch.setattr(__main__, "FastMCP", FakeMCP)
    __main__._build_mcp()

    assert not any("build" in name.lower() for name in tools)
    assert not any("refresh" in name.lower() for name in tools)
