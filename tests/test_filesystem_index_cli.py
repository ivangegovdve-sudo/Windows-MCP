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
    help_result = CliRunner().invoke(__main__.main, ["index", "--help"])

    assert help_result.exit_code == 0
    assert "build" in help_result.output
    assert "refresh" in help_result.output
    assert "status" in help_result.output

    # Additionally verify that no index lifecycle tools are exposed in the MCP registry
    from fastmcp import FastMCP
    from windows_mcp.tools import register_all

    mcp = FastMCP("test-server")

    # Provide mock dependencies to satisfy the permission/analytics handlers during registration
    class DummyAnalytics:
        pass

    class DummyPolicyEngine:
        def get_restrictions(self, tool_name):
            return None

    class DummyState:
        def __init__(self):
            self.policy_engine = DummyPolicyEngine()
            self.analytics = DummyAnalytics()

    state = DummyState()

    register_all(
        mcp,
        get_config=lambda: None,
        get_state=lambda: state,
        get_index=lambda: None,
        get_analytics=lambda: state.analytics,
    )

    # We shouldn't see 'build', 'refresh', or any similar administrative commands
    # exposed as MCP tools. The index tools should be read-only (like search, info).
    tool_names = [tool.name.casefold() for tool in mcp._tool_manager.get_tools()]
    assert not any("build" in name for name in tool_names)
    assert not any("refresh" in name for name in tool_names)
