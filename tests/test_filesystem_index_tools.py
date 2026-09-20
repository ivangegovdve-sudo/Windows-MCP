from __future__ import annotations

import asyncio
import json
from collections.abc import Callable

from windows_mcp.filesystem.index import FilesystemIndex
from windows_mcp.tools import filesystem_index as index_tools


class FakeMCP:
    def __init__(self) -> None:
        self.tools: dict[str, Callable] = {}
        self.tool_options: dict[str, dict[str, object]] = {}

    def tool(self, *, name: str, **kwargs: object) -> Callable:
        self.tool_options[name] = kwargs

        def decorator(func: Callable) -> Callable:
            self.tools[name] = func
            return func

        return decorator


def test_index_tools_are_registered_read_only_and_report_search_denominator(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "plan.md").write_text("plan", encoding="utf-8")
    index = FilesystemIndex(":memory:", [str(root)])
    index.build()
    mcp = FakeMCP()

    index_tools.register(mcp, get_index=lambda: index, get_analytics=lambda: None)

    assert set(mcp.tools) == {
        "IndexedFileSearch",
        "IndexedDirectory",
        "IndexedPathInfo",
        "FilesystemIndexStatus",
    }
    for options in mcp.tool_options.values():
        annotations = options["annotations"]
        assert annotations.readOnlyHint is True
        assert annotations.destructiveHint is False

    payload = json.loads(asyncio.run(mcp.tools["IndexedFileSearch"]("*.md")))
    assert payload["items"][0]["name"] == "plan.md"
    assert payload["searched_roots"] == [str(root)]
    assert payload["coverage"][0]["state"] == "fresh"
    assert payload["exclusions"]


def test_index_tools_fail_explicitly_when_service_is_not_configured():
    mcp = FakeMCP()
    index_tools.register(mcp, get_index=lambda: None, get_analytics=lambda: None)

    result = asyncio.run(mcp.tools["FilesystemIndexStatus"]())

    assert result.startswith("Error: filesystem index is not configured")
