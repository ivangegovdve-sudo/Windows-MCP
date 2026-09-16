"""Read-only MCP tools backed by the live filesystem metadata index."""

from __future__ import annotations

import json

from fastmcp import Context
from mcp.types import ToolAnnotations

from windows_mcp.infrastructure import with_analytics


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)


def _not_configured() -> str:
    return (
        "Error: filesystem index is not configured. "
        "Configure WINDOWS_MCP_INDEX_DB on N: and run `windows-mcp index build`."
    )


def register(mcp, *, get_index, get_analytics):
    read_only = ToolAnnotations(
        title="Live filesystem index",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )

    @mcp.tool(
        name="IndexedFileSearch",
        description=(
            "Find local files, folders, or boundary entries by glob pattern in the live "
            "metadata index. Results are metadata-only and always include searched roots, "
            "exclusions, index age, per-root coverage, and freshness. No file contents are read."
        ),
        annotations=read_only,
    )
    @with_analytics(get_analytics(), "IndexedFileSearch-Tool")
    def indexed_file_search(
        pattern: str,
        root: str | None = None,
        kind: str = "file",
        limit: int = 100_000,
        ctx: Context = None,
    ) -> str:
        del ctx
        index = get_index()
        if index is None:
            return _not_configured()
        try:
            return _json(index.search(pattern, scope=root, kind=kind, limit=limit))
        except (OSError, ValueError, RuntimeError) as exc:
            return f"Error: indexed file search failed: {exc}"

    @mcp.tool(
        name="IndexedDirectory",
        description=(
            "List immediate children from the live local filesystem metadata index. "
            "The result is bounded, read-only, metadata-only, and reports the complete "
            "searched-root denominator, exclusions, and freshness state."
        ),
        annotations=read_only,
    )
    @with_analytics(get_analytics(), "IndexedDirectory-Tool")
    def indexed_directory(
        path: str,
        limit: int = 10_000,
        ctx: Context = None,
    ) -> str:
        del ctx
        index = get_index()
        if index is None:
            return _not_configured()
        try:
            return _json(index.list_directory(path, limit=limit))
        except (OSError, ValueError, RuntimeError) as exc:
            return f"Error: indexed directory listing failed: {exc}"

    @mcp.tool(
        name="IndexedPathInfo",
        description=(
            "Return indexed metadata for one local file or folder plus a live os.stat "
            "check for that path. Excluded descendants resolve to their boundary row; "
            "contents are never read. Coverage and freshness are always included."
        ),
        annotations=read_only,
    )
    @with_analytics(get_analytics(), "IndexedPathInfo-Tool")
    def indexed_path_info(path: str, ctx: Context = None) -> str:
        del ctx
        index = get_index()
        if index is None:
            return _not_configured()
        try:
            return _json(index.get_metadata(path))
        except (OSError, ValueError, RuntimeError) as exc:
            return f"Error: indexed path metadata failed: {exc}"

    @mcp.tool(
        name="FilesystemIndexStatus",
        description=(
            "Report live filesystem index status, SQLite WAL mode, FTS5 availability, "
            "per-root coverage, pending changes, exclusions, and the reserved content "
            "identity slot. This tool never builds, refreshes, or mutates the index."
        ),
        annotations=read_only,
    )
    @with_analytics(get_analytics(), "FilesystemIndexStatus-Tool")
    def filesystem_index_status(ctx: Context = None) -> str:
        del ctx
        index = get_index()
        if index is None:
            return _not_configured()
        try:
            return _json(index.status())
        except (OSError, ValueError, RuntimeError) as exc:
            return f"Error: filesystem index status failed: {exc}"
