"""Behavior tests for the registered-tool permission boundary."""

import asyncio
import json
from pathlib import Path
from typing import Callable

import pytest
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from windows_mcp.infrastructure import policy
from windows_mcp.infrastructure.policy import PolicyEngine, sanitize_args
from windows_mcp.tools import filesystem as filesystem_tool
from windows_mcp.tools import scrape as scrape_tool


def _register_filesystem_tool() -> FastMCP:
    mcp = FastMCP(name="policy-boundary-test")
    filesystem_tool.register(
        mcp,
        get_desktop=lambda: None,
        get_analytics=lambda: None,
    )
    return mcp


def _use_policy(
    monkeypatch: pytest.MonkeyPatch,
    policy_path: Path,
    audit_path: Path,
) -> PolicyEngine:
    engine = PolicyEngine(policy_path, audit_path)
    monkeypatch.setattr(policy, "_engine", engine)
    return engine


def _call_filesystem_write(mcp: FastMCP) -> object:
    return asyncio.run(
        mcp.call_tool(
            "FileSystem",
            {
                "mode": "write",
                "path": "boundary-test.txt",
                "content": "client_secret=opaque-sensitive-value",
            },
        )
    )


def test_registered_consequential_tool_requires_an_explicit_exact_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy_path = tmp_path / "permissions.json"
    policy_path.write_text(json.dumps({"allowed_tools": ["FileSystem"]}), encoding="utf-8")
    _use_policy(monkeypatch, policy_path, tmp_path / "audit.log")
    monkeypatch.setattr(
        filesystem_tool.filesystem,
        "write_file",
        lambda *args, **kwargs: pytest.fail("consequential sink executed"),
    )

    with pytest.raises(ToolError, match="denied by the server policy"):
        _call_filesystem_write(_register_filesystem_tool())


def test_registered_consequential_tool_accepts_a_narrow_exact_mode_allow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy_path = tmp_path / "permissions.json"
    policy_path.write_text(
        json.dumps(
            {
                "allowed_tools": ["FileSystem"],
                "allowed_modes": {"FileSystem": ["write"]},
            }
        ),
        encoding="utf-8",
    )
    _use_policy(monkeypatch, policy_path, tmp_path / "audit.log")
    sink_calls: list[tuple[object, ...]] = []

    def write_file(*args: object, **kwargs: object) -> str:
        sink_calls.append((*args, kwargs))
        return "write completed"

    monkeypatch.setattr(filesystem_tool.filesystem, "write_file", write_file)

    result = _call_filesystem_write(_register_filesystem_tool())

    assert result.content[0].text == "write completed"
    assert len(sink_calls) == 1


def _missing_policy(path: Path) -> None:
    assert not path.exists()


def _empty_policy(path: Path) -> None:
    path.write_text("", encoding="utf-8")


def _malformed_policy(path: Path) -> None:
    path.write_text("{", encoding="utf-8")


def _unreadable_policy(path: Path) -> None:
    path.mkdir()


def _non_object_policy(path: Path) -> None:
    path.write_text("[]", encoding="utf-8")


def _invalid_shape_policy(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "allowed_tools": "FileSystem",
                "allowed_modes": {"FileSystem": "write"},
            }
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    "arrange_policy",
    [
        _missing_policy,
        _empty_policy,
        _malformed_policy,
        _unreadable_policy,
        _non_object_policy,
        _invalid_shape_policy,
    ],
    ids=["missing", "empty", "malformed", "unreadable", "non-object", "invalid-shape"],
)
def test_invalid_policy_denies_registered_consequential_tool_without_calling_sink(
    arrange_policy: Callable[[Path], None],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy_path = tmp_path / "permissions.json"
    arrange_policy(policy_path)
    audit_path = tmp_path / "audit.log"
    _use_policy(monkeypatch, policy_path, audit_path)
    monkeypatch.setattr(
        filesystem_tool.filesystem,
        "write_file",
        lambda *args, **kwargs: pytest.fail("consequential sink executed"),
    )

    with pytest.raises(ToolError, match="denied by the server policy"):
        _call_filesystem_write(_register_filesystem_tool())

    entry = json.loads(audit_path.read_text(encoding="utf-8"))
    assert entry["decision"] == "DENIED"
    assert entry["tool"] == "FileSystem"
    assert entry["args"]["mode"] == "write"
    assert "opaque-sensitive-value" not in audit_path.read_text(encoding="utf-8")


def test_registered_reversible_tool_remains_usable_with_invalid_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy_path = tmp_path / "permissions.json"
    policy_path.write_text("{", encoding="utf-8")
    _use_policy(monkeypatch, policy_path, tmp_path / "audit.log")
    read_calls: list[str] = []

    def read_file(path: str, **kwargs: object) -> str:
        read_calls.append(path)
        return "read completed"

    monkeypatch.setattr(filesystem_tool.filesystem, "read_file", read_file)
    mcp = _register_filesystem_tool()

    result = asyncio.run(mcp.call_tool("FileSystem", {"mode": "read", "path": "boundary-test.txt"}))

    assert result.content[0].text == "read completed"
    assert len(read_calls) == 1


def test_audit_write_failure_denies_before_registered_consequential_sink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy_path = tmp_path / "permissions.json"
    policy_path.write_text(
        json.dumps(
            {
                "allowed_tools": ["FileSystem"],
                "allowed_modes": {"FileSystem": ["write"]},
            }
        ),
        encoding="utf-8",
    )
    audit_path = tmp_path / "audit-target"
    audit_path.mkdir()
    _use_policy(monkeypatch, policy_path, audit_path)
    monkeypatch.setattr(
        filesystem_tool.filesystem,
        "write_file",
        lambda *args, **kwargs: pytest.fail("consequential sink executed"),
    )

    with pytest.raises(ToolError, match="denied by the server policy"):
        _call_filesystem_write(_register_filesystem_tool())


def test_registered_async_scrape_returns_resolved_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Desktop:
        def scrape(self, url: str) -> str:
            return "resolved page content"

    _use_policy(monkeypatch, tmp_path / "missing-policy.json", tmp_path / "audit.log")
    mcp = FastMCP(name="async-policy-boundary-test")
    scrape_tool.register(
        mcp,
        get_desktop=lambda: Desktop(),
        get_analytics=lambda: None,
    )

    result = asyncio.run(
        mcp.call_tool(
            "Scrape",
            {"url": "https://example.invalid", "use_sampling": False},
        )
    )

    assert result.content[0].text == (
        "URL: https://example.invalid\nContent:\nresolved page content"
    )


@pytest.mark.parametrize(
    "assignment",
    [
        "client_secret=opaque-sensitive-value",
        "access-token: opaque-sensitive-value",
        "Authorization: Bearer opaque-sensitive-value",
    ],
)
def test_audit_sanitizes_opaque_assignment_alias_values(assignment: str) -> None:
    sanitized = sanitize_args("PowerShell", {"command": assignment})

    assert "opaque-sensitive-value" not in sanitized["command"]
    assert "***REDACTED***" in sanitized["command"]


def test_audit_sanitizer_preserves_ordinary_text() -> None:
    text = "List token usage and password rotation guidance without assigned values."

    assert sanitize_args("PowerShell", {"command": text}) == {"command": text}
