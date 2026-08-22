"""Policy engine for Windows-MCP permission layer."""

import json
import inspect
import logging
import re
import time
from functools import wraps
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

SECRET_PATTERNS = [
    r"(sk-[a-zA-Z0-9_-]+)",
    r"(gh[pousr]_[a-zA-Z0-9]+)",
    r"(xox[baprs]-[a-zA-Z0-9]+)",
    r"(AIza[0-9A-Za-z-_]+)",
    r"(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)",
]

CREDENTIAL_NAME = (
    r"(?:[a-z0-9]+[_-])*(?:api[_-]?key|client[_-]?secret|access[_-]?token|"
    r"refresh[_-]?token)|secret|token|password|passwd|pwd|authorization|auth|bearer"
)
ASSIGNMENT_PATTERN = re.compile(
    rf"(?i)(?P<prefix>[\"']?\b(?:{CREDENTIAL_NAME})\b[\"']?\s*[:=]\s*)"
    r"(?P<value>(?:(?:bearer|basic)\s+)?(?:\"[^\"]*\"|'[^']*'|[^\s,;]+))"
)


def scrub_string(text: str) -> str:
    for pattern in SECRET_PATTERNS:
        text = re.sub(pattern, "***REDACTED***", text)
    return ASSIGNMENT_PATTERN.sub(
        lambda match: f"{match.group('prefix')}***REDACTED***",
        text,
    )


def scrub_recursive(data: Any) -> Any:
    if isinstance(data, str):
        return scrub_string(data)
    elif isinstance(data, dict):
        return {k: scrub_recursive(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [scrub_recursive(v) for v in data]
    return data


def sanitize_args(tool_name: str, kwargs: dict) -> dict:
    """Sanitize arguments for the audit log."""
    safe_kwargs = dict(kwargs)

    # Precise per-tool redactions
    if tool_name == "Type" and "text" in safe_kwargs:
        safe_kwargs["text"] = "***REDACTED***"
    elif tool_name == "Shortcut" and "shortcut" in safe_kwargs:
        safe_kwargs["shortcut"] = "***REDACTED***"
    elif tool_name == "Clipboard" and safe_kwargs.get("mode") == "set" and "text" in safe_kwargs:
        safe_kwargs["text"] = "***REDACTED***"
    elif tool_name == "Registry" and safe_kwargs.get("mode") == "set" and "value" in safe_kwargs:
        safe_kwargs["value"] = "***REDACTED***"
    elif tool_name == "MultiEdit":
        # MultiEdit accepts locs=[[x,y,text], ...] and labels=[[label,text], ...]
        if "locs" in safe_kwargs and safe_kwargs["locs"]:
            locs = safe_kwargs["locs"]
            if isinstance(locs, str):
                try:
                    locs = json.loads(locs)
                except Exception:
                    pass
            safe_locs = []
            if isinstance(locs, list):
                for item in locs:
                    if isinstance(item, list) and len(item) == 3:
                        safe_locs.append([item[0], item[1], "***REDACTED***"])
                    else:
                        safe_locs.append(item)
                safe_kwargs["locs"] = safe_locs
        if "labels" in safe_kwargs and safe_kwargs["labels"]:
            labels = safe_kwargs["labels"]
            if isinstance(labels, str):
                try:
                    labels = json.loads(labels)
                except Exception:
                    pass
            safe_labels = []
            if isinstance(labels, list):
                for item in labels:
                    if isinstance(item, list) and len(item) == 2:
                        safe_labels.append([item[0], "***REDACTED***"])
                    else:
                        safe_labels.append(item)
                safe_kwargs["labels"] = safe_labels

    # Remove context
    safe_kwargs.pop("ctx", None)

    # Final scrub over every string bound for the log
    return scrub_recursive(safe_kwargs)


class PolicyEngine:
    def __init__(self, policy_path: Path, audit_path: Path):
        self.policy_path = policy_path
        self.audit_path = audit_path
        self._policy = None

        # Ensure audit log directory exists
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        self.reload()

    def reload(self):
        """Load policy from file, failing closed on error."""
        if not self.policy_path.exists():
            self._policy = {"status": "fail_closed", "reason": "Missing policy file"}
            return

        try:
            with open(self.policy_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
        except Exception:
            self._policy = {
                "status": "fail_closed",
                "reason": "Malformed or unreadable policy file",
            }
            return

        if not self._is_valid_policy(loaded):
            self._policy = {
                "status": "fail_closed",
                "reason": "Structurally invalid policy file",
            }
            return

        self._policy = loaded

    @staticmethod
    def _is_valid_policy(loaded: Any) -> bool:
        if not isinstance(loaded, dict):
            return False

        allowed_tools = loaded.get("allowed_tools", [])
        if not isinstance(allowed_tools, list) or not all(
            isinstance(tool, str) for tool in allowed_tools
        ):
            return False

        allowed_modes = loaded.get("allowed_modes", {})
        if not isinstance(allowed_modes, dict):
            return False
        if not all(
            isinstance(tool, str)
            and isinstance(modes, list)
            and all(isinstance(mode, str) for mode in modes)
            for tool, modes in allowed_modes.items()
        ):
            return False

        return "allow_drag" not in loaded or isinstance(loaded["allow_drag"], bool)

    def is_consequential(self, tool_name: str, kwargs: dict) -> bool:
        """Determine if an action is consequential based on tool and arguments."""
        consequential_tools = {
            "PowerShell",
            "Click",
            "Type",
            "Shortcut",
            "MultiSelect",
            "MultiEdit",
        }

        if tool_name in consequential_tools:
            return True

        if tool_name == "FileSystem":
            mode = kwargs.get("mode", "read")
            if mode in ["write", "move", "delete"]:
                return True
            if mode == "copy" and kwargs.get("overwrite", False):
                return True

        if tool_name == "App":
            mode = kwargs.get("mode", "launch")
            if mode in ["launch", "launch_executable", "switch"]:
                return True

        if tool_name == "Process":
            if kwargs.get("mode") == "kill":
                return True

        if tool_name == "Registry":
            mode = kwargs.get("mode", "get")
            if mode in ["set", "delete"]:
                return True

        if tool_name == "Move":
            if kwargs.get("drag", False):
                return True

        return False

    def evaluate(self, tool_name: str, kwargs: dict) -> bool:
        """Evaluate if the action is permitted."""
        # Fail closed check
        if self._policy and self._policy.get("status") == "fail_closed":
            return False

        allowed_tools = self._policy.get("allowed_tools", [])
        if tool_name not in allowed_tools:
            return False

        # Consequential mode-based actions require an explicit exact-mode allow.
        allowed_modes = self._policy.get("allowed_modes", {})
        mode = kwargs.get("mode")
        if mode is not None:
            tool_modes = allowed_modes.get(tool_name)
            if tool_modes is None or mode not in tool_modes:
                return False

        # Drag specific permission
        if tool_name == "Move" and kwargs.get("drag", False):
            if not self._policy.get("allow_drag", False):
                return False

        return True

    def log_audit(self, tool_name: str, kwargs: dict, decision: str) -> bool:
        sanitized = sanitize_args(tool_name, kwargs)
        entry = {
            "timestamp": time.time(),
            "tool": tool_name,
            "args": sanitized,
            "decision": decision,
        }
        try:
            with open(self.audit_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
            return True
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
            return False


# Global instance
_engine = None


def get_policy_engine() -> PolicyEngine:
    global _engine
    if _engine is None:
        policy_path = Path("~/.windows-mcp/permissions.json").expanduser()
        audit_path = Path("~/.windows-mcp/audit.log").expanduser()
        _engine = PolicyEngine(policy_path, audit_path)
    return _engine


def requires_permission(tool_name: str):
    """Decorator to enforce policy checks on tool execution."""

    def decorator(func: Callable):
        def enforce(args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
            # In FastMCP, tool arguments are usually passed as kwargs.
            # However, if passed as args, we need a way to inspect them.
            # To keep things simple and robust for Stage 1, we assume
            # arguments are either kwargs or we inspect the function signature.
            # FastMCP generally passes user inputs as kwargs.
            sig = inspect.signature(func)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            all_kwargs = bound.arguments

            engine = get_policy_engine()

            if engine.is_consequential(tool_name, all_kwargs):
                allowed = engine.evaluate(tool_name, all_kwargs)
                if not allowed:
                    engine.log_audit(tool_name, all_kwargs, "DENIED")
                    raise PermissionError(f"Action '{tool_name}' is denied by the server policy.")
                if not engine.log_audit(tool_name, all_kwargs, "ALLOWED"):
                    raise PermissionError(f"Action '{tool_name}' is denied by the server policy.")
            else:
                engine.log_audit(tool_name, all_kwargs, "ALLOWED (Reversible)")

        if inspect.iscoroutinefunction(func):

            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                enforce(args, kwargs)
                return await func(*args, **kwargs)

            return async_wrapper

        @wraps(func)
        def wrapper(*args, **kwargs):
            enforce(args, kwargs)
            return func(*args, **kwargs)

        return wrapper

    return decorator
