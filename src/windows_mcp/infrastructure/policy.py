"""Policy engine for Windows-MCP permission layer."""

import json
import logging
import time
from pathlib import Path
from functools import wraps
from typing import Callable, Any, Optional

logger = logging.getLogger(__name__)

def sanitize_args(tool_name: str, kwargs: dict) -> dict:
    """Sanitize arguments for the audit log."""
    safe_kwargs = dict(kwargs)

    # Redact secret or sensitive values
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

    return safe_kwargs

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
                self._policy = json.load(f)
        except Exception as e:
            self._policy = {"status": "fail_closed", "reason": f"Malformed policy file: {e}"}

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

        # Tool-specific granular permissions (modes)
        allowed_modes = self._policy.get("allowed_modes", {})
        if tool_name in allowed_modes:
            mode = kwargs.get("mode")
            if mode is not None and mode not in allowed_modes[tool_name]:
                return False

        # Drag specific permission
        if tool_name == "Move" and kwargs.get("drag", False):
            if not self._policy.get("allow_drag", False):
                return False

        return True

    def log_audit(self, tool_name: str, kwargs: dict, decision: str):
        sanitized = sanitize_args(tool_name, kwargs)
        entry = {
            "timestamp": time.time(),
            "tool": tool_name,
            "args": sanitized,
            "decision": decision
        }
        try:
            with open(self.audit_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")


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
        @wraps(func)
        def wrapper(*args, **kwargs):
            # In FastMCP, tool arguments are usually passed as kwargs.
            # However, if passed as args, we need a way to inspect them.
            # To keep things simple and robust for Stage 1, we assume
            # arguments are either kwargs or we inspect the function signature.
            # FastMCP generally passes user inputs as kwargs.

            import inspect
            sig = inspect.signature(func)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            all_kwargs = bound.arguments

            engine = get_policy_engine()

            if engine.is_consequential(tool_name, all_kwargs):
                allowed = engine.evaluate(tool_name, all_kwargs)
                if not allowed:
                    engine.log_audit(tool_name, all_kwargs, "DENIED")
                    raise PermissionError(
                        f"Action '{tool_name}' is denied by the server policy."
                    )
                else:
                    engine.log_audit(tool_name, all_kwargs, "ALLOWED")
            else:
                engine.log_audit(tool_name, all_kwargs, "ALLOWED (Reversible)")

            return func(*args, **kwargs)
        return wrapper
    return decorator
