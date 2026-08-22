import json
import os
import pytest
from pathlib import Path
from windows_mcp.infrastructure.policy import PolicyEngine

def test_policy_allowed_action(tmp_path):
    policy_file = tmp_path / "permissions.json"
    audit_file = tmp_path / "audit.log"

    # Write a policy that allows FileSystem read and App launch
    policy_data = {
        "allowed_tools": ["FileSystem", "App"],
        "allowed_modes": {
            "FileSystem": ["read"],
            "App": ["launch"]
        }
    }
    policy_file.write_text(json.dumps(policy_data))

    engine = PolicyEngine(policy_file, audit_file)

    # App launch is consequential, let's see if evaluate allows it
    is_consequential = engine.is_consequential("App", {"mode": "launch"})
    assert is_consequential is True

    allowed = engine.evaluate("App", {"mode": "launch"})
    assert allowed is True

    # Test audit logging
    engine.log_audit("App", {"mode": "launch"}, "ALLOWED")

    log_content = audit_file.read_text()
    assert "ALLOWED" in log_content
    assert "App" in log_content

def test_policy_denied_action(tmp_path):
    policy_file = tmp_path / "permissions.json"
    audit_file = tmp_path / "audit.log"

    # Write a policy that explicitly does not allow Shell
    policy_data = {
        "allowed_tools": ["FileSystem", "App"],
        "allowed_modes": {
            "FileSystem": ["read"],
            "App": ["launch"]
        }
    }
    policy_file.write_text(json.dumps(policy_data))

    engine = PolicyEngine(policy_file, audit_file)

    is_consequential = engine.is_consequential("PowerShell", {"command": "echo hi"})
    assert is_consequential is True

    allowed = engine.evaluate("PowerShell", {"command": "echo hi"})
    assert allowed is False

def test_policy_malformed_fails_closed(tmp_path):
    policy_file = tmp_path / "permissions.json"
    audit_file = tmp_path / "audit.log"

    # Write malformed JSON
    policy_file.write_text("{ this is not valid json }")

    engine = PolicyEngine(policy_file, audit_file)

    # Because it fails closed, EVERYTHING should be denied
    # Even if we just ask for evaluate
    allowed = engine.evaluate("App", {"mode": "launch"})
    assert allowed is False

    assert engine._policy.get("status") == "fail_closed"

def test_policy_missing_fails_closed(tmp_path):
    policy_file = tmp_path / "does_not_exist.json"
    audit_file = tmp_path / "audit.log"

    engine = PolicyEngine(policy_file, audit_file)

    allowed = engine.evaluate("App", {"mode": "launch"})
    assert allowed is False

    assert engine._policy.get("status") == "fail_closed"

def test_policy_audit_redaction(tmp_path):
    policy_file = tmp_path / "permissions.json"
    audit_file = tmp_path / "audit.log"
    policy_file.write_text(json.dumps({"allowed_tools": ["Type"]}))

    engine = PolicyEngine(policy_file, audit_file)

    # We simulate a Type tool being called with sensitive text
    engine.log_audit("Type", {"text": "my_secret_password", "loc": [100, 200]}, "ALLOWED")

    log_content = audit_file.read_text()

    # The secret password should NOT be in the audit log
    assert "my_secret_password" not in log_content
    # The redaction string should be in the log
    assert "***REDACTED***" in log_content
    # Non-sensitive arguments should still be there
    assert "100" in log_content

def test_policy_mode_granularity(tmp_path):
    policy_file = tmp_path / "permissions.json"
    audit_file = tmp_path / "audit.log"

    # Allow FileSystem read, but not delete
    policy_data = {
        "allowed_tools": ["FileSystem"],
        "allowed_modes": {
            "FileSystem": ["read", "list"]
        }
    }
    policy_file.write_text(json.dumps(policy_data))

    engine = PolicyEngine(policy_file, audit_file)

    assert engine.evaluate("FileSystem", {"mode": "read"}) is True
    assert engine.evaluate("FileSystem", {"mode": "list"}) is True

    # FileSystem delete is consequential and explicitly not in allowed_modes
    assert engine.is_consequential("FileSystem", {"mode": "delete"}) is True
    assert engine.evaluate("FileSystem", {"mode": "delete"}) is False

def test_policy_drag_mode(tmp_path):
    policy_file = tmp_path / "permissions.json"
    audit_file = tmp_path / "audit.log"

    # Tool Move is allowed, but allow_drag is False by default
    policy_data = {
        "allowed_tools": ["Move"],
    }
    policy_file.write_text(json.dumps(policy_data))

    engine = PolicyEngine(policy_file, audit_file)

    # Simple move (drag=False) should pass
    assert engine.is_consequential("Move", {"drag": False}) is False
    # If a tool is not consequential, evaluate shouldn't block it normally, but here evaluate blocks it if drag=True because allow_drag is False
    assert engine.evaluate("Move", {"drag": False}) is True

    # Drag move (drag=True) should be blocked because allow_drag=False
    assert engine.is_consequential("Move", {"drag": True}) is True
    assert engine.evaluate("Move", {"drag": True}) is False

def test_policy_multiedit_redaction(tmp_path):
    policy_file = tmp_path / "permissions.json"
    audit_file = tmp_path / "audit.log"
    policy_file.write_text(json.dumps({"allowed_tools": ["MultiEdit"]}))

    engine = PolicyEngine(policy_file, audit_file)

    # Simulate MultiEdit
    engine.log_audit("MultiEdit", {"locs": [[100, 200, "secret1"]], "labels": [[5, "secret2"]]}, "ALLOWED")

    log_content = audit_file.read_text()
    assert "secret1" not in log_content
    assert "secret2" not in log_content
    assert "***REDACTED***" in log_content
    assert "100" in log_content

def test_policy_registry_redaction(tmp_path):
    policy_file = tmp_path / "permissions.json"
    audit_file = tmp_path / "audit.log"
    policy_file.write_text(json.dumps({"allowed_tools": ["Registry"], "allowed_modes": {"Registry": ["set"]}}))

    engine = PolicyEngine(policy_file, audit_file)

    # Simulate Registry
    engine.log_audit("Registry", {"mode": "set", "key": "HKCU", "value": "secret_registry"}, "ALLOWED")

    log_content = audit_file.read_text()
    assert "secret_registry" not in log_content
    assert "***REDACTED***" in log_content

def test_policy_clipboard_redaction(tmp_path):
    policy_file = tmp_path / "permissions.json"
    audit_file = tmp_path / "audit.log"
    policy_file.write_text(json.dumps({"allowed_tools": ["Clipboard"]}))

    engine = PolicyEngine(policy_file, audit_file)

    # Simulate Clipboard
    engine.log_audit("Clipboard", {"mode": "set", "text": "secret_clipboard"}, "ALLOWED")

    log_content = audit_file.read_text()
    assert "secret_clipboard" not in log_content
    assert "***REDACTED***" in log_content

def test_policy_shell_consequential(tmp_path):
    policy_file = tmp_path / "permissions.json"
    audit_file = tmp_path / "audit.log"
    # By default PowerShell is consequential and blocked
    policy_file.write_text(json.dumps({"allowed_tools": ["FileSystem"]}))

    engine = PolicyEngine(policy_file, audit_file)

    is_consequential = engine.is_consequential("PowerShell", {"command": "echo hi"})
    assert is_consequential is True

    allowed = engine.evaluate("PowerShell", {"command": "echo hi"})
    assert allowed is False

def test_policy_multiedit_string_redaction(tmp_path):
    policy_file = tmp_path / "permissions.json"
    audit_file = tmp_path / "audit.log"
    policy_file.write_text(json.dumps({"allowed_tools": ["MultiEdit"]}))

    engine = PolicyEngine(policy_file, audit_file)

    # Simulate MultiEdit with string
    engine.log_audit("MultiEdit", {"locs": json.dumps([[100, 200, "secret3"]]), "labels": json.dumps([[5, "secret4"]])}, "ALLOWED")

    log_content = audit_file.read_text()
    assert "secret3" not in log_content
    assert "secret4" not in log_content
    assert "***REDACTED***" in log_content
