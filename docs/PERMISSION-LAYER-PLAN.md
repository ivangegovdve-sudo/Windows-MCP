# Windows-MCP Permission Layer Design

This document outlines a plan to implement a server-side permission layer for Windows-MCP. The goal is to enforce safety boundaries on the server rather than relying on the connecting agent's prompt or judgment.

## 1. Tool Audit & Blast Radius Classification

Every tool exposed by Windows-MCP must be classified into one of three categories: Read-only observation, Reversible action, or Irreversible/consequential action.

| Tool Category / Name | Action Mode / Function | Blast Radius Classification | Notes |
|---|---|---|---|
| **Snapshot** | Screenshot | Read-only observation | May capture sensitive info; see Section 3. |
| | UI Tree | Read-only observation | |
| **FileSystem** | `read`, `list`, `info`, `search` | Read-only observation | |
| | `copy` | Reversible action (mostly) | Reversible if `overwrite=False`. If `overwrite=True`, it is irreversible. |
| | `write`, `move` | Irreversible/consequential action | Modifies files or changes system state. |
| | `delete` | Irreversible/consequential action | |
| **Shell** | `powershell` | Irreversible/consequential action | Unconstrained execution; highest blast radius. |
| **Input** | `click` | Context-dependent (Consequential) | Clicking "Save" vs "Delete" is indistinguishable without context. |
| | `type` | Context-dependent (Consequential) | Could be typing a password, sending an email, or formatting a drive. |
| | `scroll`, `move`, `wait`, `waitFor` | Reversible action | Generally safe, though `scroll` can change view state. |
| | `shortcut` | Context-dependent (Consequential) | E.g., `Ctrl+S` vs `Alt+F4`. |
| **App** | `launch`, `close`, `focus` | Consequential action | Can interrupt user workflow or cause data loss (`close`). |
| **Process** | `list` | Read-only observation | |
| | `kill` | Irreversible/consequential action | |
| **Registry** | `read`, `list` | Read-only observation | |
| | `write`, `delete` | Irreversible/consequential action | High risk of system instability. |
| **Clipboard** | `read` | Read-only observation | Exposes potentially sensitive data (passwords). |
| | `write` | Reversible action | |
| **Display** | `inventory` | Read-only observation | |
| **Notification**| `send` | Reversible action | Annoying but harmless. |
| **Multi** | `multiSelect`, `multiEdit` | Consequential action | Same concerns as `click`/`type`. |
| **Scrape** | `scrape` | Read-only observation | Reaches out to the internet. |

## 2. Permission Layer Design

The permission layer will be governed by a configuration file (e.g., `permissions.json` or `permissions.yaml`).

### Core Principles
1. **Server-Side Enforcement**: The policy lives in the server; agents cannot override it. Rules are in server-side configuration rather than agent prompts.
2. **Fail Closed**: If the policy file is missing or malformed, the server fails CLOSED and all consequential actions are denied by default.
3. **Default-Deny for Consequential Actions**: Explicit allow-listing is required for actions like `Shell`, `FileSystem.delete`, or `Registry.write`.
4. **Append-Only Audit Log**: Every tool invocation is logged to an append-only file. The logger will sanitize parameters: it will *never* record secret values, key material, clipboard contents, or screenshots of credential fields. It logs *intent* (e.g., "Agent requested `Type` tool") and coordinates/metadata, but not payload data.
5. **Human-Approval Path**:
   - For tools marked as `requires_approval`, the tool execution blocks.
   - A system tray notification or out-of-band mechanism displays the request.
   - The request states plainly what is about to happen: e.g., "Agent [Name] is requesting to execute [Command/Action]".
   - The agent waits until approved/denied.

## 3. The Honest Limits (The Hard Part)

Some actions are dangerous only depending on what is on screen, and coordinates alone cannot tell you that. The hardest part of driving a UI via accessibility trees and coordinates is that **intent and safety are context-dependent**, and the server cannot always know the context.

*   **The Coordinate Problem**: A click on `(x: 100, y: 200)` is just a click. The server doesn't know if that's the "Cancel" button or the "Confirm Purchase" button unless it cross-references the UI tree at that exact moment. Even then, UI trees can be misleading or laggy.
*   **The Keystroke Problem**: Sending "yes\n" to a terminal might accept a benign prompt or confirm a disk wipe. The server cannot reliably parse the visual or textual context of the active window to determine safety.
*   **The Credential Field Problem**: A screenshot captures whatever is on screen. If a password manager is open and unmasked, the screenshot contains the password. The server cannot reliably mask these out before sending them to the agent without advanced, slow OCR/CV, which is often brittle.

**Our Approach & Admitted Limits**:
We will *not* attempt to build a perfect AI vision system inside the server to evaluate the safety of clicks and keystrokes. What genuinely cannot be determined is the exact visual or textual context of an action at execution time.
Instead, we rely on macro-level controls:
- **Global Input Lockout**: Allow the human to quickly pause agent input.
- **Process-Level Restrictions**: Allow configuring the server to refuse input tools if certain high-risk applications (e.g., `KeePass.exe`, `regedit.exe`) are the active window.
- **Limit Admission**: We explicitly state that if `Click` and `Type` are enabled, the agent has full desktop control. The permission layer protects against *systemic* abuse (like hidden shell scripts), not against the agent blundering through a UI.

## 4. Multi-Agent Arbitration

**Scenario**: Two agents connect and try to drive the desktop simultaneously.

**Recommendation**: **Strict Locking (Refusal/Mutual Exclusion)**.
**Justification**: A desktop environment is a single stateful resource. If Agent A starts typing while Agent B clicks to focus a different window, Agent A's keystrokes go to Agent B's window. This causes catastrophic confusion for both agents.
*   **Implementation**: Only one active "session" can hold the lock for input/consequential tools. Other agents can connect and use read-only tools (like `Snapshot` or `Process.list`), but if they attempt to use an input tool, the server returns an explicit refusal (e.g., "Error: Desktop is currently locked by another agent"). We will not queue inputs, as the UI state will have changed by the time queued inputs execute. Refusal is the safest and most predictable approach.

## 5. Upstream Posture

**Recommendation**: **Keep a Private Fork (for now), aiming for Upstream Contribution later.**

**Trade-offs**:
*   **Upstream Contribution (PR to CursorTouch/Windows-MCP)**:
    *   *Maintenance*: Lower long-term maintenance burden; benefits the wider community.
    *   *Trade-off*: Imposing a strict permission layer might break existing workflows for users who treat Windows-MCP as an unconstrained playground. The design must be extremely flexible (e.g., an easy "allow-all" flag) to be accepted upstream.
*   **Private Fork**:
    *   *Maintenance*: Must manually merge upstream updates (new tools, bug fixes); risk of diverging too far. Higher maintenance burden.
    *   *Trade-off*: Complete control over the security posture; can move fast and break things; no need to debate default settings with upstream maintainers.

**Strategy**: Implement the permission layer in this fork. Design it cleanly via decorators and a centralized policy engine. Once stable, offer it upstream as an *optional* feature (disabled by default for backward compatibility, but highly recommended).

## 6. Staged Implementation Sequence & Effort Estimate

| Stage | Goal | Description | Rough Effort Estimate |
|---|---|---|---|
| **Stage 1** | **Policy Engine & Fail-Closed** | Create `policy.py` to read `permissions.json` config. Implement the fail-closed logic. Wrap existing tools with a `@requires_permission` decorator. | 2-3 Days |
| **Stage 2** | **Sanitized Audit Logging** | Implement the append-only JSONL logger. Ensure parameter redaction for secret values, `type`, `shortcut`, and `clipboard`. | 1-2 Days |
| **Stage 3** | **Multi-Agent Locking** | Implement a session token/lock mechanism for input tools. Ensure clear error messages for lock contention / refusal. | 2 Days |
| **Stage 4** | **Human-Approval Path** | Implement the blocking approval flow stating plainly what will happen. Requires a small UI component (e.g., a system tray balloon or basic dialog) that can block the async tool call. | 3-5 Days |
| **Stage 5** | **Active Window Awareness** | Refuse input tools if the active window title/process matches a high-risk blocklist. | 1-2 Days |
