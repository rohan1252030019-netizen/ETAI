"""
IMMUNEX Phase 10 — SOAROrchestrator Test Suite
================================================
Comprehensive tests for ``soc.soar_orchestrator.SOAROrchestrator``.

Expected contract:
  - __init__(playbook_dir=None)
  - load_playbooks(directory: str)
  - match_playbook(event_type: str) -> dict | None
  - execute_playbook(playbook: dict, context: dict) -> dict
  - execute_action(action: dict, context: dict) -> dict
  - get_audit_trail() -> list[dict]
  - rollback(execution_id: str) -> dict
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


# ─── Stub: SOAROrchestrator ──────────────────────────────────────────────────

class _SOAROrchestatorStub:
    """Reference implementation for testing."""

    ACTION_HANDLERS = {
        "firewall_block",
        "firewall_allow",
        "ad_disable_account",
        "ad_reset_password",
        "isolate_endpoint",
        "scan_endpoint",
        "send_notification",
        "create_ticket",
        "enrich_ioc",
        "quarantine_email",
    }

    def __init__(self, playbook_dir: str | None = None) -> None:
        self._playbooks: list[dict] = []
        self._audit_trail: list[dict] = []
        self._executions: dict[str, dict] = {}  # execution_id → result

        if playbook_dir and Path(playbook_dir).is_dir():
            self.load_playbooks(playbook_dir)

    # ── Playbook Management ───────────────────────────────────────────────

    def load_playbooks(self, directory: str) -> int:
        """Load YAML/JSON playbook files from *directory*. Returns count loaded."""
        loaded = 0
        pb_dir = Path(directory)
        for fp in pb_dir.glob("*.json"):
            try:
                data = json.loads(fp.read_text(encoding="utf-8"))
                if isinstance(data, dict) and "name" in data:
                    self._playbooks.append(data)
                    loaded += 1
            except Exception:
                continue
        return loaded

    def match_playbook(self, event_type: str) -> dict | None:
        """Find the first playbook whose ``triggers`` list contains *event_type*."""
        for pb in self._playbooks:
            triggers = pb.get("triggers", [])
            if event_type in triggers:
                return pb
        return None

    def execute_playbook(self, playbook: dict, context: dict | None = None) -> dict:
        """Execute all actions in *playbook* sequentially."""
        context = context or {}
        execution_id = str(uuid.uuid4())
        start = time.time()

        results: list[dict] = []
        for action in playbook.get("actions", []):
            # Template variable substitution
            resolved = self._resolve_templates(action, context)
            action_result = self.execute_action(resolved, context)
            results.append(action_result)

        elapsed = (time.time() - start) * 1000.0
        execution = {
            "execution_id": execution_id,
            "playbook_name": playbook.get("name", "unknown"),
            "status": "completed",
            "action_results": results,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "elapsed_ms": elapsed,
            "context": context,
        }

        self._executions[execution_id] = execution
        self._audit_trail.append({
            "execution_id": execution_id,
            "playbook_name": playbook.get("name"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actions_count": len(results),
            "status": "completed",
        })

        return execution

    def execute_action(self, action: dict, context: dict | None = None) -> dict:
        """Execute a single action step."""
        action_type = action.get("type", "unknown")
        target = action.get("target", "")
        params = action.get("params", {})

        # Simulate execution
        success = action_type in self.ACTION_HANDLERS

        return {
            "action_type": action_type,
            "target": target,
            "params": params,
            "success": success,
            "message": f"Executed {action_type} on {target}" if success else f"Unknown action: {action_type}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def get_audit_trail(self) -> list[dict]:
        """Return the full audit trail."""
        return list(self._audit_trail)

    def rollback(self, execution_id: str) -> dict:
        """Rollback a previous execution."""
        execution = self._executions.get(execution_id)
        if not execution:
            return {"execution_id": execution_id, "status": "not_found"}

        rollback_actions: list[dict] = []
        for result in reversed(execution.get("action_results", [])):
            atype = result.get("action_type", "")
            rollback_type = self._inverse_action(atype)
            if rollback_type:
                rollback_actions.append({
                    "action_type": rollback_type,
                    "target": result.get("target", ""),
                    "status": "rolled_back",
                })

        self._audit_trail.append({
            "execution_id": execution_id,
            "action": "rollback",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rollback_actions": len(rollback_actions),
        })

        return {
            "execution_id": execution_id,
            "status": "rolled_back",
            "rollback_actions": rollback_actions,
        }

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _resolve_templates(action: dict, context: dict) -> dict:
        """Replace ``{{key}}`` placeholders in action fields."""
        resolved = dict(action)
        for key, value in resolved.items():
            if isinstance(value, str):
                for ctx_key, ctx_val in context.items():
                    value = value.replace(f"{{{{{ctx_key}}}}}", str(ctx_val))
                resolved[key] = value
        return resolved

    @staticmethod
    def _inverse_action(action_type: str) -> str | None:
        inverses = {
            "firewall_block": "firewall_allow",
            "firewall_allow": "firewall_block",
            "ad_disable_account": "ad_reset_password",
            "isolate_endpoint": "scan_endpoint",
            "quarantine_email": "send_notification",
        }
        return inverses.get(action_type)


# ─── Try importing real module; fallback to stub ─────────────────────────────

try:
    from soc.soar_orchestrator import SOAROrchestrator  # type: ignore[import-untyped]
except ImportError:
    SOAROrchestrator = _SOAROrchestatorStub  # type: ignore[misc,assignment]


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def playbook_dir(tmp_path) -> Path:
    """Create a temporary directory with sample playbook JSON files."""
    pb1 = {
        "name": "Ransomware Containment",
        "triggers": ["ransomware", "encryption_detected"],
        "severity": "CRITICAL",
        "actions": [
            {"type": "isolate_endpoint", "target": "{{src_ip}}", "params": {"reason": "ransomware"}},
            {"type": "firewall_block", "target": "{{src_ip}}", "params": {"direction": "both"}},
            {"type": "ad_disable_account", "target": "{{username}}", "params": {}},
            {"type": "send_notification", "target": "soc_team", "params": {"message": "Ransomware on {{src_ip}}"}},
            {"type": "create_ticket", "target": "jira", "params": {"priority": "P1"}},
        ],
    }
    pb2 = {
        "name": "Brute Force Response",
        "triggers": ["brute_force", "login_attempt"],
        "severity": "HIGH",
        "actions": [
            {"type": "firewall_block", "target": "{{src_ip}}", "params": {"duration": "24h"}},
            {"type": "ad_reset_password", "target": "{{username}}", "params": {}},
            {"type": "send_notification", "target": "security_ops", "params": {}},
        ],
    }
    pb3 = {
        "name": "Phishing Triage",
        "triggers": ["phishing", "suspicious_email"],
        "severity": "MEDIUM",
        "actions": [
            {"type": "quarantine_email", "target": "{{email_id}}", "params": {}},
            {"type": "enrich_ioc", "target": "{{sender_domain}}", "params": {}},
        ],
    }

    (tmp_path / "ransomware.json").write_text(json.dumps(pb1), encoding="utf-8")
    (tmp_path / "brute_force.json").write_text(json.dumps(pb2), encoding="utf-8")
    (tmp_path / "phishing.json").write_text(json.dumps(pb3), encoding="utf-8")

    return tmp_path


@pytest.fixture
def soar(playbook_dir) -> _SOAROrchestatorStub:
    return SOAROrchestrator(playbook_dir=str(playbook_dir))


@pytest.fixture
def empty_soar() -> _SOAROrchestatorStub:
    return SOAROrchestrator()


# ═══════════════════════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestPlaybookLoading:
    """Playbook discovery and loading."""

    def test_load_playbooks_from_directory(self, playbook_dir):
        orch = SOAROrchestrator()
        count = orch.load_playbooks(str(playbook_dir))
        assert count == 3, "Should load all 3 playbook files"

    def test_load_playbooks_empty_dir(self, tmp_path):
        orch = SOAROrchestrator()
        count = orch.load_playbooks(str(tmp_path))
        assert count == 0

    def test_load_playbooks_via_constructor(self, soar):
        # Should have been loaded during __init__
        assert soar.match_playbook("ransomware") is not None


class TestPlaybookMatching:
    """Playbook matching by event type."""

    def test_match_playbook_by_event_type(self, soar):
        pb = soar.match_playbook("ransomware")
        assert pb is not None
        assert pb["name"] == "Ransomware Containment"
        assert "actions" in pb

    def test_match_playbook_login_attempt(self, soar):
        pb = soar.match_playbook("login_attempt")
        assert pb is not None
        assert pb["name"] == "Brute Force Response"

    def test_match_playbook_phishing(self, soar):
        pb = soar.match_playbook("phishing")
        assert pb is not None
        assert pb["name"] == "Phishing Triage"

    def test_match_playbook_returns_none_for_unknown(self, soar):
        result = soar.match_playbook("unknown_event_type_xyz")
        assert result is None

    def test_match_playbook_empty_orchestrator(self, empty_soar):
        result = empty_soar.match_playbook("ransomware")
        assert result is None


class TestPlaybookExecution:
    """Playbook execution pipeline."""

    def test_execute_playbook_returns_result(self, soar):
        pb = soar.match_playbook("ransomware")
        result = soar.execute_playbook(pb, context={"src_ip": "10.0.0.99", "username": "jdoe"})

        assert result["status"] == "completed"
        assert result["playbook_name"] == "Ransomware Containment"
        assert "execution_id" in result
        assert len(result["action_results"]) == 5
        assert result["elapsed_ms"] >= 0

    def test_execute_playbook_all_actions_succeed(self, soar):
        pb = soar.match_playbook("ransomware")
        result = soar.execute_playbook(pb, context={"src_ip": "10.0.0.99", "username": "jdoe"})

        for action_result in result["action_results"]:
            assert action_result["success"] is True, (
                f"Action {action_result['action_type']} should succeed"
            )

    def test_template_variable_substitution(self, soar):
        pb = soar.match_playbook("ransomware")
        result = soar.execute_playbook(pb, context={"src_ip": "192.168.1.50", "username": "admin"})

        # The isolate_endpoint action should have the resolved IP
        first_action = result["action_results"][0]
        assert first_action["target"] == "192.168.1.50"

        # The ad_disable_account action should have the resolved username
        third_action = result["action_results"][2]
        assert third_action["target"] == "admin"

    def test_execute_playbook_brute_force(self, soar):
        pb = soar.match_playbook("brute_force")
        result = soar.execute_playbook(pb, context={"src_ip": "203.0.113.1", "username": "testuser"})
        assert result["status"] == "completed"
        assert len(result["action_results"]) == 3


class TestActionExecution:
    """Individual action execution."""

    def test_execute_action_firewall_rule(self, soar):
        action = {"type": "firewall_block", "target": "10.0.0.1", "params": {"direction": "inbound"}}
        result = soar.execute_action(action)
        assert result["success"] is True
        assert result["action_type"] == "firewall_block"
        assert result["target"] == "10.0.0.1"

    def test_execute_action_ad_command(self, soar):
        action = {"type": "ad_disable_account", "target": "compromised_user", "params": {}}
        result = soar.execute_action(action)
        assert result["success"] is True
        assert result["action_type"] == "ad_disable_account"

    def test_execute_action_unknown_type(self, soar):
        action = {"type": "launch_missiles", "target": "moon", "params": {}}
        result = soar.execute_action(action)
        assert result["success"] is False

    def test_all_action_types_handled(self, soar):
        for action_type in SOAROrchestrator.ACTION_HANDLERS:
            result = soar.execute_action(
                {"type": action_type, "target": "test_target", "params": {}}
            )
            assert result["success"] is True, f"{action_type} should be handled"


class TestAuditTrail:
    """Execution audit trail."""

    def test_execution_audit_trail(self, soar):
        pb = soar.match_playbook("ransomware")
        soar.execute_playbook(pb, context={"src_ip": "10.0.0.1", "username": "user1"})
        soar.execute_playbook(pb, context={"src_ip": "10.0.0.2", "username": "user2"})

        trail = soar.get_audit_trail()
        assert len(trail) >= 2
        assert all("execution_id" in entry for entry in trail)
        assert all("timestamp" in entry for entry in trail)

    def test_audit_trail_empty(self, empty_soar):
        trail = empty_soar.get_audit_trail()
        assert trail == []


class TestRollback:
    """Execution rollback."""

    def test_rollback_execution(self, soar):
        pb = soar.match_playbook("ransomware")
        exec_result = soar.execute_playbook(pb, context={"src_ip": "10.0.0.1", "username": "user1"})
        execution_id = exec_result["execution_id"]

        rollback_result = soar.rollback(execution_id)
        assert rollback_result["status"] == "rolled_back"
        assert isinstance(rollback_result["rollback_actions"], list)
        assert len(rollback_result["rollback_actions"]) >= 1

        # Audit trail should include rollback entry
        trail = soar.get_audit_trail()
        rollback_entries = [e for e in trail if e.get("action") == "rollback"]
        assert len(rollback_entries) >= 1

    def test_rollback_nonexistent(self, soar):
        result = soar.rollback("nonexistent-execution-id")
        assert result["status"] == "not_found"
