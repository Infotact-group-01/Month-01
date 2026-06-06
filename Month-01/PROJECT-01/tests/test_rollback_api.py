"""Tests for the Rollback REST API (Week 4).

All tests run against a Flask test client — no real server, no real network,
no real firewall changes. Firewall calls are mocked.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import src.rollback_api as api_module
from src.rollback_api import app


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture()
def client():
    """Flask test client with dry-run enabled and a fresh in-memory state."""
    app.testing = True
    api_module._DRY_RUN = True
    return app.test_client()


@pytest.fixture()
def state_with_blocked(tmp_path, monkeypatch):
    """Patch the state file to a temp file pre-populated with two blocked IPs."""
    fake_state = tmp_path / "enforcer_state.json"
    state = {
        "blocked": {
            "1.2.3.4": {
                "blocked_at": "2026-05-25T10:00:00+00:00",
                "risk_score": 95,
                "source": "AbuseIPDB",
                "tags": ["malware", "ssh-brute-force"],
                "rule_name": "TIP-BLOCK-1.2.3.4",
            },
            "5.5.5.5": {
                "blocked_at": "2026-05-25T11:00:00+00:00",
                "risk_score": 90,
                "source": "EmergingThreats_IPs",
                "tags": [],
                "rule_name": "TIP-BLOCK-5.5.5.5",
            },
        }
    }
    fake_state.write_text(json.dumps(state), encoding="utf-8")
    monkeypatch.setattr("src.rollback_api.STATE_FILE", fake_state)
    monkeypatch.setattr("src.rollback_api.ROLLBACK_LOG", tmp_path / "rollback.log")
    return fake_state


@pytest.fixture()
def state_empty(tmp_path, monkeypatch):
    """Patch the state file to an empty temp file."""
    fake_state = tmp_path / "enforcer_state.json"
    fake_state.write_text('{"blocked": {}}', encoding="utf-8")
    monkeypatch.setattr("src.rollback_api.STATE_FILE", fake_state)
    monkeypatch.setattr("src.rollback_api.ROLLBACK_LOG", tmp_path / "rollback.log")
    return fake_state


# ── GET /health ────────────────────────────────────────────────────────────────

class TestHealth:
    def test_returns_200(self, client, state_empty):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_status_ok(self, client, state_empty):
        data = client.get("/health").get_json()
        assert data["status"] == "ok"

    def test_blocked_count_zero(self, client, state_empty):
        data = client.get("/health").get_json()
        assert data["blocked_count"] == 0

    def test_blocked_count_reflects_state(self, client, state_with_blocked):
        data = client.get("/health").get_json()
        assert data["blocked_count"] == 2

    def test_dry_run_flag_present(self, client, state_empty):
        data = client.get("/health").get_json()
        assert "dry_run" in data


# ── GET /api/blocked ───────────────────────────────────────────────────────────

class TestGetBlocked:
    def test_returns_200(self, client, state_with_blocked):
        resp = client.get("/api/blocked")
        assert resp.status_code == 200

    def test_returns_correct_count(self, client, state_with_blocked):
        data = client.get("/api/blocked").get_json()
        assert data["count"] == 2

    def test_blocked_list_has_ip_field(self, client, state_with_blocked):
        data = client.get("/api/blocked").get_json()
        ips = [entry["ip"] for entry in data["blocked"]]
        assert "1.2.3.4" in ips
        assert "5.5.5.5" in ips

    def test_each_entry_has_required_fields(self, client, state_with_blocked):
        data = client.get("/api/blocked").get_json()
        for entry in data["blocked"]:
            assert "ip" in entry
            assert "risk_score" in entry
            assert "blocked_at" in entry
            assert "source" in entry
            assert "tags" in entry

    def test_sorted_by_risk_score_desc(self, client, state_with_blocked):
        data = client.get("/api/blocked?sort_by=risk_score&order=desc").get_json()
        scores = [e["risk_score"] for e in data["blocked"]]
        assert scores == sorted(scores, reverse=True)

    def test_empty_state_returns_zero(self, client, state_empty):
        data = client.get("/api/blocked").get_json()
        assert data["count"] == 0
        assert data["blocked"] == []


# ── GET /api/blocked/<ip> ──────────────────────────────────────────────────────

class TestGetBlockedIP:
    def test_found_returns_200(self, client, state_with_blocked):
        resp = client.get("/api/blocked/1.2.3.4")
        assert resp.status_code == 200

    def test_not_found_returns_404(self, client, state_with_blocked):
        resp = client.get("/api/blocked/9.9.9.9")
        assert resp.status_code == 404

    def test_invalid_ip_returns_400(self, client, state_with_blocked):
        resp = client.get("/api/blocked/not-an-ip")
        assert resp.status_code == 400

    def test_correct_metadata(self, client, state_with_blocked):
        data = client.get("/api/blocked/1.2.3.4").get_json()
        assert data["ip"] == "1.2.3.4"
        assert data["risk_score"] == 95
        assert data["source"] == "AbuseIPDB"


# ── POST /api/rollback/<ip> ────────────────────────────────────────────────────

class TestRollback:
    def test_rollback_existing_ip_returns_200(self, client, state_with_blocked):
        resp = client.post("/api/rollback/1.2.3.4",
                           json={"reason": "false positive", "analyst": "tester"})
        assert resp.status_code == 200

    def test_rollback_success_flag(self, client, state_with_blocked):
        data = client.post("/api/rollback/1.2.3.4", json={}).get_json()
        assert data["success"] is True

    def test_rollback_removes_from_state(self, client, state_with_blocked):
        client.post("/api/rollback/1.2.3.4", json={})
        # Check the state was cleaned
        resp = client.get("/api/blocked")
        ips = [e["ip"] for e in resp.get_json()["blocked"]]
        assert "1.2.3.4" not in ips

    def test_rollback_missing_ip_returns_404(self, client, state_with_blocked):
        resp = client.post("/api/rollback/9.9.9.9", json={})
        assert resp.status_code == 404

    def test_rollback_invalid_ip_returns_400(self, client, state_with_blocked):
        resp = client.post("/api/rollback/not-an-ip", json={})
        assert resp.status_code == 400

    def test_rollback_preserves_other_ips(self, client, state_with_blocked):
        client.post("/api/rollback/1.2.3.4", json={})
        data = client.get("/api/blocked").get_json()
        ips = [e["ip"] for e in data["blocked"]]
        assert "5.5.5.5" in ips

    def test_rollback_response_has_metadata(self, client, state_with_blocked):
        data = client.post(
            "/api/rollback/1.2.3.4",
            json={"reason": "test", "analyst": "alice"},
        ).get_json()
        assert data["ip"] == "1.2.3.4"
        assert "unblocked_at" in data
        assert data["reason"] == "test"
        assert data["analyst"] == "alice"

    def test_rollback_creates_audit_entry(self, client, state_with_blocked):
        client.post("/api/rollback/5.5.5.5",
                    json={"reason": "approved by SOC", "analyst": "bob"})
        # Check rollback log exists and contains the entry
        log_path = api_module.ROLLBACK_LOG
        assert log_path.exists()
        with open(log_path) as f:
            lines = [json.loads(l) for l in f if l.strip()]
        assert any(e["ip"] == "5.5.5.5" for e in lines)


# ── POST /api/rollback-all ────────────────────────────────────────────────────

class TestRollbackAll:
    def test_requires_confirm_field(self, client, state_with_blocked):
        resp = client.post("/api/rollback-all", json={})
        assert resp.status_code == 400

    def test_confirm_false_rejected(self, client, state_with_blocked):
        resp = client.post("/api/rollback-all", json={"confirm": False})
        assert resp.status_code == 400

    def test_confirm_true_succeeds(self, client, state_with_blocked):
        resp = client.post("/api/rollback-all", json={"confirm": True})
        assert resp.status_code == 200

    def test_all_ips_cleared_from_state(self, client, state_with_blocked):
        client.post("/api/rollback-all", json={"confirm": True})
        data = client.get("/api/blocked").get_json()
        assert data["count"] == 0

    def test_removed_count_in_response(self, client, state_with_blocked):
        data = client.post("/api/rollback-all",
                           json={"confirm": True}).get_json()
        assert data["removed_count"] == 2


# ── GET /api/audit ─────────────────────────────────────────────────────────────

class TestAudit:
    def test_returns_200(self, client, state_empty):
        resp = client.get("/api/audit")
        assert resp.status_code == 200

    def test_returns_count_field(self, client, state_empty):
        data = client.get("/api/audit").get_json()
        assert "count" in data
        assert "entries" in data

    def test_after_rollback_audit_has_entry(self, client, state_with_blocked):
        client.post("/api/rollback/1.2.3.4",
                    json={"reason": "audit test", "analyst": "x"})
        data = client.get("/api/audit").get_json()
        assert data["count"] >= 1


# ── GET /api/stats ─────────────────────────────────────────────────────────────

class TestStats:
    def test_returns_200(self, client, state_empty):
        resp = client.get("/api/stats")
        assert resp.status_code == 200

    def test_empty_stats(self, client, state_empty):
        data = client.get("/api/stats").get_json()
        assert data["total_blocked"] == 0
        assert data["by_source"] == {}
        assert data["by_risk_tier"]["critical"] == 0

    def test_populated_stats(self, client, state_with_blocked):
        data = client.get("/api/stats").get_json()
        assert data["total_blocked"] == 2
        assert data["by_source"]["AbuseIPDB"] == 1
        assert data["by_source"]["EmergingThreats_IPs"] == 1
        assert data["by_risk_tier"]["critical"] == 2
        assert data["by_risk_tier"]["high"] == 0


# ── API Key Auth ───────────────────────────────────────────────────────────────

class TestAPIKeyAuth:
    def test_no_key_configured_allows_all(self, client, monkeypatch):
        monkeypatch.setattr("src.rollback_api.ROLLBACK_API_KEY", "")
        resp = client.get("/api/blocked")
        assert resp.status_code == 200

    def test_missing_header_returns_401(self, client, monkeypatch):
        monkeypatch.setattr("src.rollback_api.ROLLBACK_API_KEY", "secret")
        resp = client.get("/api/blocked")
        assert resp.status_code == 401

    def test_invalid_header_returns_403(self, client, monkeypatch):
        monkeypatch.setattr("src.rollback_api.ROLLBACK_API_KEY", "secret")
        resp = client.get("/api/blocked", headers={"X-API-Key": "wrong"})
        assert resp.status_code == 403

    def test_valid_header_returns_200(self, client, monkeypatch, state_with_blocked):
        monkeypatch.setattr("src.rollback_api.ROLLBACK_API_KEY", "secret")
        resp = client.get("/api/blocked", headers={"X-API-Key": "secret"})
        assert resp.status_code == 200
