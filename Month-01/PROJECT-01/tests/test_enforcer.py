"""Tests for the Policy Enforcer Daemon (Week 3).

All tests are fully local — no real firewall calls, no network, no Elasticsearch.
Firewall commands are mocked so tests run safely on any machine without admin rights.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── Helpers to import enforcer cleanly ────────────────────────────────────────
import sys, os
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.enforcer import (
    FIREWALL_PREFIX,
    STATE_FILE,
    add_firewall_block,
    audit,
    load_state,
    query_high_risk_ips,
    remove_firewall_block,
    rule_name,
    run_enforcement_cycle,
    save_state,
    unblock_all_tip_rules,
)


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture()
def tmp_state(tmp_path, monkeypatch):
    """Redirect STATE_FILE to a temp path so tests don't touch the real file."""
    fake_state = tmp_path / "enforcer_state.json"
    monkeypatch.setattr("src.enforcer.STATE_FILE", fake_state)
    return fake_state


@pytest.fixture()
def mock_es():
    """A mock Elasticsearch client that returns a canned response."""
    es = MagicMock()
    es.ping.return_value = True
    es.search.return_value = {
        "hits": {
            "hits": [
                {
                    "_source": {
                        "indicator": "1.2.3.4",
                        "risk_score": 95,
                        "source": "AbuseIPDB",
                        "tags": ["malware", "ssh-brute-force"],
                    }
                },
                {
                    "_source": {
                        "indicator": "10.0.0.1",
                        "risk_score": 90,
                        "source": "EmergingThreats_IPs",
                        "tags": [],
                    }
                },
            ]
        }
    }
    return es


# ── rule_name ─────────────────────────────────────────────────────────────────

class TestRuleName:
    def test_prefix_is_correct(self):
        assert rule_name("1.2.3.4") == "TIP-BLOCK-1.2.3.4"

    def test_special_ip(self):
        assert rule_name("192.168.0.1") == "TIP-BLOCK-192.168.0.1"

    def test_prefix_constant(self):
        ip = "8.8.8.8"
        assert rule_name(ip).startswith(FIREWALL_PREFIX)


# ── State file ─────────────────────────────────────────────────────────────────

class TestState:
    def test_load_missing_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr("src.enforcer.STATE_FILE", tmp_path / "missing.json")
        state = load_state()
        assert state == {"blocked": {}}

    def test_save_and_load_roundtrip(self, tmp_state):
        original = {
            "blocked": {
                "5.5.5.5": {
                    "blocked_at": "2026-05-25T10:00:00+00:00",
                    "risk_score": 92,
                    "source": "AbuseIPDB",
                    "tags": ["phishing"],
                    "rule_name": "TIP-BLOCK-5.5.5.5",
                }
            }
        }
        save_state(original)
        loaded = load_state()
        assert loaded == original

    def test_save_creates_file(self, tmp_state):
        save_state({"blocked": {}})
        assert tmp_state.exists()

    def test_corrupt_json_returns_empty(self, tmp_state):
        tmp_state.write_text("not json!!!", encoding="utf-8")
        state = load_state()
        assert state == {"blocked": {}}


# ── Firewall operations (mocked) ───────────────────────────────────────────────

class TestFirewallOperations:
    def test_add_block_dry_run_returns_true(self):
        result = add_firewall_block("1.2.3.4", dry_run=True)
        assert result is True

    def test_remove_block_dry_run_returns_true(self):
        result = remove_firewall_block("1.2.3.4", dry_run=True)
        assert result is True

    def test_add_block_calls_netsh(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            result = add_firewall_block("192.168.1.1", dry_run=False)
            assert result is True
            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            assert "netsh" in cmd
            assert "TIP-BLOCK-192.168.1.1" in " ".join(cmd)

    def test_remove_block_calls_netsh(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            result = remove_firewall_block("192.168.1.1", dry_run=False)
            assert result is True
            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            assert "delete" in cmd

    def test_add_block_returns_false_on_nonzero(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Access denied")
            result = add_firewall_block("1.1.1.1", dry_run=False)
            assert result is False

    def test_unblock_all_dry_run(self):
        result = unblock_all_tip_rules(dry_run=True)
        assert result == 0

    def test_unblock_all_calls_netsh_wildcard(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="1 rule(s) deleted.", stderr="")
            unblock_all_tip_rules(dry_run=False)
            cmd = mock_run.call_args[0][0]
            assert any("TIP-BLOCK-*" in part or "TIP-BLOCK-" in part for part in cmd)


# ── Elasticsearch query ────────────────────────────────────────────────────────

class TestQueryHighRiskIPs:
    def test_returns_list(self, mock_es):
        results = query_high_risk_ips(mock_es, threshold=90)
        assert isinstance(results, list)

    def test_correct_count(self, mock_es):
        results = query_high_risk_ips(mock_es, threshold=90)
        assert len(results) == 2

    def test_correct_fields(self, mock_es):
        results = query_high_risk_ips(mock_es, threshold=90)
        first = results[0]
        assert "indicator" in first
        assert "risk_score" in first
        assert "source" in first
        assert "tags" in first

    def test_returns_empty_on_exception(self):
        bad_es = MagicMock()
        bad_es.search.side_effect = Exception("Connection refused")
        results = query_high_risk_ips(bad_es, threshold=90)
        assert results == []

    def test_empty_hits(self):
        es = MagicMock()
        es.search.return_value = {"hits": {"hits": []}}
        results = query_high_risk_ips(es)
        assert results == []


# ── Enforcement cycle ──────────────────────────────────────────────────────────

class TestEnforcementCycle:
    def test_dry_run_cycle_adds_to_state(self, mock_es, tmp_state):
        state = {"blocked": {}}
        newly, already = run_enforcement_cycle(mock_es, state, dry_run=True)
        assert newly == 2
        assert already == 0
        assert "1.2.3.4" in state["blocked"]
        assert "10.0.0.1" in state["blocked"]

    def test_already_blocked_not_double_counted(self, mock_es, tmp_state):
        state = {"blocked": {"1.2.3.4": {"blocked_at": "2026-01-01T00:00:00+00:00"}}}
        newly, already = run_enforcement_cycle(mock_es, state, dry_run=True)
        assert newly == 1    # only 10.0.0.1 is new
        assert already == 1  # 1.2.3.4 was already blocked

    def test_blocked_entry_has_metadata(self, mock_es, tmp_state):
        state = {"blocked": {}}
        run_enforcement_cycle(mock_es, state, dry_run=True)
        entry = state["blocked"]["1.2.3.4"]
        assert "blocked_at" in entry
        assert entry["risk_score"] == 95
        assert entry["source"] == "AbuseIPDB"
        assert entry["rule_name"] == "TIP-BLOCK-1.2.3.4"

    def test_empty_feed_returns_zeros(self, tmp_state):
        es = MagicMock()
        es.search.return_value = {"hits": {"hits": []}}
        state = {"blocked": {}}
        newly, already = run_enforcement_cycle(es, state, dry_run=True)
        assert newly == 0
        assert already == 0
