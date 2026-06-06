"""Rollback REST API — Week 4
=================================
Flask API that allows SOC analysts to view and undo firewall blocks
created by the Policy Enforcer Daemon.

Endpoints:
    GET  /health                → System health + blocked count
    GET  /api/blocked           → All currently blocked IPs (with metadata)
    GET  /api/blocked/<ip>      → Details for a single blocked IP
    POST /api/rollback/<ip>     → Unblock an IP (removes firewall rule)
    GET  /api/audit             → Full audit trail from the log file
    POST /api/rollback-all      → Remove ALL TIP firewall rules (dangerous!)

Usage:
    python -m src.rollback_api            # Starts on http://localhost:5050
    python -m src.rollback_api --dry-run  # Simulate unblocks only

Environment variables (in .env):
    ROLLBACK_API_PORT=5050  (default)
    ROLLBACK_API_HOST=127.0.0.1  (default — LAN only)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS
from .utils import is_valid_any_ip

load_dotenv()

# ── Config ─────────────────────────────────────────────────────────────────────
API_HOST    = os.getenv("ROLLBACK_API_HOST", "127.0.0.1")
API_PORT    = int(os.getenv("ROLLBACK_API_PORT", "5050"))
# If set, all /api/* endpoints require the header:  X-API-Key: <ROLLBACK_API_KEY>
# Leave empty / unset to run without authentication.
ROLLBACK_API_KEY = os.getenv("ROLLBACK_API_KEY", "")

_PROJECT_ROOT   = Path(__file__).resolve().parents[1]
STATE_FILE      = _PROJECT_ROOT / "enforcer_state.json"
LOG_FILE        = _PROJECT_ROOT / "logs" / "enforcer.log"
ROLLBACK_LOG    = _PROJECT_ROOT / "logs" / "rollback.log"
FIREWALL_PREFIX = "TIP-BLOCK-"

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("rollback-api")

# ── Flask app ──────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)  # Allow browser requests from Kibana or any local frontend

# Global dry-run flag (set at startup)
_DRY_RUN: bool = False


# ── Authentication ──────────────────────────────────────────────────────────────────

def _require_api_key():
    """Return a JSON error response if API key auth is configured and fails.

    If ``ROLLBACK_API_KEY`` is set in the environment, every protected endpoint
    requires the caller to send the header::

        X-API-Key: <your_key>

    Returns:
        ``None`` if the request is authorised (or no key is configured).
        A ``(response, status_code)`` tuple to return immediately on failure.
    """
    if not ROLLBACK_API_KEY:
        return None  # Auth not configured — allow all requests
    provided = request.headers.get("X-API-Key", "")
    if not provided:
        return jsonify({"error": "Missing X-API-Key header",
                        "hint": "Set ROLLBACK_API_KEY in .env and pass X-API-Key header."}), 401
    if provided != ROLLBACK_API_KEY:
        return jsonify({"error": "Invalid API key"}), 403
    return None


# ── State helpers ──────────────────────────────────────────────────────────────

def _load_state() -> dict:
    """Load the enforcer state file from disk."""
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning("Could not read state file: %s", e)
    return {"blocked": {}}


def _save_state(state: dict) -> None:
    """Persist the enforcer state file to disk."""
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


def _append_rollback_log(ip: str, reason: str, analyst: str, dry_run: bool) -> None:
    """Append an entry to the rollback audit log."""
    ROLLBACK_LOG.parent.mkdir(exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action":    "ROLLBACK" if not dry_run else "ROLLBACK_SIMULATED",
        "ip":        ip,
        "reason":    reason or "no reason provided",
        "analyst":   analyst or "anonymous",
    }
    with open(ROLLBACK_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


# ── Firewall helpers ────────────────────────────────────────────────────────────────────────────

def _remove_firewall_rule(ip: str) -> bool:
    """Remove both inbound and outbound TIP firewall block rules for the given IP.

    The primary inbound rule (``TIP-BLOCK-<ip>``) must succeed for this
    function to return True.  The outbound rule (``TIP-BLOCK-<ip>-OUT``) is
    removed as a best-effort — if it doesn't exist (legacy block), we don't fail.
    """
    base_name = f"{FIREWALL_PREFIX}{ip}"

    # Primary inbound rule — must succeed
    cmd_in = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={base_name}"]
    try:
        result = subprocess.run(cmd_in, capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            logger.error("Error removing inbound firewall rule for %s: %s",
                         ip, result.stderr.strip())
            return False
    except Exception as exc:
        logger.error("Error removing firewall rule for %s: %s", ip, exc)
        return False

    # Outbound rule — best-effort (may not exist for older blocks)
    cmd_out = ["netsh", "advfirewall", "firewall", "delete", "rule",
               f"name={base_name}-OUT"]
    try:
        subprocess.run(cmd_out, capture_output=True, text=True, timeout=15)
    except Exception:
        pass  # Best-effort; failure here is non-fatal

    return True


# ── Validators ──────────────────────────────────────────────────────────────────────────
# Delegates to the shared utility in src/utils.py — no duplicate regex.
# is_valid_any_ip accepts both IPv4 and IPv6 so SOC analysts can roll back
# IPv6 threat indicators as well.
_valid_ip = is_valid_any_ip


# ── API Routes ─────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    """Health check — returns service status and blocked IP count."""
    state = _load_state()
    blocked = state.get("blocked", {})
    return jsonify({
        "status":         "ok",
        "service":        "TIP Rollback API",
        "version":        "1.0.0",
        "dry_run":        _DRY_RUN,
        "blocked_count":  len(blocked),
        "state_file":     str(STATE_FILE),
        "timestamp":      datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/blocked", methods=["GET"])
def get_blocked():
    """Return all currently blocked IPs with metadata.

    Query params:
        sort_by: field to sort by (risk_score, blocked_at, source) — default: risk_score
        order:   asc or desc — default: desc
    """
    auth_error = _require_api_key()
    if auth_error:
        return auth_error

    state = _load_state()
    blocked = state.get("blocked", {})

    sort_by = request.args.get("sort_by", "risk_score")
    order   = request.args.get("order", "desc")
    reverse = order.lower() != "asc"

    results = []
    for ip, meta in blocked.items():
        results.append({
            "ip":         ip,
            "blocked_at": meta.get("blocked_at"),
            "risk_score": meta.get("risk_score", 0),
            "source":     meta.get("source", "unknown"),
            "tags":       meta.get("tags", []),
            "rule_name":  meta.get("rule_name", f"{FIREWALL_PREFIX}{ip}"),
        })

    # Sort
    valid_sorts = {"risk_score", "blocked_at", "source", "ip"}
    if sort_by in valid_sorts:
        results.sort(key=lambda x: (x.get(sort_by) or ""), reverse=reverse)

    return jsonify({
        "count":   len(results),
        "blocked": results,
    })


@app.route("/api/blocked/<ip>", methods=["GET"])
def get_blocked_ip(ip: str):
    """Return metadata for a single blocked IP."""
    auth_error = _require_api_key()
    if auth_error:
        return auth_error

    if not _valid_ip(ip):
        return jsonify({"error": "Invalid IP address format"}), 400

    state = _load_state()
    blocked = state.get("blocked", {})

    if ip not in blocked:
        return jsonify({"error": f"{ip} is not currently blocked"}), 404

    meta = blocked[ip]
    return jsonify({
        "ip":         ip,
        "blocked_at": meta.get("blocked_at"),
        "risk_score": meta.get("risk_score", 0),
        "source":     meta.get("source", "unknown"),
        "tags":       meta.get("tags", []),
        "rule_name":  meta.get("rule_name", f"{FIREWALL_PREFIX}{ip}"),
    })


@app.route("/api/rollback/<ip>", methods=["POST"])
def rollback_ip(ip: str):
    """Unblock a single IP — removes the Windows Firewall rule.

    Request body (JSON, optional):
        {
          "reason":  "False positive confirmed",
          "analyst": "john.doe"
        }
    """
    auth_error = _require_api_key()
    if auth_error:
        return auth_error

    if not _valid_ip(ip):
        return jsonify({"error": "Invalid IP address format"}), 400

    state  = _load_state()
    blocked = state.get("blocked", {})

    if ip not in blocked:
        return jsonify({
            "error":   f"{ip} is not in the blocked list",
            "message": "It may have already been unblocked or was never blocked by TIP",
        }), 404

    # Parse optional body
    body    = request.get_json(silent=True) or {}
    reason  = body.get("reason", "manual rollback by analyst")
    analyst = body.get("analyst", "anonymous")

    # Remove firewall rule
    if _DRY_RUN:
        logger.info("[DRY-RUN] Would remove firewall rule for %s", ip)
        success = True
    else:
        success = _remove_firewall_rule(ip)

    if not success:
        return jsonify({
            "error":   "Failed to remove firewall rule",
            "ip":      ip,
            "message": "The rule may not exist in Windows Firewall. State has been cleaned up.",
        }), 500

    # Remove from state
    meta = blocked.pop(ip, {})
    _save_state(state)

    # Audit log
    _append_rollback_log(ip, reason, analyst, dry_run=_DRY_RUN)

    logger.info("ROLLBACK | IP=%-18s | reason=%s | analyst=%s | dry_run=%s",
                ip, reason, analyst, _DRY_RUN)

    return jsonify({
        "success":       True,
        "ip":            ip,
        "unblocked_at":  datetime.now(timezone.utc).isoformat(),
        "reason":        reason,
        "analyst":       analyst,
        "was_blocked_at": meta.get("blocked_at"),
        "risk_score":    meta.get("risk_score"),
        "dry_run":       _DRY_RUN,
    })


@app.route("/api/rollback-all", methods=["POST"])
def rollback_all():
    """Remove ALL TIP firewall rules. Use with caution.

    Request body (JSON):
        {
          "confirm":  true,         ← required safety field
          "reason":   "...",
          "analyst":  "..."
        }
    """
    auth_error = _require_api_key()
    if auth_error:
        return auth_error

    body = request.get_json(silent=True) or {}

    if not body.get("confirm"):
        return jsonify({
            "error": "Must include {'confirm': true} in request body to execute rollback-all.",
        }), 400

    reason  = body.get("reason", "bulk rollback by analyst")
    analyst = body.get("analyst", "anonymous")

    state   = _load_state()
    blocked = state.get("blocked", {})
    count   = len(blocked)

    if not _DRY_RUN:
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={FIREWALL_PREFIX}*"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                # Firewall command failed — do NOT clear state so it stays consistent
                err = result.stderr.strip() or result.stdout.strip()
                logger.error("Firewall rollback-all failed: %s", err)
                return jsonify({"error": "Firewall command failed", "detail": err}), 500
        except Exception as exc:
            logger.error("Error during rollback-all: %s", exc)
            return jsonify({"error": "Firewall command failed", "detail": str(exc)}), 500

    # Log each IP before clearing
    for ip in list(blocked.keys()):
        _append_rollback_log(ip, reason, analyst, dry_run=_DRY_RUN)

    state["blocked"] = {}
    _save_state(state)

    logger.info("ROLLBACK-ALL | removed %d rules | reason=%s | analyst=%s | dry_run=%s",
                count, reason, analyst, _DRY_RUN)

    return jsonify({
        "success":      True,
        "removed_count": count,
        "reason":       reason,
        "analyst":      analyst,
        "dry_run":      _DRY_RUN,
        "timestamp":    datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/audit", methods=["GET"])
def get_audit():
    """Return the audit trail from both enforcer.log and rollback.log.

    Query params:
        limit: max number of entries to return (default: 200)
        action: filter by action type (BLOCKED, ROLLBACK)
    """
    auth_error = _require_api_key()
    if auth_error:
        return auth_error

    limit  = int(request.args.get("limit", 200))
    action = request.args.get("action", "").upper()

    entries = []

    # Parse rollback.log (structured JSON lines)
    if ROLLBACK_LOG.exists():
        try:
            with open(ROLLBACK_LOG, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if action and entry.get("action", "").upper() != action:
                            continue
                        entries.append(entry)
                    except json.JSONDecodeError:
                        pass
        except IOError:
            pass

    # Parse enforcer.log (plain text) for BLOCKED lines
    if LOG_FILE.exists():
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if "BLOCKED" in line and ("DRY-RUN" not in line or not action):
                        if action and action != "BLOCKED":
                            continue
                        entries.append({
                            "action":    "BLOCKED",
                            "raw_log":   line,
                            "source":    "enforcer.log",
                        })
        except IOError:
            pass

    # Sort by timestamp descending where possible, return latest N
    entries.reverse()
    entries = entries[:limit]

    return jsonify({
        "count":   len(entries),
        "limit":   limit,
        "entries": entries,
    })


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Return aggregate statistics about currently blocked IPs.

    Response:
        {
          "total_blocked": 12,
          "by_source": {"AbuseIPDB": 8, "EmergingThreats_IPs": 4},
          "by_risk_tier": {"critical": 10, "high": 2, "medium": 0, "low": 0},
          "dry_run": false,
          "timestamp": "..."
        }
    """
    auth_error = _require_api_key()
    if auth_error:
        return auth_error

    state = _load_state()
    blocked = state.get("blocked", {})

    by_source: dict = {}
    by_risk_tier = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for _ip, meta in blocked.items():
        # Count by source
        source = meta.get("source", "unknown")
        by_source[source] = by_source.get(source, 0) + 1

        # Classify by risk tier
        score = meta.get("risk_score", 0) or 0
        if score >= 90:
            by_risk_tier["critical"] += 1
        elif score >= 75:
            by_risk_tier["high"] += 1
        elif score >= 50:
            by_risk_tier["medium"] += 1
        else:
            by_risk_tier["low"] += 1

    return jsonify({
        "total_blocked": len(blocked),
        "by_source":     by_source,
        "by_risk_tier":  by_risk_tier,
        "dry_run":       _DRY_RUN,
        "timestamp":     datetime.now(timezone.utc).isoformat(),
    })


# ── Main entry ─────────────────────────────────────────────────────────────────

def main() -> None:
    global _DRY_RUN

    parser = argparse.ArgumentParser(
        description="TIP Rollback API — Flask service for SOC analysts to manage firewall blocks."
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Simulate rollbacks without actually removing firewall rules.")
    parser.add_argument("--host", default=API_HOST,
                        help=f"Host to bind to (default: {API_HOST}).")
    parser.add_argument("--port", type=int, default=API_PORT,
                        help=f"Port to listen on (default: {API_PORT}).")
    args = parser.parse_args()

    _DRY_RUN = args.dry_run

    dry_label = " [DRY-RUN MODE]" if _DRY_RUN else ""
    auth_mode = "ENABLED (X-API-Key required)" if ROLLBACK_API_KEY else "DISABLED (Open to localhost)"
    
    print()
    print("=" * 65)
    print("  TIP Rollback API — Week 4")
    print(f"  Listening : http://{args.host}:{args.port}")
    print(f"  State     : {STATE_FILE}")
    print(f"  Mode      : {'DRY-RUN — no real firewall changes' if _DRY_RUN else 'LIVE'}")
    print(f"  Auth      : {auth_mode}")
    print()
    print("  Endpoints:")
    print("    GET  /health")
    print("    GET  /api/blocked")
    print("    GET  /api/blocked/<ip>")
    print("    GET  /api/stats")
    print("    POST /api/rollback/<ip>")
    print("    POST /api/rollback-all")
    print("    GET  /api/audit")
    print("=" * 65)
    print()

    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
