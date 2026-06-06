"""Policy Enforcer Daemon — Week 3
===================================
Automatically blocks high-risk threat indicators using Windows Firewall.

How it works:
  1. Queries Elasticsearch every POLL_INTERVAL seconds for IPs with
     risk_score >= BLOCK_THRESHOLD.
  2. For each IP not yet blocked → adds a Windows Firewall inbound block rule.
  3. Writes every action to logs/enforcer.log (append-only audit trail).
  4. Tracks current blocks in enforcer_state.json so it never double-blocks.

Usage:
    python -m src.enforcer             # Run daemon forever (requires Admin)
    python -m src.enforcer --dry-run   # Simulate only, no real firewall changes
    python -m src.enforcer --once      # Run one cycle and exit (good for testing)
    python -m src.enforcer --unblock-all  # Remove ALL TIP firewall rules

Firewall commands (Windows netsh):
    Block:   netsh advfirewall firewall add rule name="TIP-BLOCK-<ip>" ...
    Remove:  netsh advfirewall firewall delete rule name="TIP-BLOCK-<ip>"
    List:    netsh advfirewall firewall show rule name=all

⚠️  Requires PowerShell / CMD run as Administrator to modify firewall rules.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

# ── Configuration ──────────────────────────────────────────────────────────────
ELASTICSEARCH_URI   = os.getenv("ELASTICSEARCH_URI", "http://localhost:9200")
ES_USER             = os.getenv("ES_USER", "elastic")
ELASTIC_PASSWORD    = os.getenv("ELASTIC_PASSWORD", "")
BLOCK_THRESHOLD     = int(os.getenv("ENFORCER_THRESHOLD", "90"))   # risk_score ≥ this
POLL_INTERVAL       = int(os.getenv("ENFORCER_INTERVAL", "60"))    # seconds between scans
MAX_INDICATORS      = int(os.getenv("ENFORCER_MAX_IPS", "1000"))   # max IPs per query

# ── Paths ──────────────────────────────────────────────────────────────────────
_PROJECT_ROOT  = Path(__file__).resolve().parents[1]
STATE_FILE     = _PROJECT_ROOT / "enforcer_state.json"
LOG_DIR        = _PROJECT_ROOT / "logs"
LOG_FILE       = LOG_DIR / "enforcer.log"
FIREWALL_PREFIX = "TIP-BLOCK-"

# ── Logging ────────────────────────────────────────────────────────────────────
LOG_DIR.mkdir(exist_ok=True)

_fmt = "%(asctime)s  %(levelname)-8s  %(message)s"
_datefmt = "%Y-%m-%d %H:%M:%S"

logging.basicConfig(
    level=logging.INFO,
    format=_fmt,
    datefmt=_datefmt,
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
    ],
)
logger = logging.getLogger("enforcer")


# ── State management ───────────────────────────────────────────────────────────

def load_state() -> dict:
    """Load the enforcer state from disk.

    State shape:
    {
        "blocked": {
            "1.2.3.4": {
                "blocked_at": "2026-05-25T10:00:00+00:00",
                "risk_score": 95,
                "source": "AbuseIPDB",
                "tags": ["malware"],
                "rule_name": "TIP-BLOCK-1.2.3.4"
            }
        }
    }
    """
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning("Could not read state file (%s) — starting fresh.", e)
    return {"blocked": {}}


def save_state(state: dict) -> None:
    """Persist the enforcer state to disk."""
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


# ── Audit log ──────────────────────────────────────────────────────────────────

def audit(action: str, ip: str, risk_score: int, source: str,
          tags: list, reason: str = "", dry_run: bool = False) -> None:
    """Write a structured audit entry to the log file."""
    prefix = "[DRY-RUN] " if dry_run else ""
    tag_str = ", ".join(tags) if tags else "none"
    logger.info(
        "%s%s | IP=%-18s | risk=%3d | source=%-15s | tags=[%s]%s",
        prefix, action, ip, risk_score, source, tag_str,
        f" | reason={reason}" if reason else "",
    )


# ── Elasticsearch query ────────────────────────────────────────────────────────

def get_es_client():
    """Return an authenticated Elasticsearch client or None on failure."""
    try:
        from elasticsearch import Elasticsearch
        kwargs: dict = {"request_timeout": 15}
        if ELASTIC_PASSWORD:
            kwargs["basic_auth"] = (ES_USER, ELASTIC_PASSWORD)
        es = Elasticsearch(ELASTICSEARCH_URI, **kwargs)
        if not es.ping():
            logger.error("Elasticsearch ping failed at %s", ELASTICSEARCH_URI)
            return None
        return es
    except ImportError:
        logger.error("elasticsearch package not installed. Run: pip install elasticsearch")
        return None
    except Exception as exc:
        logger.error("Cannot connect to Elasticsearch: %s", exc)
        return None


def query_high_risk_ips(es, threshold: int = BLOCK_THRESHOLD) -> list[dict]:
    """Query Elasticsearch for IPs with risk_score >= threshold.

    Returns a list of dicts with keys: indicator, risk_score, source, tags.
    """
    try:
        resp = es.search(
            index="indicators",
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"type": "ip"}},
                            {"range": {"risk_score": {"gte": threshold}}},
                        ]
                    }
                },
                "sort": [{"risk_score": "desc"}],
                "size": MAX_INDICATORS,
                "_source": ["indicator", "risk_score", "source", "tags"],
            },
        )
        hits = resp.get("hits", {}).get("hits", [])
        results = []
        for hit in hits:
            src = hit.get("_source", {})
            results.append({
                "indicator": src.get("indicator", ""),
                "risk_score": src.get("risk_score", 0),
                "source":     src.get("source", "unknown"),
                "tags":       src.get("tags", []) or [],
            })
        return results
    except Exception as exc:
        logger.error("Elasticsearch query failed: %s", exc)
        return []


# ── Windows Firewall management ────────────────────────────────────────────────

def rule_name(ip: str) -> str:
    """Generate the base firewall rule name for an IP.

    The inbound rule uses this name directly; the outbound rule appends ``-OUT``.
    Both rules are created/removed together to provide bidirectional blocking.
    """
    return f"{FIREWALL_PREFIX}{ip}"


def firewall_rule_exists(ip: str) -> bool:
    """Check if the inbound TIP block rule exists for this IP in Windows Firewall."""
    name = rule_name(ip)
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"],
            capture_output=True, text=True, timeout=10,
        )
        return "No rules match the specified criteria" not in result.stdout
    except Exception:
        return False


def _run_firewall_cmd(cmd: list, ip: str, dry_run: bool, description: str) -> bool:
    """Execute a single netsh firewall command (or simulate in dry_run mode).

    Args:
        cmd:         Full netsh command list.
        ip:          The IP address being acted upon (for logging).
        dry_run:     If True, log the command but do not execute it.
        description: Short label for log messages (e.g. "add IN rule").

    Returns:
        True on success (or dry_run), False on any failure.
    """
    if dry_run:
        logger.info("[DRY-RUN] Would run: %s", " ".join(cmd))
        return True

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            return True
        logger.error("Firewall %s failed for %s: %s",
                     description, ip, result.stderr.strip())
        return False
    except subprocess.TimeoutExpired:
        logger.error("Firewall command timed out for IP %s (%s)", ip, description)
        return False
    except FileNotFoundError:
        logger.error("'netsh' not found — are you on Windows?")
        return False
    except Exception as exc:
        logger.error("Unexpected error during firewall %s for %s: %s",
                     description, ip, exc)
        return False


def add_firewall_block(ip: str, dry_run: bool = False) -> bool:
    """Add **inbound AND outbound** block rules for the given IP in Windows Firewall.

    Two rules are created:
    - ``TIP-BLOCK-<ip>``     — blocks inbound traffic FROM this IP.
    - ``TIP-BLOCK-<ip>-OUT`` — blocks outbound traffic TO this IP
      (prevents infected internal hosts reaching the C2 address).

    Args:
        ip:      The IP address to block.
        dry_run: If True, only logs the commands — no real firewall changes.

    Returns:
        True if **both** rules were successfully applied (or simulated).
    """
    base = rule_name(ip)
    description = f"Auto-blocked by TIP enforcer (risk >= {BLOCK_THRESHOLD})"

    all_ok = True
    for direction, name in [("in", base), ("out", f"{base}-OUT")]:
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={name}",
            "protocol=any",
            f"dir={direction}",
            "action=block",
            f"remoteip={ip}",
            "enable=yes",
            f"description={description}",
        ]
        if not _run_firewall_cmd(cmd, ip, dry_run, f"add {direction} rule"):
            all_ok = False

    return all_ok


def remove_firewall_block(ip: str, dry_run: bool = False) -> bool:
    """Remove both inbound and outbound TIP block rules for the given IP.

    Removes ``TIP-BLOCK-<ip>`` and ``TIP-BLOCK-<ip>-OUT``.  If the -OUT rule
    does not exist (e.g. legacy blocks created before this feature), the
    operation still returns True as long as the primary inbound rule was removed.

    Args:
        ip:      The IP address to unblock.
        dry_run: If True, only logs — no real firewall changes.

    Returns:
        True if the primary inbound rule was successfully removed (or simulated).
    """
    base = rule_name(ip)

    # Primary inbound rule — failure here is a real error
    cmd_in = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={base}",
    ]
    primary_ok = _run_firewall_cmd(cmd_in, ip, dry_run, "remove IN rule")

    # Outbound rule — best-effort; may not exist for legacy blocks
    cmd_out = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={base}-OUT",
    ]
    _run_firewall_cmd(cmd_out, ip, dry_run, "remove OUT rule")

    return primary_ok


def unblock_all_tip_rules(dry_run: bool = False) -> bool:
    """Remove ALL Windows Firewall rules created by TIP (name starts with TIP-BLOCK-).

    Returns:
        True if the command succeeded (or dry_run), False on failure.
    """
    cmd = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={FIREWALL_PREFIX}*",
    ]

    if dry_run:
        logger.info("[DRY-RUN] Would remove all TIP-BLOCK-* firewall rules.")
        return True

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            logger.info("Removed all TIP firewall rules. Output: %s", result.stdout.strip())
            return True
        else:
            logger.warning("Unblock-all returned non-zero: %s", result.stderr.strip())
            return False
    except Exception as exc:
        logger.error("Error during unblock-all: %s", exc)
        return False


# ── Admin check ────────────────────────────────────────────────────────────────

def is_admin() -> bool:
    """Return True if the current process has administrator privileges on Windows."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ── Core enforcement cycle ─────────────────────────────────────────────────────

def run_enforcement_cycle(es, state: dict, dry_run: bool = False) -> tuple[int, int]:
    """Execute one enforcement cycle.

    Args:
        es: Elasticsearch client.
        state: Mutable state dict (will be modified in place).
        dry_run: If True, simulate only.

    Returns:
        Tuple of (newly_blocked_count, already_blocked_count).
    """
    high_risk = query_high_risk_ips(es, BLOCK_THRESHOLD)
    if not high_risk:
        logger.info("No high-risk IPs found (threshold=%d).", BLOCK_THRESHOLD)
        return 0, 0

    logger.info("Found %d high-risk IPs (risk_score >= %d).", len(high_risk), BLOCK_THRESHOLD)

    newly_blocked = 0
    already_blocked = 0
    blocked_map: dict = state.setdefault("blocked", {})

    for entry in high_risk:
        ip         = entry["indicator"]
        risk_score = entry["risk_score"]
        source     = entry["source"]
        tags       = entry["tags"]

        if not ip:
            continue

        # Already in our state? Skip.
        if ip in blocked_map:
            already_blocked += 1
            continue

        # Add firewall rule
        success = add_firewall_block(ip, dry_run=dry_run)

        if success:
            now = datetime.now(timezone.utc).isoformat()
            blocked_map[ip] = {
                "blocked_at": now,
                "risk_score": risk_score,
                "source":     source,
                "tags":       tags,
                "rule_name":  rule_name(ip),
            }
            audit("BLOCKED", ip, risk_score, source, tags, dry_run=dry_run)
            newly_blocked += 1

    return newly_blocked, already_blocked


# ── Main entry point ──────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="TIP Policy Enforcer — auto-blocks high-risk IPs via Windows Firewall."
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Simulate enforcement without making real firewall changes.",
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Run a single enforcement cycle and exit.",
    )
    parser.add_argument(
        "--threshold", type=int, default=BLOCK_THRESHOLD,
        help=f"Risk score threshold for blocking (default: {BLOCK_THRESHOLD}).",
    )
    parser.add_argument(
        "--interval", type=int, default=POLL_INTERVAL,
        help=f"Seconds between enforcement cycles (default: {POLL_INTERVAL}).",
    )
    parser.add_argument(
        "--unblock-all", action="store_true",
        help="Remove ALL TIP firewall rules and clear state, then exit.",
    )
    args = parser.parse_args()

    # ── Banner
    dry_label = " [DRY-RUN MODE — no real firewall changes]" if args.dry_run else ""
    print()
    print("=" * 65)
    print("  TIP Policy Enforcer Daemon — Week 3")
    print(f"  Threshold : risk_score >= {args.threshold}")
    print(f"  Interval  : every {args.interval}s")
    print(f"  State file: {STATE_FILE}")
    print(f"  Audit log : {LOG_FILE}")
    print(f"  Mode      : {'SINGLE CYCLE' if args.once else 'DAEMON'}{dry_label}")
    print("=" * 65)
    print()

    # ── Admin check (warn but don't block in dry-run mode)
    if not args.dry_run and not is_admin():
        print("⚠️  WARNING: Not running as Administrator.")
        print("   Windows Firewall rules require elevated privileges.")
        print("   Run PowerShell as Administrator, or use --dry-run to simulate.")
        print()
        if not args.once:
            sys.exit(1)

    # ── Unblock-all mode
    if args.unblock_all:
        state = load_state()
        # Count from state (reliable) rather than parsing netsh output text
        rule_count = len(state.get("blocked", {}))
        success = unblock_all_tip_rules(dry_run=args.dry_run)
        if success or args.dry_run:
            state["blocked"] = {}
            save_state(state)
            logger.info("Cleared %d TIP firewall rules. State reset.", rule_count)
        else:
            logger.error("unblock-all firewall command failed — state NOT cleared.")
        return

    # ── Connect to Elasticsearch
    es = get_es_client()
    if not es:
        logger.error("Cannot connect to Elasticsearch. Is Docker running?")
        logger.error("Start it with: docker-compose up -d")
        sys.exit(1)

    info = es.info()
    logger.info("Connected to Elasticsearch %s at %s",
                info["version"]["number"], ELASTICSEARCH_URI)

    # ── Load state
    state = load_state()
    logger.info("Loaded state: %d IPs currently blocked.", len(state.get("blocked", {})))

    # ── Single cycle mode
    if args.once:
        newly, already = run_enforcement_cycle(es, state, dry_run=args.dry_run)
        save_state(state)
        print()
        print(f"  ✅ Cycle complete: {newly} newly blocked, {already} already blocked.")
        print(f"  📋 Total blocked : {len(state['blocked'])} IPs")
        print()
        return

    # ── Daemon mode
    logger.info("Daemon started. Press Ctrl+C to stop.")
    cycle = 0
    try:
        while True:
            cycle += 1
            logger.info("── Cycle #%d ──────────────────────────────────────────", cycle)
            newly, already = run_enforcement_cycle(es, state, dry_run=args.dry_run)
            save_state(state)
            logger.info(
                "Cycle #%d done: %d newly blocked | %d already blocked | %d total",
                cycle, newly, already, len(state["blocked"]),
            )
            logger.info("Sleeping %ds until next cycle...", args.interval)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        logger.info("Enforcer stopped by user. Final state: %d IPs blocked.", len(state["blocked"]))
        save_state(state)


if __name__ == "__main__":
    main()
