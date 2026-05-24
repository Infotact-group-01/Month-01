"""CLI interface for the Threat Intelligence Platform.

Usage:
    python -m src.cli ingest   — Run full ingestion pipeline
    python -m src.cli fetch    — Fetch feeds (no DB insert, print JSON)
    python -m src.cli stats    — Show database statistics
    python -m src.cli feeds    — List configured feed sources
"""

import argparse
import json
import sys

# ── ANSI helpers ─────────────────────────────────────────────────────────────
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_GREEN = "\033[92m"
_CYAN = "\033[96m"
_YELLOW = "\033[93m"
_RED = "\033[91m"
_MAGENTA = "\033[95m"
_BLUE = "\033[94m"


def _ok(msg: str) -> str:
    return f"{_GREEN}✓{_RESET} {msg}"


def _info(msg: str) -> str:
    return f"{_CYAN}ℹ{_RESET} {msg}"


def _warn(msg: str) -> str:
    return f"{_YELLOW}⚠{_RESET} {msg}"


def _err(msg: str) -> str:
    return f"{_RED}✗{_RESET} {msg}"


def _header(title: str) -> str:
    bar = "─" * 60
    return f"\n{_BOLD}{_MAGENTA}{bar}{_RESET}\n{_BOLD}  {title}{_RESET}\n{_MAGENTA}{bar}{_RESET}"


# ── Subcommands ──────────────────────────────────────────────────────────────

def cmd_ingest(_args: argparse.Namespace) -> None:
    """Run the full ingestion pipeline."""
    print(_header("TIP — Ingestion Pipeline"))
    from .ingest import process_feeds

    process_feeds()
    print(_ok("Ingestion pipeline finished."))


def cmd_fetch(_args: argparse.Namespace) -> None:
    """Fetch feeds and print as JSON (no database insert)."""
    print(_header("TIP — Feed Fetch"))
    from .fetch_feeds import fetch_all_feeds

    indicators = fetch_all_feeds()
    print(json.dumps(indicators, indent=2, default=str))
    print(_ok(f"Fetched {_BOLD}{len(indicators)}{_RESET} indicators."))


def cmd_stats(_args: argparse.Namespace) -> None:
    """Display database statistics."""
    print(_header("TIP — Database Statistics"))
    from .config import get_db_collection

    col = get_db_collection()
    total = col.count_documents({})

    # Count by type
    pipeline = [{"$group": {"_id": "$type", "count": {"$sum": 1}}}]
    try:
        by_type = {doc["_id"]: doc["count"] for doc in col.aggregate(pipeline)}
    except Exception:
        by_type = {}

    # Count by source
    pipeline_src = [{"$group": {"_id": "$source", "count": {"$sum": 1}}}]
    try:
        by_source = {doc["_id"]: doc["count"] for doc in col.aggregate(pipeline_src)}
    except Exception:
        by_source = {}

    print(f"\n  {_BOLD}Total indicators:{_RESET} {_GREEN}{total}{_RESET}")

    if by_type:
        print(f"\n  {_BOLD}By type:{_RESET}")
        for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
            bar = "█" * min(c, 40)
            print(f"    {_CYAN}{t:<10}{_RESET} {c:>5}  {_DIM}{bar}{_RESET}")

    if by_source:
        print(f"\n  {_BOLD}By source:{_RESET}")
        for s, c in sorted(by_source.items(), key=lambda x: -x[1]):
            print(f"    {_BLUE}{s:<25}{_RESET} {c:>5}")

    print()


def cmd_feeds(_args: argparse.Namespace) -> None:
    """List configured feed sources."""
    print(_header("TIP — Configured Feeds"))
    from .config import FEED_URLS

    if not FEED_URLS:
        print(_warn("No feeds configured in feeds.json"))
        return

    for i, (name, url) in enumerate(FEED_URLS.items(), 1):
        scheme = url.split("://")[0] if "://" in url else "?"
        color = _GREEN if scheme in ("https", "http") else _YELLOW
        print(f"  {_DIM}{i}.{_RESET} {_BOLD}{name}{_RESET}")
        print(f"     {color}{url}{_RESET}")

    print(f"\n  {_info(f'{len(FEED_URLS)} feed(s) configured.')}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="tip",
        description="Threat Intelligence Platform — CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    sub.add_parser("ingest", help="Run full ingestion pipeline")
    sub.add_parser("fetch", help="Fetch feeds (JSON output, no DB)")
    sub.add_parser("stats", help="Show database statistics")
    sub.add_parser("feeds", help="List configured feed sources")

    args = parser.parse_args()

    commands = {
        "ingest": cmd_ingest,
        "fetch": cmd_fetch,
        "stats": cmd_stats,
        "feeds": cmd_feeds,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
