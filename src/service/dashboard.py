#!/usr/bin/env python3
"""
ROE Gate -- Real-Time Audit Dashboard

A terminal-based dashboard that monitors the Gate Service in real time.
Uses Python's built-in curses module for rendering (NO external dependencies).

Features:
    - Displays ROE Gate header with engagement info and ROE hash
    - Shows real-time statistics: evaluations, allows, denials, halted sessions
    - Scrolling log of recent decisions with color coding
    - Keyboard controls: quit, emergency halt, resume session, manual refresh
    - Auto-refreshes every 2 seconds by polling the Gate Service HTTP API

Layout:
    +======================================================================+
    |  ROE GATE -- Real-Time Audit Dashboard                               |
    |  Engagement: ENG-2024-001  Client: Acme Corp                         |
    |  ROE Hash: sha256:abc123...                                          |
    +======================================================================+
    |  STATS | Evaluations: 42  Allows: 35  Denials: 6  Halts: 1          |
    +======================================================================+
    |  DECISIONS                                                           |
    |  14:32:01 [ALLOW]  curl -> app.acme.com:443 (web_application_test)   |
    |  14:32:05 [ALLOW]  nmap -> 10.0.0.1 (reconnaissance)                |
    |  14:32:08 [DENY]   psql -> 10.0.2.50:5432 (direct_database_access)  |
    |  ...                                                                 |
    +======================================================================+
    |  [q]uit  [h]alt  [r]esume  [space] refresh    Auto-refresh: 2s       |
    +======================================================================+

Usage:
    python -m src.service.dashboard
    python -m src.service.dashboard --gate-url http://127.0.0.1:19990
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
import urllib.request
from datetime import datetime, timezone
from typing import Any


logger = logging.getLogger("roe_gate.dashboard")


# ---------------------------------------------------------------------------
# Gate Service HTTP Client (stdlib only -- no external dependencies)
# ---------------------------------------------------------------------------

def _gate_get(gate_url: str, path: str) -> dict:
    """GET request to the Gate Service API.

    Returns parsed JSON or empty dict on failure.
    """
    try:
        req = urllib.request.Request(f"{gate_url}{path}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return {}


def _gate_post(gate_url: str, path: str, data: dict | None = None) -> dict:
    """POST request to the Gate Service API.

    Returns parsed JSON or empty dict on failure.
    """
    try:
        body = json.dumps(data or {}).encode()
        req = urllib.request.Request(
            f"{gate_url}{path}",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Data Fetching Helpers
# ---------------------------------------------------------------------------

def fetch_health(gate_url: str) -> dict[str, Any]:
    """Fetch /api/v1/health from the Gate Service."""
    return _gate_get(gate_url, "/api/v1/health")


def fetch_stats(gate_url: str) -> dict[str, Any]:
    """Fetch /api/v1/stats from the Gate Service."""
    return _gate_get(gate_url, "/api/v1/stats")


def fetch_audit(gate_url: str, limit: int = 100) -> list[dict[str, Any]]:
    """Fetch /api/v1/audit from the Gate Service.

    Returns a list of audit event dicts, most recent first.
    """
    result = _gate_get(gate_url, f"/api/v1/audit?limit={limit}")
    if isinstance(result, dict):
        return result.get("events", [])
    if isinstance(result, list):
        return result
    return []


def send_emergency_halt(gate_url: str) -> dict[str, Any]:
    """POST /api/v1/halt to the Gate Service."""
    return _gate_post(gate_url, "/api/v1/halt")


def send_resume(gate_url: str, session_id: str = "") -> dict[str, Any]:
    """POST /api/v1/resume to the Gate Service."""
    payload: dict[str, Any] = {}
    if session_id:
        payload["session_id"] = session_id
    return _gate_post(gate_url, "/api/v1/resume", payload)


# ---------------------------------------------------------------------------
# Decision Log Entry Parsing
# ---------------------------------------------------------------------------

def _parse_decision_entry(event: dict[str, Any]) -> dict[str, str] | None:
    """Parse an audit event into a display-friendly decision entry.

    Returns a dict with keys: timestamp, decision, tool, target, category,
    reasoning.  Returns None if the event is not an action_evaluation.
    """
    if event.get("event_type") != "action_evaluation":
        return None

    details = event.get("details", {})
    decision = details.get("decision", "?")
    reasoning = details.get("reasoning", "")

    intent = details.get("intent", {})
    action = intent.get("action", {})
    tool = action.get("tool", "?")
    category = action.get("category", "?")

    target_info = intent.get("target", {})
    host = target_info.get("host", "?")
    port = target_info.get("port")
    if port:
        target = f"{host}:{port}"
    else:
        target = host

    # Parse timestamp
    ts_raw = event.get("timestamp", "")
    try:
        dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        ts_display = dt.strftime("%H:%M:%S")
    except (ValueError, AttributeError):
        ts_display = ts_raw[:8] if len(ts_raw) >= 8 else ts_raw

    return {
        "timestamp": ts_display,
        "decision": decision,
        "tool": tool,
        "target": target,
        "category": category,
        "reasoning": reasoning,
    }


# ---------------------------------------------------------------------------
# Curses-Based Dashboard
# ---------------------------------------------------------------------------

def _run_curses_dashboard(gate_url: str, refresh_interval: float = 2.0) -> None:
    """Run the full curses-based terminal dashboard."""
    import curses

    def _dashboard(stdscr: curses.window) -> None:
        # -- Setup curses --
        curses.curs_set(0)  # Hide cursor
        stdscr.nodelay(True)  # Non-blocking getch
        stdscr.timeout(int(refresh_interval * 1000))

        # -- Setup colors --
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, -1)    # ALLOW
        curses.init_pair(2, curses.COLOR_RED, -1)       # DENY
        curses.init_pair(3, curses.COLOR_YELLOW, -1)    # ESCALATE
        curses.init_pair(4, curses.COLOR_RED, -1)       # HALT (same red, bold later)
        curses.init_pair(5, curses.COLOR_CYAN, -1)      # Headers
        curses.init_pair(6, curses.COLOR_WHITE, -1)     # Normal text
        curses.init_pair(7, curses.COLOR_MAGENTA, -1)   # Status line

        COLOR_ALLOW = curses.color_pair(1)
        COLOR_DENY = curses.color_pair(2)
        COLOR_ESCALATE = curses.color_pair(3)
        COLOR_HALT = curses.color_pair(4) | curses.A_BOLD
        COLOR_HEADER = curses.color_pair(5) | curses.A_BOLD
        COLOR_NORMAL = curses.color_pair(6)
        COLOR_STATUS = curses.color_pair(7) | curses.A_BOLD

        def _decision_color(decision: str) -> int:
            d = decision.upper()
            if d == "ALLOW":
                return COLOR_ALLOW
            elif d == "DENY":
                return COLOR_DENY
            elif d == "ESCALATE":
                return COLOR_ESCALATE
            elif d == "HALT":
                return COLOR_HALT
            return COLOR_NORMAL

        # -- State --
        status_message = ""
        status_time = 0.0
        last_known_events: list[dict[str, str]] = []
        connection_ok = False

        while True:
            stdscr.erase()
            height, width = stdscr.getmaxyx()

            # Clamp width for drawing
            draw_width = min(width - 1, 120)
            if draw_width < 40:
                draw_width = 40

            # -- Fetch data --
            health = fetch_health(gate_url)
            stats = fetch_stats(gate_url)
            raw_events = fetch_audit(gate_url, limit=200)
            connection_ok = bool(health)

            # Parse events into display entries
            entries: list[dict[str, str]] = []
            for ev in raw_events:
                parsed = _parse_decision_entry(ev)
                if parsed:
                    entries.append(parsed)
            if entries:
                last_known_events = entries

            # -- Draw border top --
            row = 0
            border_line = "+" + "=" * (draw_width - 2) + "+"
            _safe_addstr(stdscr, row, 0, border_line, COLOR_HEADER, draw_width)
            row += 1

            # -- Header section --
            engagement = health.get("engagement_id", stats.get("engagement_id", "---"))
            client = health.get("client", stats.get("client", "---"))
            roe_hash = stats.get("roe_hash", health.get("roe_hash", "---"))

            _safe_addstr(
                stdscr, row, 0,
                _pad(f"|  ROE GATE -- Real-Time Audit Dashboard", draw_width),
                COLOR_HEADER, draw_width,
            )
            row += 1

            _safe_addstr(
                stdscr, row, 0,
                _pad(f"|  Engagement: {engagement}  Client: {client}", draw_width),
                COLOR_NORMAL, draw_width,
            )
            row += 1

            hash_display = roe_hash[:50] + "..." if len(roe_hash) > 50 else roe_hash
            _safe_addstr(
                stdscr, row, 0,
                _pad(f"|  ROE Hash: {hash_display}", draw_width),
                COLOR_NORMAL, draw_width,
            )
            row += 1

            # -- Stats separator --
            _safe_addstr(stdscr, row, 0, border_line, COLOR_HEADER, draw_width)
            row += 1

            total_evals = stats.get("total_evaluations", 0)
            total_allows = stats.get("total_allows", 0)
            total_denials = stats.get("total_denials", 0)
            halted_sessions = stats.get("halted_sessions", [])
            num_halts = len(halted_sessions) if isinstance(halted_sessions, list) else 0

            stats_line = (
                f"|  STATS | Evaluations: {total_evals}  "
                f"Allows: {total_allows}  "
                f"Denials: {total_denials}  "
                f"Halts: {num_halts}"
            )
            _safe_addstr(stdscr, row, 0, _pad(stats_line, draw_width), COLOR_NORMAL, draw_width)
            row += 1

            # -- Decisions separator --
            _safe_addstr(stdscr, row, 0, border_line, COLOR_HEADER, draw_width)
            row += 1

            _safe_addstr(
                stdscr, row, 0,
                _pad("|  DECISIONS", draw_width),
                COLOR_HEADER, draw_width,
            )
            row += 1

            # -- Decision log entries --
            # Reserve 4 rows for footer (separator + controls + status + bottom border)
            footer_rows = 4
            available_rows = height - row - footer_rows
            if available_rows < 1:
                available_rows = 1

            display_events = last_known_events[:available_rows]

            if not display_events and not connection_ok:
                msg = "|    (waiting for Gate Service connection...)"
                _safe_addstr(stdscr, row, 0, _pad(msg, draw_width), COLOR_ESCALATE, draw_width)
                row += 1
            elif not display_events:
                msg = "|    (no decisions yet)"
                _safe_addstr(stdscr, row, 0, _pad(msg, draw_width), COLOR_NORMAL, draw_width)
                row += 1
            else:
                for entry in display_events:
                    if row >= height - footer_rows:
                        break
                    decision = entry["decision"]
                    tool = entry["tool"]
                    target = entry["target"]
                    category = entry["category"]
                    ts = entry["timestamp"]
                    reasoning = entry.get("reasoning", "")

                    # Build the line
                    decision_tag = f"[{decision}]"
                    line = f"|  {ts} {decision_tag:10s} {tool} -> {target} ({category})"

                    # Add truncated reasoning for DENY/HALT
                    if decision in ("DENY", "HALT") and reasoning:
                        max_reason = draw_width - len(line) - 5
                        if max_reason > 10:
                            truncated = reasoning[:max_reason] + "..." if len(reasoning) > max_reason else reasoning
                            line += f" -- {truncated}"

                    color = _decision_color(decision)
                    _safe_addstr(stdscr, row, 0, _pad(line, draw_width), color, draw_width)
                    row += 1

            # Fill remaining space with empty lines
            while row < height - footer_rows:
                _safe_addstr(stdscr, row, 0, _pad("|", draw_width), COLOR_NORMAL, draw_width)
                row += 1

            # -- Footer --
            _safe_addstr(stdscr, row, 0, border_line, COLOR_HEADER, draw_width)
            row += 1

            controls = f"|  [q]uit  [h]alt  [r]esume  [space] refresh    Auto-refresh: {refresh_interval:.0f}s"
            _safe_addstr(stdscr, row, 0, _pad(controls, draw_width), COLOR_NORMAL, draw_width)
            row += 1

            # Status message line
            now = time.time()
            if status_message and (now - status_time) < 5.0:
                status_line = f"|  >> {status_message}"
                _safe_addstr(stdscr, row, 0, _pad(status_line, draw_width), COLOR_STATUS, draw_width)
            else:
                conn_status = "Connected" if connection_ok else "Disconnected"
                conn_color = COLOR_ALLOW if connection_ok else COLOR_DENY
                ts_now = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
                status_line = f"|  Gate: {conn_status}  |  {ts_now}  |  {gate_url}"
                _safe_addstr(stdscr, row, 0, _pad(status_line, draw_width), conn_color, draw_width)
            row += 1

            if row < height:
                _safe_addstr(stdscr, row, 0, border_line, COLOR_HEADER, draw_width)

            stdscr.refresh()

            # -- Handle keyboard input --
            try:
                key = stdscr.getch()
            except Exception:
                key = -1

            if key == ord("q") or key == ord("Q"):
                break
            elif key == ord("h") or key == ord("H"):
                result = send_emergency_halt(gate_url)
                if result:
                    status_message = "EMERGENCY HALT sent to Gate Service"
                else:
                    status_message = "Failed to send halt (Gate unreachable?)"
                status_time = time.time()
            elif key == ord("r") or key == ord("R"):
                result = send_resume(gate_url)
                if result:
                    status_message = "RESUME sent to Gate Service"
                else:
                    status_message = "Failed to send resume (Gate unreachable?)"
                status_time = time.time()
            elif key == ord(" "):
                status_message = "Manual refresh"
                status_time = time.time()
                # Loop will re-fetch on next iteration

    curses.wrapper(_dashboard)


def _safe_addstr(
    stdscr: Any,
    row: int,
    col: int,
    text: str,
    attr: int,
    max_width: int,
) -> None:
    """Safely write a string to the curses window, clipping to bounds."""
    try:
        height, width = stdscr.getmaxyx()
        if row < 0 or row >= height:
            return
        available = width - col - 1
        if available <= 0:
            return
        clipped = text[:available]
        stdscr.addstr(row, col, clipped, attr)
    except Exception:
        pass


def _pad(text: str, width: int) -> str:
    """Pad or truncate text to exactly width characters, ending with '|'."""
    inner_width = width - 1  # Reserve last column for closing '|'
    if len(text) >= inner_width:
        return text[: inner_width - 1] + "|"
    return text + " " * (inner_width - len(text)) + "|"


# ---------------------------------------------------------------------------
# Fallback Print-Based Dashboard (when curses is unavailable)
# ---------------------------------------------------------------------------

def _run_print_dashboard(gate_url: str, refresh_interval: float = 2.0) -> None:
    """Fallback dashboard using simple print statements.

    Used when curses is not available (e.g., non-TTY environments, Windows
    without windows-curses, piped output).
    """
    print("=" * 70)
    print("  ROE GATE -- Audit Dashboard (text mode)")
    print(f"  Polling: {gate_url}")
    print(f"  Refresh: {refresh_interval}s")
    print("  Press Ctrl+C to quit")
    print("=" * 70)
    print()

    seen_event_ids: set[str] = set()

    try:
        while True:
            stats = fetch_stats(gate_url)
            raw_events = fetch_audit(gate_url, limit=20)

            # Print stats
            total_evals = stats.get("total_evaluations", 0)
            total_allows = stats.get("total_allows", 0)
            total_denials = stats.get("total_denials", 0)
            halted = stats.get("halted_sessions", [])
            num_halts = len(halted) if isinstance(halted, list) else 0

            # ANSI color codes for non-curses output
            GREEN = "\033[92m"
            RED = "\033[91m"
            YELLOW = "\033[93m"
            BOLD = "\033[1m"
            RESET = "\033[0m"

            timestamp_now = datetime.now(timezone.utc).strftime("%H:%M:%S")
            print(
                f"[{timestamp_now}] Evals: {total_evals}  "
                f"{GREEN}Allows: {total_allows}{RESET}  "
                f"{RED}Denials: {total_denials}{RESET}  "
                f"Halts: {num_halts}"
            )

            # Print new events
            for ev in reversed(raw_events):
                event_id = ev.get("event_id", "")
                if event_id and event_id in seen_event_ids:
                    continue
                if event_id:
                    seen_event_ids.add(event_id)

                parsed = _parse_decision_entry(ev)
                if not parsed:
                    continue

                decision = parsed["decision"]
                if decision == "ALLOW":
                    color = GREEN
                elif decision == "DENY":
                    color = RED
                elif decision == "HALT":
                    color = f"{RED}{BOLD}"
                elif decision == "ESCALATE":
                    color = YELLOW
                else:
                    color = ""

                print(
                    f"  {parsed['timestamp']} "
                    f"{color}[{decision}]{RESET}  "
                    f"{parsed['tool']} -> {parsed['target']} "
                    f"({parsed['category']})"
                )
                if decision in ("DENY", "HALT") and parsed.get("reasoning"):
                    reason_short = parsed["reasoning"][:80]
                    print(f"           {reason_short}")

            time.sleep(refresh_interval)

    except KeyboardInterrupt:
        print("\n  Dashboard stopped.")


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    """Parse CLI arguments and launch the dashboard."""
    parser = argparse.ArgumentParser(
        description="ROE Gate -- Real-Time Audit Dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python -m src.service.dashboard\n"
            "  python -m src.service.dashboard --gate-url http://10.0.0.5:19990\n"
            "  python -m src.service.dashboard --refresh 5\n"
        ),
    )
    parser.add_argument(
        "--gate-url",
        default="http://127.0.0.1:19990",
        help="Gate Service base URL (default: http://127.0.0.1:19990)",
    )
    parser.add_argument(
        "--refresh",
        type=float,
        default=2.0,
        help="Auto-refresh interval in seconds (default: 2.0)",
    )
    parser.add_argument(
        "--text-mode",
        action="store_true",
        help="Force text-mode dashboard (no curses)",
    )
    args = parser.parse_args()

    gate_url = args.gate_url.rstrip("/")

    print(f"ROE Gate Dashboard connecting to: {gate_url}")
    print("Checking Gate Service health...")

    health = fetch_health(gate_url)
    if health:
        engagement = health.get("engagement_id", "?")
        print(f"  Gate Service is healthy (engagement: {engagement})")
    else:
        print("  Gate Service is not responding (will retry on each refresh)")

    # Try curses; fall back to print mode
    if args.text_mode:
        _run_print_dashboard(gate_url, refresh_interval=args.refresh)
        return

    try:
        import curses  # noqa: F401
        _run_curses_dashboard(gate_url, refresh_interval=args.refresh)
    except ImportError:
        print("  curses not available; falling back to text mode")
        _run_print_dashboard(gate_url, refresh_interval=args.refresh)
    except Exception as exc:
        print(f"  curses failed ({exc}); falling back to text mode")
        _run_print_dashboard(gate_url, refresh_interval=args.refresh)


if __name__ == "__main__":
    main()
