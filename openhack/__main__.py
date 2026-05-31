"""
Entry point for OpenHack.

Usage:
  openhack                              Launch interactive TUI
  openhack /path/to/repo                Scan a repository (headless)
  openhack --list-sessions              List all saved scan sessions
  openhack --list-entry-points ID       Show entry points for a session
  openhack --resume ID                  Resume a previous scan session
  openhack --classify /path/to/repo     Classify frameworks and detect entry points
"""

import sys


def main():
    # Check for CLI flags before launching TUI
    if len(sys.argv) > 1:
        arg = sys.argv[1]

        if arg == "--list-sessions":
            import json
            from pathlib import Path

            scans_dir = Path.home() / ".openhack" / "scans"
            if not scans_dir.exists():
                print("\nNo saved scans yet.")
                return
            reports = []
            for p in sorted(scans_dir.glob("*.json"), reverse=True):
                try:
                    data = json.loads(p.read_text())
                    reports.append(data)
                except (OSError, json.JSONDecodeError):
                    continue
            print(f"\nSaved scans: {len(reports)}")
            for r in reports:
                scan_id = (r.get("scan_id") or p.stem)[:8]
                target = r.get("target_dir", "?")
                status = r.get("status", "?")
                findings = r.get("findings", [])
                started = r.get("started_at", "")[:16]
                print(f"  {scan_id}  {target}  [{status}]  {len(findings)} findings  {started}")
            return

        if arg == "--list-entry-points":
            from openhack.scan_session import ScanSession
            session_id = sys.argv[2] if len(sys.argv) > 2 else None
            if not session_id:
                print("Usage: openhack --list-entry-points <session_id>")
                return
            session = ScanSession.load(session_id)
            if not session:
                print(f"Session {session_id} not found")
                return
            session.print_entry_points(show_all=True)
            return

        if arg == "--resume":
            from openhack.scan_session import ScanSession
            session_id = sys.argv[2] if len(sys.argv) > 2 else None
            if not session_id:
                print("Usage: openhack --resume <session_id>")
                return
            session = ScanSession.load(session_id)
            if not session:
                print(f"Session {session_id} not found")
                return
            if session.unscanned_count == 0:
                print(f"Session {session_id} is fully scanned ({session.scanned_count}/{len(session.entry_points)} endpoints)")
                session.print_summary()
                return
            print(f"Resuming session {session_id} on {session.target_dir}")
            print(f"  {session.scanned_count}/{len(session.entry_points)} endpoints scanned")
            print(f"  {session.unscanned_count} remaining")
            import asyncio
            from openhack.headless_scan import run_headless_scan
            asyncio.run(run_headless_scan(session.target_dir, resume_session=session))
            return

        if arg == "--classify":
            from pathlib import Path
            from openhack.tools.registry import ToolRegistry
            from openhack.framework_classifier import classify_frameworks
            from openhack.entry_points import detect_entry_points
            from openhack.scan_session import ScanSession
            import uuid

            target = sys.argv[2] if len(sys.argv) > 2 else "."
            tools = ToolRegistry(target_dir=Path(target))

            print(f"\nClassifying {target}...\n")
            classifications = classify_frameworks(tools.fs_tools)
            for c in classifications:
                print(f"  {c['root']} → {c['language']} [{', '.join(c['frameworks'])}]")

            print(f"\nDetecting entry points...")
            entry_points = detect_entry_points(tools.fs_tools, classifications)
            print(f"  {len(entry_points)} entry points found\n")

            # Save session
            sid = str(uuid.uuid4())[:8]
            session = ScanSession(sid, target)
            session.classifications = classifications
            session.entry_points = entry_points
            session.save()
            print(f"  Session saved: {sid}")
            print(f"  Run 'openhack --list-entry-points {sid}' to see all endpoints")
            print(f"  Run 'openhack --resume {sid}' to scan\n")
            return

        if arg in ("--help", "-h"):
            print(__doc__)
            return

        # If arg is a path (not a flag), run headless scan on it
        if not arg.startswith("-"):
            import asyncio
            from openhack.headless_scan import run_headless_scan
            asyncio.run(run_headless_scan(arg))
            return

    # Default: launch TUI
    from openhack.setup import needs_first_time_setup, run_first_time_setup

    try:
        if needs_first_time_setup():
            completed = run_first_time_setup()
            if not completed:
                print("\nSetup skipped. Run openhack again or use /setup inside the TUI.\n")

        from openhack.tui import main as tui_main
        tui_main()
    except KeyboardInterrupt:
        print()


if __name__ == "__main__":
    main()
