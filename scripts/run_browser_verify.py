"""
Run browser-based verification on saved scan findings.

Usage:
    python run_browser_verify.py <scan_report_json>
    python run_browser_verify.py ~/.openhack/scans/scan-756f01ec.json

Spins up the target app in Docker, launches Playwright Chromium,
and drives the browser to exploit each finding with screenshot evidence.
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from openhack.agents.browser_verifier_swarm import BrowserVerifierSwarmAgent
from openhack.agents.llm import LLMClient
from openhack.agents.session import Session
from openhack.tools.registry import ToolRegistry
from openhack.sandbox.orchestrator import SandboxConfig
from openhack.config import settings, reload_settings


def _on_trace(entry):
    agent = entry.agent or "?"
    event = entry.event_type or ""
    snippet = str(entry.content or "")[:150]
    print(f"  [{agent}] {event}: {snippet}")


async def main():
    if len(sys.argv) < 2:
        print("Usage: python run_browser_verify.py <scan_report.json>")
        sys.exit(1)

    reload_settings()
    report_path = Path(sys.argv[1])
    report = json.loads(report_path.read_text())

    target_dir = report["target_dir"]
    findings = report["findings"]

    if not findings:
        print("No findings to verify.")
        return

    print(f"\n{'='*60}")
    print(f"  BROWSER VERIFICATION")
    print(f"  Target: {target_dir}")
    print(f"  Findings: {len(findings)}")
    print(f"  Provider: {settings.llm_provider}")
    print(f"  Headless: {settings.browser_headless}")
    print(f"{'='*60}\n")

    # Check playwright is installed
    try:
        from openhack.browser.runner import BrowserRunner
    except ImportError as e:
        print(f"ERROR: Playwright not installed. Run: pip install openhack[browser]")
        print(f"  Then: playwright install chromium")
        sys.exit(1)

    session = Session(target_dir=target_dir, on_trace=_on_trace)
    tools = ToolRegistry(target_dir=Path(target_dir))

    sandbox_config = SandboxConfig(
        health_check_path=settings.sandbox_health_check_path,
        health_check_timeout=settings.sandbox_health_check_timeout,
        teardown_on_complete=settings.sandbox_teardown_on_complete,
    )

    llm = LLMClient(provider=settings.llm_provider, temperature=0.0, max_tokens=8192)
    swarm = BrowserVerifierSwarmAgent(llm, tools, session, sandbox_config=sandbox_config)

    context = {
        "confirmed_findings": findings,
        "project_context": {},
    }

    result = await swarm.run(
        "Verify findings using browser-based exploit verification.",
        context=context,
    )

    exploitable = result.get("exploitable", [])
    not_exploitable = result.get("not_exploitable", [])
    evidence_dir = result.get("evidence_dir", "")

    print(f"\n{'='*60}")
    print(f"  BROWSER RESULTS")
    print(f"{'='*60}")
    print(f"  Exploitable: {len(exploitable)}")
    print(f"  Not exploitable: {len(not_exploitable)}")
    print(f"  Evidence dir: {evidence_dir}")
    print(f"  Cost: ${swarm.total_cost:.4f}")

    if exploitable:
        print(f"\n  Confirmed exploitable:")
        for r in exploitable:
            idx = r.get("finding_index", "?")
            f = findings[idx] if isinstance(idx, int) and idx < len(findings) else {}
            print(f"    [{f.get('severity', '?')}] {f.get('category', '?')} — {f.get('file_path', '?')}")
            if r.get("working_poc"):
                print(f"      PoC: {r['working_poc'][:100]}")

    # Save results
    out_path = report_path.parent / f"browser-{report_path.stem}.json"
    out = {
        "source_report": str(report_path),
        "target_dir": target_dir,
        "exploitable": exploitable,
        "not_exploitable": not_exploitable,
        "evidence_dir": evidence_dir,
        "cost": swarm.total_cost,
    }
    out_path.write_text(json.dumps(out, indent=2, default=str))
    print(f"\n  Results saved: {out_path}\n")


if __name__ == "__main__":
    asyncio.run(main())
