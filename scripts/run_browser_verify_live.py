"""
Run browser-based verification against an ALREADY RUNNING app instance.

Usage:
    python run_browser_verify_live.py <scan_report_json> <base_url>
    python run_browser_verify_live.py ~/.openhack/scans/scan-756f01ec.json http://localhost:3666

Skips sandbox orchestration - assumes the app is already running at base_url.
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from openhack.agents.browser_verifier import BrowserVerifierAgent
from openhack.agents.llm import LLMClient
from openhack.agents.session import Session
from openhack.browser.runner import BrowserRunner
from openhack.tools.registry import ToolRegistry
from openhack.config import settings, reload_settings


def _on_trace(entry):
    agent = entry.agent or "?"
    event = entry.event_type or ""
    snippet = str(entry.content or "")[:150]
    print(f"  [{agent}] {event}: {snippet}")


async def main():
    if len(sys.argv) < 3:
        print("Usage: python run_browser_verify_live.py <scan_report.json> <base_url>")
        print("Example: python run_browser_verify_live.py ~/.openhack/scans/scan-756f01ec.json http://localhost:3666")
        sys.exit(1)

    reload_settings()
    report_path = Path(sys.argv[1])
    base_url = sys.argv[2]
    report = json.loads(report_path.read_text())

    target_dir = report["target_dir"]
    findings = report["findings"]

    if not findings:
        print("No findings to verify.")
        return

    print(f"\n{'='*60}")
    print(f"  BROWSER VERIFICATION (LIVE)")
    print(f"  Target: {target_dir}")
    print(f"  App URL: {base_url}")
    print(f"  Findings: {len(findings)}")
    print(f"  Provider: {settings.llm_provider}")
    print(f"  Headless: {settings.browser_headless}")
    print(f"{'='*60}\n")

    session = Session(target_dir=target_dir, on_trace=_on_trace)
    tools = ToolRegistry(target_dir=Path(target_dir))

    session_id = "browser-verify-live"
    evidence_dir = Path.home() / ".openhack" / "evidence" / session_id
    evidence_dir.mkdir(parents=True, exist_ok=True)

    total_cost = 0.0
    exploitable = []
    not_exploitable = []

    async with BrowserRunner(
        base_url=base_url,
        evidence_dir=evidence_dir,
        headless=settings.browser_headless,
        timeout=settings.browser_timeout_ms,
    ) as runner:
        semaphore = asyncio.Semaphore(2)

        async def verify_one(idx: int, finding: dict):
            async with semaphore:
                llm = LLMClient(
                    provider=settings.llm_provider,
                    temperature=0.0,
                    max_tokens=8192,
                )
                verifier = BrowserVerifierAgent(
                    llm, tools, session,
                    sandbox_url=base_url,
                    browser_runner=runner,
                    sandbox_orchestrator=None,
                    finding_index=idx,
                    max_attempts=settings.browser_max_exploit_attempts,
                )
                sub_context = {
                    "finding": finding,
                    "project_context": {},
                }
                try:
                    result = await asyncio.wait_for(
                        verifier.run(
                            "Verify this vulnerability by exploiting it in the browser.",
                            context=sub_context,
                        ),
                        timeout=180,
                    )
                    return idx, result, llm
                except asyncio.TimeoutError:
                    print(f"  TIMEOUT finding {idx} after 180s")
                    return idx, {
                        "browser_result": {
                            "finding_index": idx,
                            "status": "timeout",
                            "confidence": "low",
                            "reason": "Verification timed out after 180s",
                        }
                    }, llm
                except Exception as e:
                    print(f"  ERROR finding {idx}: {e}")
                    return idx, {
                        "browser_result": {
                            "finding_index": idx,
                            "status": "error",
                            "confidence": "low",
                            "reason": str(e),
                        }
                    }, llm

        tasks = [asyncio.create_task(verify_one(i, f)) for i, f in enumerate(findings)]
        results = await asyncio.gather(*tasks)

    for idx, result, llm_client in results:
        total_cost += llm_client.total_cost
        browser_result = result.get("browser_result", {})
        status = browser_result.get("status", "unknown")
        finding = findings[idx]

        if status == "exploitable":
            exploitable.append(browser_result)
            print(f"  [EXPLOITABLE] #{idx} [{finding.get('severity')}] {finding.get('category')} — {finding.get('file_path')}")
        else:
            not_exploitable.append(browser_result)
            print(f"  [NOT CONFIRMED] #{idx} [{finding.get('severity')}] {finding.get('category')} — {finding.get('file_path')} ({browser_result.get('reason', '')})")

    print(f"\n{'='*60}")
    print(f"  BROWSER RESULTS")
    print(f"{'='*60}")
    print(f"  Exploitable: {len(exploitable)} / {len(findings)}")
    print(f"  Not confirmed: {len(not_exploitable)}")
    print(f"  Evidence: {evidence_dir}")
    print(f"  Cost: ${total_cost:.4f}")

    out_path = report_path.parent / f"browser-live-{report_path.stem}.json"
    out = {
        "source_report": str(report_path),
        "target_dir": target_dir,
        "base_url": base_url,
        "exploitable": exploitable,
        "not_exploitable": not_exploitable,
        "evidence_dir": str(evidence_dir),
        "cost": total_cost,
    }
    out_path.write_text(json.dumps(out, indent=2, default=str))
    print(f"\n  Results saved: {out_path}\n")


if __name__ == "__main__":
    asyncio.run(main())
