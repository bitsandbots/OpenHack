"""
Run sandbox verification against an ALREADY RUNNING app instance.

Usage:
    python run_sandbox_verify_live.py <scan_report_json> <base_url>
    python run_sandbox_verify_live.py ~/.openhack/scans/scan-756f01ec.json http://localhost:3666

Skips Docker orchestration - assumes the app is already running at base_url.
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from openhack.agents.sandbox_verifier import SandboxVerifierAgent
from openhack.agents.llm import LLMClient
from openhack.agents.session import Session
from openhack.tools.registry import ToolRegistry
from openhack.sandbox.runner import ExploitRunner
from openhack.config import settings, reload_settings


def _on_trace(entry):
    agent = entry.agent or "?"
    event = entry.event_type or ""
    snippet = str(entry.content or "")[:150]
    print(f"  [{agent}] {event}: {snippet}")


async def main():
    if len(sys.argv) < 3:
        print("Usage: python run_sandbox_verify_live.py <scan_report.json> <base_url>")
        print("Example: python run_sandbox_verify_live.py ~/.openhack/scans/scan-756f01ec.json http://localhost:3666")
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
    print(f"  SANDBOX VERIFICATION (LIVE)")
    print(f"  Target: {target_dir}")
    print(f"  App URL: {base_url}")
    print(f"  Findings: {len(findings)}")
    print(f"  Provider: {settings.llm_provider}")
    print(f"{'='*60}\n")

    session = Session(target_dir=target_dir, on_trace=_on_trace)
    tools = ToolRegistry(target_dir=Path(target_dir))

    total_cost = 0.0
    exploitable = []
    not_exploitable = []

    semaphore = asyncio.Semaphore(5)

    async with ExploitRunner(base_url=base_url, timeout=30) as runner:
        async def verify_one(idx: int, finding: dict):
            async with semaphore:
                llm = LLMClient(
                    provider=settings.llm_provider,
                    temperature=0.0,
                    max_tokens=8192,
                )
                verifier = SandboxVerifierAgent(
                    llm, tools, session,
                    sandbox_url=base_url,
                    exploit_runner=runner,
                    finding_index=idx,
                    max_attempts=settings.sandbox_max_exploit_attempts,
                )
                sub_context = {
                    "finding": finding,
                    "project_context": {},
                }
                try:
                    result = await asyncio.wait_for(
                        verifier.run(
                            "Verify this vulnerability by exploiting it against the live app.",
                            context=sub_context,
                        ),
                        timeout=180,
                    )
                    return idx, result, llm
                except asyncio.TimeoutError:
                    print(f"  TIMEOUT finding {idx} after 180s")
                    return idx, {
                        "exploit_result": {
                            "finding_index": idx,
                            "status": "timeout",
                            "confidence": "low",
                            "reason": "Verification timed out after 180s",
                        }
                    }, llm
                except Exception as e:
                    print(f"  ERROR finding {idx}: {e}")
                    return idx, {
                        "exploit_result": {
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
        exploit_result = result.get("exploit_result", {})
        status = exploit_result.get("status", "unknown")
        finding = findings[idx]

        if status == "exploitable":
            exploitable.append(exploit_result)
            print(f"  [EXPLOITABLE] #{idx} [{finding.get('severity')}] {finding.get('category')} — {finding.get('file_path')}")
        else:
            not_exploitable.append(exploit_result)
            reason = exploit_result.get("reason", "")[:80]
            print(f"  [NOT CONFIRMED] #{idx} [{finding.get('severity')}] {finding.get('category')} — {finding.get('file_path')} ({reason})")

    print(f"\n{'='*60}")
    print(f"  SANDBOX RESULTS")
    print(f"{'='*60}")
    print(f"  Exploitable: {len(exploitable)} / {len(findings)}")
    print(f"  Not confirmed: {len(not_exploitable)}")
    print(f"  Cost: ${total_cost:.4f}")

    out_path = report_path.parent / f"sandbox-live-{report_path.stem}.json"
    out = {
        "source_report": str(report_path),
        "target_dir": target_dir,
        "base_url": base_url,
        "exploitable": exploitable,
        "not_exploitable": not_exploitable,
        "cost": total_cost,
    }
    out_path.write_text(json.dumps(out, indent=2, default=str))
    print(f"\n  Results saved: {out_path}\n")


if __name__ == "__main__":
    asyncio.run(main())
