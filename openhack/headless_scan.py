"""
Headless scan — runs the full pipeline without the TUI.

Supports both new scans and resuming from a previous session.
Uses framework classification, entry point detection, deterministic recon,
researcher agents, and LLM validation.
"""

import asyncio
import json
import logging
import time
import uuid
from pathlib import Path
from typing import Optional

from .agents.coordinator import CoordinatorAgent
from .agents.validator_swarm import ValidatorSwarmAgent
from .agents.hunter_swarm import HunterSwarmAgent
from .agents.llm import LLMClient
from .agents.session import Session, TraceEntry
from .tools.registry import ToolRegistry
from .deterministic_recon import run_deterministic_recon
from .framework_classifier import classify_frameworks
from .entry_points import detect_entry_points
from .scan_session import ScanSession
from .config import reload_settings, settings
from .prompts.project_context import build_project_context

logger = logging.getLogger(__name__)


def _on_trace(entry: TraceEntry):
    agent = entry.agent or "?"
    event = entry.event_type or ""
    if event == "tool_call":
        pass
    elif "finding" in event.lower():
        print(f"    [{agent}] FINDING: {entry.content}")
    elif event in ("status", "step_start", "step_complete"):
        snippet = str(entry.content or "")[:120]
        print(f"    [{agent}] {event}: {snippet}")


def _filter_attack_surface(surface: dict, exclude_files: set[str]) -> dict:
    """Remove already-analyzed files from the attack surface for resume."""
    filtered = {}
    total = 0
    for key, entries in surface.items():
        if not isinstance(entries, list):
            filtered[key] = entries
            continue
        kept = [ep for ep in entries if ep.get("file", "") not in exclude_files]
        filtered[key] = kept
        total += len(kept)
    filtered["total_endpoints"] = total
    return filtered


async def run_headless_scan(
    target_dir: str,
    resume_session: Optional[ScanSession] = None,
):
    """Run a headless scan with full pipeline.

    If resume_session is provided, continues from where the previous scan left off,
    focusing researchers on unscanned entry points.
    """
    reload_settings()
    target_path = Path(target_dir)
    provider = settings.llm_provider

    print(f"\n{'='*60}")
    if resume_session:
        print(f"  RESUMING SCAN — {target_dir}")
    else:
        print(f"  SCANNING — {target_dir}")
    print(f"  Provider: {provider}")
    print(f"{'='*60}\n")

    project_context = build_project_context(target_dir)
    agent_session = Session(target_dir=target_dir, on_trace=_on_trace, project_context=project_context)
    tools = ToolRegistry(target_dir=target_path)
    total_cost = 0.0

    if project_context and project_context.get("openhack_md"):
        print(f"  Loaded .openhack.md project context ({len(project_context['openhack_md'])} chars)")

    # ── Step 1: Framework Classification + Entry Points ─────────
    if resume_session:
        scan_session = resume_session
        classifications = scan_session.classifications
        entry_points = scan_session.entry_points
        unscanned_files = scan_session.get_unscanned_files()

        print(f"[1/5] Resuming session {scan_session.session_id}")
        print(f"  {len(entry_points)} total endpoints")
        print(f"  {scan_session.scanned_count} already scanned")
        print(f"  {scan_session.unscanned_count} remaining in {len(unscanned_files)} files")
        if scan_session.zone_coverage:
            completed = scan_session.get_completed_zones()
            print(f"  Zones completed: {len(completed)}")
        if scan_session.analyzed_files:
            print(f"  Files analyzed: {len(scan_session.analyzed_files)}")
        if scan_session.findings:
            print(f"  Previous findings: {len(scan_session.findings)}")
    else:
        print("[1/5] Classifying frameworks...")
        classifications = classify_frameworks(tools.fs_tools)
        for c in classifications:
            print(f"  {c['root']} → {c['language']} [{', '.join(c['frameworks'])}]")

        print("\n[2/5] Detecting entry points...")
        entry_points = detect_entry_points(tools.fs_tools, classifications)
        print(f"  {len(entry_points)} entry points found")

        scan_session = ScanSession(str(uuid.uuid4())[:8], target_dir)
        scan_session.classifications = classifications
        scan_session.entry_points = entry_points
        scan_session.save()
        print(f"  Session: {scan_session.session_id}")

    # ── Step 2: Deterministic Recon ──────────────────────────────
    print(f"\n[3/5] Running deterministic reconnaissance...")
    recon_result = run_deterministic_recon(tools)
    features_detected = list(recon_result.get("features", {}).keys())
    print(f"  Features: {features_detected}")

    # Add unscanned file hints to recon context for resume
    if resume_session:
        unscanned_files = scan_session.get_unscanned_files()
        if unscanned_files:
            unscanned_hint = "\n\n## Unscanned Files (FOCUS ON THESE)\n"
            unscanned_hint += "The following files have NOT been analyzed yet. "
            unscanned_hint += "Prioritize these over already-scanned files:\n"
            for f in unscanned_files[:30]:
                unscanned_hint += f"- `{f}`\n"
            if len(unscanned_files) > 30:
                unscanned_hint += f"- ... and {len(unscanned_files) - 30} more\n"
            recon_result["summary"] = recon_result.get("summary", "") + unscanned_hint

    # ── Step 2.5: Attack Surface Discovery ─────────────────────────
    if resume_session and scan_session.attack_surface:
        attack_surface = scan_session.attack_surface
        print(f"  Attack surface (cached): {attack_surface.get('total_endpoints', '?')} files")
    else:
        attack_surface = recon_result.get("attack_surface")
        if attack_surface:
            print(f"  Attack surface: {attack_surface.get('total_endpoints', '?')} files")
            scan_session.attack_surface = attack_surface
            scan_session.save()
        else:
            logger.warning("No attack surface from recon")

    # On resume: filter attack surface to exclude already-analyzed files
    effective_surface = attack_surface
    if resume_session and attack_surface and scan_session.analyzed_files:
        already_done = scan_session.get_analyzed_file_set()
        effective_surface = _filter_attack_surface(attack_surface, already_done)
        remaining = effective_surface.get("total_endpoints", 0)
        print(f"  Filtered surface: {remaining} files remaining (skipping {len(already_done)} analyzed)")

    # ── Step 3: Researcher Deep Dive ─────────────────────────────
    print(f"\n[4/5] Running researcher deep dive...")
    coordinator = CoordinatorAgent(
        LLMClient(provider=provider, temperature=0.0, max_tokens=8192, prompt_cache_key=agent_session.id),
        tools, agent_session,
    )
    coordinator.context = {
        "recon": recon_result,
        "detected_frameworks": classifications,
    }
    if effective_surface:
        coordinator.context["attack_surface"] = effective_surface

    feature_result = await coordinator._run_feature_deep_dive([], coordinator.context)

    feature_findings = feature_result.get("findings", [])
    hunt_cost = feature_result.get("total_cost", 0)
    total_cost += hunt_cost

    print(f"  {len(feature_findings)} raw findings, ${hunt_cost:.4f}")

    # Update zone coverage from researcher results
    for zr in feature_result.get("zone_results", []):
        scan_session.mark_zone_complete(
            zr["zone_name"], zr["files_analyzed"], zr["findings_count"]
        )

    if not feature_findings:
        print("\n  No findings from deep dive.")
        for f in feature_result.get("files_analyzed", []):
            scan_session.mark_scanned(f)
        scan_session.total_cost += total_cost
        scan_session.save()
        scan_session.print_summary()
        return

    # ── Step 4: LLM Validation ───────────────────────────────────
    print(f"\n[5/5] Validating {len(feature_findings)} findings...")
    validator_llm = LLMClient(provider=provider, temperature=0.0, max_tokens=8192, prompt_cache_key=agent_session.id)
    validator_context = {"hunter": {"findings": feature_findings}, "recon": recon_result}
    validator_swarm = ValidatorSwarmAgent(validator_llm, tools, agent_session)
    validator_result = await validator_swarm.run(
        "Validate each potential vulnerability.", context=validator_context)

    validated = validator_result.get("validated_findings", [])
    validator_cost = validator_swarm.total_cost
    total_cost += validator_cost

    validated = CoordinatorAgent._deduplicate_validated(validated, feature_findings)
    validated = CoordinatorAgent._cap_findings_per_file(validated, feature_findings)

    # ── Results ──────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  RESULTS")
    print(f"{'='*60}")

    if not validated:
        print("  No vulnerabilities confirmed.")
    else:
        print(f"  {len(validated)} vulnerability(ies) confirmed:\n")
        for i, v in enumerate(validated, 1):
            idx = v.get("original_index", 0)
            if 0 <= idx < len(feature_findings):
                f = feature_findings[idx]
                sev = f.get("severity", "?").upper()
                cat = f.get("category", "?")
                fp = f.get("file_path", "?")
                desc = f.get("description", "")[:200]
                print(f"  {i}. [{sev}] {cat} — {fp}")
                print(f"     {desc}")
                print()

    print(f"  Cost: ${total_cost:.4f}")

    # ── Update scan session ──────────────────────────────────────
    files_analyzed = feature_result.get("files_analyzed", [])
    for f in files_analyzed:
        scan_session.mark_scanned(f)
        if f not in scan_session.analyzed_files:
            scan_session.analyzed_files.append(f)

    for f in feature_findings:
        fp = f.get("file_path", "")
        if fp:
            scan_session.mark_finding(fp)

    # Append new findings to existing ones (for resume)
    new_findings = [
        {
            "severity": feature_findings[v["original_index"]].get("severity", "?"),
            "category": feature_findings[v["original_index"]].get("category", "?"),
            "file_path": feature_findings[v["original_index"]].get("file_path", "?"),
            "description": feature_findings[v["original_index"]].get("description", "")[:200],
        }
        for v in validated
        if 0 <= v.get("original_index", -1) < len(feature_findings)
    ]
    scan_session.findings.extend(new_findings)
    scan_session.total_cost += total_cost
    scan_session.save()
    scan_session.print_summary()

    # Save report
    report_dir = Path.home() / ".openhack" / "scans"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"scan-{scan_session.session_id}.json"
    report = {
        "session_id": scan_session.session_id,
        "target_dir": target_dir,
        "provider": provider,
        "resumed": resume_session is not None,
        "cost": total_cost,
        "raw_findings": len(feature_findings),
        "validated_findings": len(validated),
        "findings": new_findings,
    }
    with open(report_path, "w") as fp:
        json.dump(report, fp, indent=2, default=str)
    print(f"  Report: {report_path}\n")
