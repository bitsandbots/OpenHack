"""
Hunter swarm agent that spawns focused sub-hunters concurrently.
"""

import asyncio
import logging
from typing import Optional

from .hunter import HunterAgent
from .llm import LLMClient
from .session import Session
from openhack.tools.registry import ToolRegistry
from openhack.categories import normalize_category
from openhack.config import settings

logger = logging.getLogger(__name__)

_FRAMEWORK_GROUP_TEMPLATES: dict[str, dict[str, dict]] = {
    "nextjs": {
        "input_validation": {
            "categories": ["xss", "injection", "ssrf", "open_redirect"],
            "task": (
                "Hunt for input validation vulnerabilities in the Next.js application"
                "{root_hint}: XSS, injection flaws, SSRF, and open redirects. "
                "Trace user input from entry points to dangerous sinks. "
                "Focus on reading route handlers, API endpoints, and components "
                "that render user-controlled data.\n\n"
                "IMPORTANT -- Open Redirect Hunting Strategy:\n"
                "Open redirects are a high-value, commonly exploitable vulnerability class. "
                "You MUST specifically search for them:\n"
                "1. Use grep to find ALL callback handlers: search for files matching '**/callback*', "
                "'**/api/auth/**', '**/api/integrations/**'\n"
                "2. Search for redirect sink patterns: grep for 'redirect(', 'NextResponse.redirect', "
                "'res.redirect', 'window.location'\n"
                "3. Search for common redirect parameter names: grep for 'returnTo', 'redirectTo', "
                "'redirect_url', 'onErrorReturnTo', 'callbackUrl', 'successUrl', 'cancelUrl'\n"
                "4. For each redirect found, trace whether the URL is validated.\n"
                "5. Pay special attention to OAuth/payment callback handlers."
            ),
        },
        "access_control": {
            "categories": ["idor", "auth_bypass", "middleware_bypass"],
            "task": (
                "Hunt for access control vulnerabilities in the Next.js application"
                "{root_hint}: IDOR, authentication bypass, "
                "and middleware bypass. Focus on authorization checks, object ownership "
                "validation, and middleware ordering."
            ),
        },
        "data_handling": {
            "categories": ["data_exposure", "csrf", "server_actions", "misconfiguration"],
            "task": (
                "Hunt for data handling and configuration vulnerabilities in the Next.js application"
                "{root_hint}: data exposure, CSRF, server action flaws, and security "
                "misconfigurations."
            ),
        },
    },
    "django": {
        "input_validation": {
            "categories": ["injection", "ssrf", "idor"],
            "task": "Hunt for input validation vulnerabilities in the Django application{root_hint}: SQL injection via ORM escape hatches, SSRF, and IDOR.",
        },
        "access_control": {
            "categories": ["auth_bypass", "csrf"],
            "task": "Hunt for access control vulnerabilities in the Django application{root_hint}: missing @login_required, broken permissions, @csrf_exempt.",
        },
        "data_handling": {
            "categories": ["data_exposure", "misconfiguration"],
            "task": "Hunt for data handling and configuration vulnerabilities in the Django application{root_hint}: serializer exposure, DEBUG=True, hardcoded secrets.",
        },
    },
    "express": {
        "input_validation": {
            "categories": ["injection", "ssrf", "idor"],
            "task": "Hunt for input validation vulnerabilities in the Express.js application{root_hint}: SQL/NoSQL injection, command injection, SSRF, IDOR.",
        },
        "access_control": {
            "categories": ["auth_bypass"],
            "task": "Hunt for access control vulnerabilities in the Express.js application{root_hint}: missing auth middleware, JWT issues.",
        },
        "data_handling": {
            "categories": ["data_exposure", "misconfiguration"],
            "task": "Hunt for data handling vulnerabilities in the Express.js application{root_hint}: data leaks, CORS issues, missing helmet.",
        },
    },
    "flask": {
        "input_validation": {
            "categories": ["injection", "ssrf", "idor"],
            "task": "Hunt for input validation vulnerabilities in the Flask application{root_hint}: SQL injection, SSTI, command injection, SSRF, IDOR.",
        },
        "access_control": {
            "categories": ["auth_bypass"],
            "task": "Hunt for access control vulnerabilities in the Flask application{root_hint}: missing @login_required, unprotected blueprints.",
        },
        "data_handling": {
            "categories": ["data_exposure", "misconfiguration"],
            "task": "Hunt for data handling vulnerabilities in the Flask application{root_hint}: data leaks, DEBUG=True, hardcoded secrets.",
        },
    },
}


def build_hunter_groups(detected_frameworks: list[dict], has_supabase: bool = False) -> dict[str, dict]:
    groups: dict[str, dict] = {}

    for i, fw_info in enumerate(detected_frameworks):
        fw_name = fw_info["framework"]
        fw_root = fw_info["root"]

        templates = _FRAMEWORK_GROUP_TEMPLATES.get(fw_name)
        if templates is None:
            continue

        root_hint = (
            f" located under `{fw_root}/`. Focus your file reads and grep "
            f"searches within this directory"
            if fw_root != "."
            else ""
        )

        suffix = f"_{i}" if sum(1 for f in detected_frameworks if f["framework"] == fw_name) > 1 else ""

        for group_key, template in templates.items():
            group_name = f"{fw_name}_{group_key}{suffix}"
            groups[group_name] = {
                "categories": template["categories"],
                "framework": fw_name,
                "requires": "source_code",
                "task": template["task"].format(root_hint=root_hint),
            }

    source_frameworks = [f for f in detected_frameworks]
    if len(source_frameworks) >= 2:
        fw_summary = ", ".join(f"{f['framework']} at `{f['root']}/`" for f in source_frameworks)
        groups["cross_framework"] = {
            "categories": ["injection", "ssrf", "auth_bypass", "idor", "data_exposure"],
            "framework": None,
            "requires": "source_code",
            "task": (
                f"This is a monorepo with multiple frameworks: {fw_summary}. "
                "Hunt specifically for CROSS-SERVICE vulnerability chains."
            ),
        }

    return groups


_CATEGORY_TO_DANGER_KEYWORDS: dict[str, list[str]] = {
    "input_validation": ["SQLi", "XSS", "SSRF", "SSTI", "RCE", "Open Redirect", "Path Traversal",
                         "Command Injection", "Prototype Pollution"],
    "access_control": ["IDOR", "Hardcoded Secret"],
    "data_handling": ["Hardcoded Secret", "Race Condition"],
}


def _build_file_hints(attack_surface: dict, group_categories: list[str]) -> str:
    """Build a file hint section from the attack surface for a hunter group.

    Maps hunter group categories to relevant attack surface files (danger pattern
    files and import dependencies) so the hunter knows exactly which files to read
    instead of guessing.
    """
    # Determine which danger keywords are relevant for this group
    relevant_keywords: set[str] = set()
    for cat in group_categories:
        for group_key, keywords in _CATEGORY_TO_DANGER_KEYWORDS.items():
            if cat in _FRAMEWORK_GROUP_TEMPLATES.get("express", {}).get(group_key, {}).get("categories", []):
                relevant_keywords.update(keywords)
            if cat in _FRAMEWORK_GROUP_TEMPLATES.get("nextjs", {}).get(group_key, {}).get("categories", []):
                relevant_keywords.update(keywords)
            if cat in _FRAMEWORK_GROUP_TEMPLATES.get("django", {}).get(group_key, {}).get("categories", []):
                relevant_keywords.update(keywords)
            if cat in _FRAMEWORK_GROUP_TEMPLATES.get("flask", {}).get(group_key, {}).get("categories", []):
                relevant_keywords.update(keywords)
    # Fallback: if no keywords matched, include everything
    if not relevant_keywords:
        relevant_keywords = {"SQLi", "XSS", "SSRF", "SSTI", "RCE", "Path Traversal",
                             "Command Injection", "IDOR", "Open Redirect", "Prototype Pollution",
                             "Hardcoded Secret", "Race Condition"}

    hint_files: list[str] = []
    max_hints = 20

    # Collect from danger_files and imported_dependencies
    for source_key in ("danger_files", "imported_dependencies"):
        for ep in attack_surface.get(source_key, []):
            label = ep.get("label", "")
            trigger = ep.get("trigger", "")
            # Check if any relevant keyword appears in the label or trigger
            if any(kw.lower() in label.lower() or kw.lower() in trigger.lower()
                   for kw in relevant_keywords):
                signals = ep.get("danger_signals", [])
                if signals:
                    signal_desc = "; ".join(
                        f"L{s['line']}: {s['description']}" for s in signals[:3]
                    )
                    hint_files.append(f"  - `{ep['file']}` — {signal_desc}")
                else:
                    hint_files.append(f"  - `{ep['file']}` — {ep.get('trigger', label)}")

            if len(hint_files) >= max_hints:
                break
        if len(hint_files) >= max_hints:
            break

    # Also include route handlers / framework entry points
    route_files: list[str] = []
    for source_key in ("route_handlers", "flask_routes", "django_views", "api_routes"):
        for ep in attack_surface.get(source_key, []):
            route_files.append(f"  - `{ep['file']}`")
            if len(route_files) >= 10:
                break

    if not hint_files and not route_files:
        return ""

    parts: list[str] = []
    if route_files:
        parts.append(
            "**Entry point files** (route handlers — start your analysis here):\n"
            + "\n".join(route_files[:10])
        )
    if hint_files:
        parts.append(
            "**High-signal files** (contain dangerous sinks or are imported by entry points — "
            "you MUST read these):\n"
            + "\n".join(hint_files)
        )

    return (
        "\n\n## Discovered Attack Surface Files\n"
        "The following files were identified by static analysis as security-relevant. "
        "READ EACH of these files during your hunt — do not skip them.\n\n"
        + "\n\n".join(parts)
    )


class HunterSwarmAgent:
    name = "hunter_swarm"
    description = "Hunter swarm coordinator"

    def __init__(self, llm: LLMClient, tools: ToolRegistry, session: Session):
        self.llm = llm
        self.tools = tools
        self.session = session
        self.total_cost: float = 0.0
        self.total_tokens: int = 0
        self.total_input_tokens: int = 0
        self.total_output_tokens: int = 0

    def _get_model_for_hunter(self) -> str:
        return settings.hunter_model_id or self.llm.model

    def _create_llm_for_sub_hunter(self) -> LLMClient:
        model = self._get_model_for_hunter()
        return LLMClient(model=model, temperature=0.0, max_tokens=8192, provider=self.llm.provider, prompt_cache_key=self.llm.prompt_cache_key)

    @staticmethod
    def _deduplicate_findings(findings: list[dict]) -> list[dict]:
        if not findings:
            return findings

        SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}

        seen: dict[str, dict] = {}
        for finding in findings:
            file_path = (finding.get("file_path") or "").strip().lower()
            raw_category = finding.get("vulnerability_type") or finding.get("category") or ""
            vuln_type = normalize_category(raw_category).lower()
            dedup_key = f"{file_path}::{vuln_type}"

            if dedup_key not in seen:
                seen[dedup_key] = finding
            else:
                existing = seen[dedup_key]
                existing_sev = SEVERITY_ORDER.get((existing.get("severity") or "info").lower(), 4)
                new_sev = SEVERITY_ORDER.get((finding.get("severity") or "info").lower(), 4)
                existing_conf = CONFIDENCE_ORDER.get((existing.get("confidence") or "low").lower(), 2)
                new_conf = CONFIDENCE_ORDER.get((finding.get("confidence") or "low").lower(), 2)
                existing_detail = len(existing.get("description") or "")
                new_detail = len(finding.get("description") or "")

                if (new_sev, new_conf, -new_detail) < (existing_sev, existing_conf, -existing_detail):
                    seen[dedup_key] = finding

        return list(seen.values())

    def _determine_groups(self, context: dict) -> dict[str, dict]:
        detected_frameworks = context.get("detected_frameworks", [])
        if not detected_frameworks:
            detected_frameworks = [{"framework": "nextjs", "root": "."}]

        all_groups = build_hunter_groups(detected_frameworks)

        return {name: config for name, config in all_groups.items()
                if config["requires"] == "source_code"}

    async def run(self, task: str, context: Optional[dict] = None) -> dict:
        context = context or {}

        active_groups = self._determine_groups(context)

        if not active_groups:
            return {"raw_output": "No hunter groups applicable", "findings": [], "type": "hunt_complete"}

        self.session.add_trace(
            agent=self.name, event_type="swarm_start",
            content={"groups": list(active_groups.keys()), "group_count": len(active_groups)},
        )

        # Build file hints from attack surface for each hunter group
        attack_surface = context.get("attack_surface", {})

        sub_hunters: list[tuple[str, HunterAgent, str]] = []
        for group_name, group_config in active_groups.items():
            llm = self._create_llm_for_sub_hunter()
            hunter = HunterAgent(
                llm, self.tools, self.session,
                vuln_categories=group_config["categories"],
                group_name=group_name,
                framework=group_config.get("framework"),
            )
            task_text = group_config["task"]
            # Inject relevant file hints so the hunter knows WHERE to look
            if attack_surface:
                file_hints = _build_file_hints(attack_surface, group_config["categories"])
                if file_hints:
                    task_text += file_hints
            sub_hunters.append((group_name, hunter, task_text))

        semaphore = asyncio.Semaphore(settings.max_concurrent_hunters)

        async def run_sub_hunter(group_name, hunter, hunter_task):
            async with semaphore:
                try:
                    result = await hunter.run(hunter_task, context)
                    return group_name, result
                except Exception as e:
                    logger.error(f"Sub-hunter {group_name} failed: {e}")
                    return group_name, {"raw_output": f"Failed: {e}", "findings": [], "type": "hunt_failed"}

        tasks = [
            asyncio.create_task(run_sub_hunter(name, hunter, task))
            for name, hunter, task in sub_hunters
        ]
        try:
            results = await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

        all_findings: list[dict] = []
        all_files_analyzed: set[str] = set()
        summaries: list[str] = []

        for group_name, result in results:
            all_findings.extend(result.get("findings", []))
            all_files_analyzed.update(result.get("files_analyzed", []))
            if result.get("raw_output"):
                summaries.append(f"[{group_name}] {result['raw_output']}")

        all_findings = self._deduplicate_findings(all_findings)

        for _, hunter, _ in sub_hunters:
            self.total_cost += hunter.llm.total_cost
            self.total_tokens += hunter.llm.total_tokens
            self.total_input_tokens += hunter.llm.total_input_tokens
            self.total_output_tokens += hunter.llm.total_output_tokens

        self.session.add_trace(
            agent=self.name, event_type="swarm_complete",
            content={"total_findings": len(all_findings), "groups_completed": len(results),
                     "total_cost": self.total_cost, "total_tokens": self.total_tokens},
        )

        return {
            "raw_output": "\n\n".join(summaries),
            "findings": all_findings,
            "type": "hunt_complete",
            "files_analyzed": sorted(all_files_analyzed),
        }
