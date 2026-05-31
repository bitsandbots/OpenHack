"""
Endpoint analyst agent — per-entry-point security analysis.

Instead of category-based researchers that each scan the whole codebase for
one type of vulnerability, this agent receives specific endpoints and checks
them against a comprehensive security checklist.
"""

import asyncio
import logging
from collections import defaultdict
from typing import Optional

from .hunter import HunterAgent
from .hunter_swarm import HunterSwarmAgent
from .llm import LLMClient
from .session import Session
from openhack.prompts import format_project_context
from openhack.prompts.endpoint_analyst import ENDPOINT_ANALYST_PROMPT
from openhack.tools.registry import ToolRegistry
from openhack.config import settings

logger = logging.getLogger(__name__)


class EndpointAnalystAgent(HunterAgent):
    """Analyst that audits specific endpoints against a full security checklist."""

    max_iterations = settings.feature_hunter_max_iterations

    DEFAULT_CATEGORIES = [
        "idor", "xss", "csrf", "ssrf", "injection",
        "auth_bypass", "data_exposure", "middleware_bypass",
        "server_actions", "misconfiguration", "path_traversal",
        "command_injection", "rce", "open_redirect",
        "xxe", "insecure_deserialization", "race_condition",
        "cors_misconfiguration", "business_logic", "mass_assignment",
    ]

    def __init__(
        self,
        llm: LLMClient,
        tools: ToolRegistry,
        session: Session,
        endpoints: list[dict],
        group_name: str,
        **kwargs,
    ):
        super().__init__(
            llm, tools, session,
            vuln_categories=self.DEFAULT_CATEGORIES,
            group_name=group_name,
            framework=None,
            **kwargs,
        )
        self.endpoints = endpoints
        self.name = f"analyst:{group_name}"
        self.description = f"Endpoint analyst ({group_name})"

    def get_system_prompt(self, context: dict) -> str:
        recon_context = context.get("recon", {}).get("summary", "No recon data available")
        project_context = context.get("project_context", {})
        project_context_str = format_project_context(project_context)

        endpoint_lines = []
        for ep in self.endpoints:
            method = ep.get("method", "ALL")
            path = ep.get("path", ep.get("file", "unknown"))
            file = ep.get("file", "unknown")
            line = ep.get("line")
            auth = ep.get("auth")
            loc = f"`{file}`"
            if line:
                loc += f" (line {line})"
            auth_str = f" [auth: {auth}]" if auth else ""
            endpoint_lines.append(f"- **{method} {path}** → {loc}{auth_str}")

        endpoint_assignments = "\n".join(endpoint_lines)

        return ENDPOINT_ANALYST_PROMPT.format(
            recon_context=recon_context,
            project_context=project_context_str,
            endpoint_assignments=endpoint_assignments,
        )


def group_entry_points(entry_points: list[dict], max_groups: int = 12) -> dict[str, list[dict]]:
    """Group entry points by directory for analyst assignment.

    Groups endpoints that share a parent directory (e.g., all /api/auth/* endpoints
    go to the same analyst). Merges small groups to stay within max_groups.
    """
    by_dir: dict[str, list[dict]] = defaultdict(list)

    for ep in entry_points:
        file_path = ep.get("file", "")
        parts = file_path.replace("\\", "/").split("/")

        # Find a meaningful grouping key — use the first 3-4 path segments
        # For "src/app/api/auth/login/route.ts" → "api/auth"
        # For "src/app/api/orders/[id]/route.ts" → "api/orders"
        api_idx = None
        for i, part in enumerate(parts):
            if part in ("api", "routes", "controllers", "views", "handlers"):
                api_idx = i
                break

        if api_idx is not None and api_idx + 1 < len(parts):
            # Group by the first path segment after "api/"
            group_key = parts[api_idx + 1]
            # Skip dynamic segments like [id]
            if group_key.startswith("[") or group_key.startswith(":"):
                group_key = parts[api_idx] if api_idx > 0 else "root"
        elif len(parts) >= 2:
            group_key = parts[-2] if parts[-1].startswith("route") else parts[-1].split(".")[0]
        else:
            group_key = "root"

        by_dir[group_key].append(ep)

    # If we have too many groups, merge the smallest ones
    if len(by_dir) > max_groups:
        groups_sorted = sorted(by_dir.items(), key=lambda x: len(x[1]))
        merged: dict[str, list[dict]] = {}
        overflow: list[dict] = []

        for name, endpoints in groups_sorted:
            if len(merged) < max_groups - 1:
                merged[name] = endpoints
            else:
                overflow.extend(endpoints)

        if overflow:
            merged["misc"] = overflow
        by_dir = merged

    return dict(by_dir)


def _find_cross_cutting_files(tools: ToolRegistry) -> list[dict]:
    """Find middleware, auth helpers, and components that render user input."""
    cross_cutting = []
    fs = tools.fs_tools

    patterns = [
        ("middleware.ts", "Middleware"),
        ("middleware.js", "Middleware"),
        ("src/middleware.ts", "Middleware"),
        ("src/middleware.js", "Middleware"),
    ]
    for path, label in patterns:
        result = fs.read_file(path)
        if "error" not in result:
            cross_cutting.append({
                "path": f"[{label}] {path}",
                "method": "MIDDLEWARE",
                "file": path,
                "line": None,
                "auth": None,
            })

    for pattern in ["**/lib/auth.*", "**/utils/auth.*", "**/helpers/auth.*"]:
        result = fs.glob(pattern)
        for match in result.get("matches", []):
            if any(skip in match for skip in [".deepsec/", "node_modules/", ".next/"]):
                continue
            cross_cutting.append({
                "path": f"[Auth Helper] {match}",
                "method": "HELPER",
                "file": match,
                "line": None,
                "auth": None,
            })

    for pattern in ["**/*.tsx", "**/*.jsx"]:
        result = fs.glob(pattern)
        for match in result.get("matches", []):
            if any(skip in match for skip in ["node_modules/", ".next/", "test/"]):
                continue
            content = fs.read_file(match).get("content", "")
            if "dangerouslySetInnerHTML" in content or "innerHTML" in content:
                cross_cutting.append({
                    "path": f"[Component] {match}",
                    "method": "RENDER",
                    "file": match,
                    "line": None,
                    "auth": None,
                })

    return cross_cutting


async def run_endpoint_analysts(
    entry_points: list[dict],
    llm_template: LLMClient,
    tools: ToolRegistry,
    session: Session,
    context: dict,
    max_concurrent: int = 3,
) -> dict:
    """Spawn per-endpoint-group analysts and collect findings."""
    groups = group_entry_points(entry_points)

    cross_cutting = _find_cross_cutting_files(tools)
    if cross_cutting:
        groups["middleware_and_shared"] = cross_cutting
        logger.info(f"Added cross-cutting group with {len(cross_cutting)} files")

    if not groups:
        return {
            "findings": [],
            "files_analyzed": [],
            "total_cost": 0.0,
            "total_tokens": 0,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
        }

    logger.info(
        f"Endpoint analyst groups ({len(groups)}): "
        + ", ".join(f"{name}({len(eps)})" for name, eps in groups.items())
    )

    semaphore = asyncio.Semaphore(max_concurrent)
    total_cost = 0.0
    total_tokens = 0
    total_input_tokens = 0
    total_output_tokens = 0

    async def run_analyst(group_name: str, endpoints: list[dict]):
        async with semaphore:
            model = (
                settings.feature_hunter_model_id
                or settings.hunter_model_id
                or llm_template.model
            )
            llm = LLMClient(
                model=model,
                temperature=0.0,
                max_tokens=8192,
                provider=llm_template.provider,
                prompt_cache_key=llm_template.prompt_cache_key,
            )
            analyst = EndpointAnalystAgent(
                llm, tools, session,
                endpoints=endpoints,
                group_name=group_name,
            )

            # Build task description listing the endpoints
            ep_summary = ", ".join(
                f"{ep.get('method', 'ALL')} {ep.get('path', '?')}"
                for ep in endpoints[:5]
            )
            if len(endpoints) > 5:
                ep_summary += f" (+{len(endpoints) - 5} more)"

            task_text = (
                f"Analyze these {len(endpoints)} endpoint(s) for security vulnerabilities: "
                f"{ep_summary}. "
                f"Read each handler file, trace dependencies, and check against the full "
                f"security checklist. Report every real vulnerability you find."
            )

            try:
                result = await analyst.run(task_text, context=context)
                return group_name, result, llm
            except Exception as e:
                logger.error(f"Endpoint analyst {group_name} failed: {e}")
                return group_name, {"findings": [], "files_analyzed": []}, llm

    tasks = [
        asyncio.create_task(run_analyst(name, eps))
        for name, eps in groups.items()
    ]

    try:
        results = await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise

    all_findings = []
    all_files = set()

    for group_name, result, llm_client in results:
        findings = result.get("findings", [])
        all_findings.extend(findings)
        all_files.update(result.get("files_analyzed", []))
        total_cost += llm_client.total_cost
        total_tokens += llm_client.total_tokens
        total_input_tokens += llm_client.total_input_tokens
        total_output_tokens += llm_client.total_output_tokens
        logger.info(f"Analyst {group_name}: {len(findings)} findings")

    all_findings = HunterSwarmAgent._deduplicate_findings(all_findings)

    return {
        "findings": all_findings,
        "files_analyzed": sorted(all_files),
        "total_cost": total_cost,
        "total_tokens": total_tokens,
        "total_input_tokens": total_input_tokens,
        "total_output_tokens": total_output_tokens,
    }
