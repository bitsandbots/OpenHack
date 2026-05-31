"""
Feature Deep Dive hunter agent.

Works like a human security researcher: reads the codebase, decides what's
interesting, goes deep on the riskiest features. No pre-assigned feature list —
the agent reads the route map, picks its own targets, and audits them.
"""

import logging
from typing import Optional

from .hunter import HunterAgent
from .llm import LLMClient
from .session import Session
from openhack.prompts import format_project_context
from openhack.prompts.feature_hunter import FEATURE_HUNTER_PROMPT
from openhack.tools.registry import ToolRegistry
from openhack.config import settings

logger = logging.getLogger(__name__)


class FeatureHunterAgent(HunterAgent):
    """Security researcher agent that picks its own targets and goes deep."""

    max_iterations = settings.feature_hunter_max_iterations

    # Check all categories — not limited to a subset
    DEFAULT_CATEGORIES = [
        "idor", "xss", "csrf", "ssrf", "injection",
        "auth_bypass", "data_exposure", "middleware_bypass",
        "server_actions", "misconfiguration", "path_traversal",
        "command_injection", "rce", "open_redirect",
    ]

    def __init__(
        self,
        llm: LLMClient,
        tools: ToolRegistry,
        session: Session,
        feature: Optional[dict] = None,
        hunter_id: int = 0,
        **kwargs,
    ):
        name = f"feature:{feature['name']}" if feature else f"researcher:{hunter_id}"
        super().__init__(
            llm, tools, session,
            vuln_categories=self.DEFAULT_CATEGORIES,
            group_name=name,
            framework=None,
            **kwargs,
        )
        self.feature = feature
        self.hunter_id = hunter_id

        if feature:
            self.name = f"feature_hunter:{feature['name']}"
            self.description = f"Deep dive on {feature['name']}"
        else:
            self.name = f"researcher:{hunter_id}"
            self.description = f"Security researcher #{hunter_id}"

    def get_system_prompt(self, context: dict) -> str:
        recon_context = context.get("recon", {}).get("summary", "No recon data available")
        project_context = context.get("project_context", {})
        project_context_str = format_project_context(project_context)

        if self.feature:
            # Legacy mode: pre-assigned feature
            entry_files = self.feature.get("entry_files", [])
            if isinstance(entry_files, list):
                files_str = "\n".join(f"- `{f}`" for f in entry_files)
            else:
                files_str = str(entry_files)

            feature_section = (
                f"\n## Your Assigned Target Feature\n\n"
                f"**Feature**: {self.feature.get('name', 'unknown')}\n"
                f"**Description**: {self.feature.get('description', '')}\n"
                f"**Key Files**: \n{files_str}\n"
                f"**Why High-Risk**: {self.feature.get('risk_reason', '')}\n"
            )

            return FEATURE_HUNTER_PROMPT.format(
                recon_context=feature_section + "\n\n## Full Application Context\n\n" + recon_context,
                project_context=project_context_str,
            )
        else:
            # New mode: agent picks its own targets
            return FEATURE_HUNTER_PROMPT.format(
                recon_context=recon_context,
                project_context=project_context_str,
            )
