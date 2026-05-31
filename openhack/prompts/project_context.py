"""
Utility for formatting project context into prompt sections.
"""

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

OPENHACK_MD_FILENAMES = [".openhack.md", "OPENHACK.md", ".openhack/context.md"]


def load_openhack_md(target_dir: str) -> Optional[str]:
    """Load .openhack.md from the target directory if it exists."""
    target = Path(target_dir)
    for filename in OPENHACK_MD_FILENAMES:
        candidate = target / filename
        if candidate.is_file():
            try:
                content = candidate.read_text(encoding="utf-8").strip()
                if content:
                    logger.info(f"Loaded project context from {candidate}")
                    return content
            except Exception as e:
                logger.warning(f"Failed to read {candidate}: {e}")
    return None


def build_project_context(target_dir: str, api_context: Optional[dict] = None) -> Optional[dict]:
    """Build project_context dict from .openhack.md and/or API-provided context."""
    ctx = dict(api_context) if api_context else {}
    markdown = load_openhack_md(target_dir)
    if markdown:
        ctx["openhack_md"] = markdown
    return ctx if ctx else None


def format_project_context(project_context: Optional[dict]) -> str:
    """Format project context into a prompt section."""
    if not project_context:
        return ""

    ctx = project_context
    context_parts = []

    if ctx.get("description"):
        context_parts.append(f"**Application Description**: {ctx['description']}")
    if ctx.get("techStack"):
        context_parts.append(f"**Tech Stack**: {ctx['techStack']}")
    if ctx.get("deploymentEnv"):
        context_parts.append(f"**Deployment Environment**: {ctx['deploymentEnv']}")
    if ctx.get("authMethod"):
        context_parts.append(f"**Authentication Method**: {ctx['authMethod']}")
    if ctx.get("dataSensitivity"):
        context_parts.append(f"**Data Sensitivity**: {ctx['dataSensitivity']}")
    if ctx.get("networkExposure"):
        context_parts.append(f"**Network Exposure**: {ctx['networkExposure']}")
    if ctx.get("complianceReqs"):
        context_parts.append(f"**Compliance Requirements**: {ctx['complianceReqs']}")
    if ctx.get("additionalNotes"):
        context_parts.append(f"**Additional Notes**: {ctx['additionalNotes']}")

    # .openhack.md content — free-form markdown from repo
    openhack_md = ctx.get("openhack_md", "")

    if not context_parts and not openhack_md:
        return ""

    sections = []
    if context_parts:
        sections.append(chr(10).join(context_parts))
    if openhack_md:
        sections.append(openhack_md)

    body = chr(10) + chr(10).join(sections)

    return f"""## Project Context (Use this to inform your analysis)

{body}

Use this context to:
- Understand the monorepo/project structure and focus on the right directories
- Prioritize findings based on data sensitivity and compliance requirements
- Consider the deployment environment when assessing severity
- Factor in authentication methods when evaluating auth-related vulnerabilities
- Pay special attention to any concerns mentioned in additional notes

"""
