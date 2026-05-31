"""
Reconnaissance agent for mapping application structure.
"""

from .base import BaseAgent
from openhack.prompts import RECON_PROMPT, format_project_context


class ReconAgent(BaseAgent):
    name = "recon"
    description = "Reconnaissance - mapping application structure"

    def get_system_prompt(self, context: dict) -> str:
        project_context = context.get("project_context", {})
        project_context_str = format_project_context(project_context)
        return RECON_PROMPT.format(project_context=project_context_str)

    def _parse_final_response(self, content: str) -> dict:
        return {"summary": content, "type": "recon_complete"}
