"""
Validator swarm agent that spawns one sub-validator per finding.
"""

import asyncio
import logging
from typing import Optional

from .validator import ValidatorAgent
from .llm import LLMClient
from .session import Session
from openhack.tools.registry import ToolRegistry
from openhack.config import settings

logger = logging.getLogger(__name__)


class ValidatorSwarmAgent:
    name = "validator_swarm"
    description = "Validator swarm coordinator"

    def __init__(self, llm: LLMClient, tools: ToolRegistry, session: Session):
        self.llm = llm
        self.tools = tools
        self.session = session
        self.total_cost: float = 0.0
        self.total_tokens: int = 0
        self.total_input_tokens: int = 0
        self.total_output_tokens: int = 0

    def _create_llm_for_sub_validator(self) -> LLMClient:
        model = settings.validator_model_id or self.llm.model
        return LLMClient(model=model, temperature=0.0, max_tokens=8192, provider=self.llm.provider, prompt_cache_key=self.llm.prompt_cache_key)

    def _build_sub_context(self, finding: dict, full_context: dict) -> dict:
        return {
            "hunter": {"findings": [finding]},
            "recon": full_context.get("recon", {}),
            "project_context": full_context.get("project_context", {}),
        }

    async def run(self, task: str, context: Optional[dict] = None) -> dict:
        context = context or {}
        findings = context.get("hunter", {}).get("findings", [])

        if not findings:
            return {"raw_output": "No findings to validate", "validated_findings": [], "false_positives": [], "type": "validation_complete"}

        self.session.add_trace(agent=self.name, event_type="swarm_start", content={"findings_count": len(findings)})

        sub_validators: list[tuple[int, ValidatorAgent, dict]] = []
        for idx, finding in enumerate(findings):
            llm = self._create_llm_for_sub_validator()
            validator = ValidatorAgent(llm, self.tools, self.session, original_finding_index=idx)
            sub_context = self._build_sub_context(finding, context)
            sub_validators.append((idx, validator, sub_context))

        semaphore = asyncio.Semaphore(settings.max_concurrent_validators)

        async def run_sub_validator(finding_idx, validator, sub_context):
            async with semaphore:
                try:
                    sub_task = "Validate this potential vulnerability. Confirm whether it is real, generate a PoC, and suggest a fix."
                    result = await validator.run(sub_task, sub_context)
                    return finding_idx, result
                except Exception as e:
                    logger.error(f"Sub-validator for finding {finding_idx} failed: {e}")
                    return finding_idx, {"validated_findings": [], "false_positives": [], "type": "validation_failed"}

        tasks = [
            asyncio.create_task(run_sub_validator(idx, validator, sub_ctx))
            for idx, validator, sub_ctx in sub_validators
        ]
        try:
            results = await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

        all_validated: list[dict] = []
        all_false_positives: list[dict] = []

        for finding_idx, result in results:
            all_validated.extend(result.get("validated_findings", []))
            all_false_positives.extend(result.get("false_positives", []))

        for _, validator, _ in sub_validators:
            self.total_cost += validator.llm.total_cost
            self.total_tokens += validator.llm.total_tokens
            self.total_input_tokens += validator.llm.total_input_tokens
            self.total_output_tokens += validator.llm.total_output_tokens

        self.session.add_trace(
            agent=self.name, event_type="swarm_complete",
            content={"total_confirmed": len(all_validated), "total_false_positives": len(all_false_positives),
                     "total_cost": self.total_cost, "total_tokens": self.total_tokens},
        )

        return {
            "raw_output": f"Validated {len(findings)} findings: {len(all_validated)} confirmed, {len(all_false_positives)} false positives",
            "validated_findings": all_validated,
            "false_positives": all_false_positives,
            "type": "validation_complete",
        }
