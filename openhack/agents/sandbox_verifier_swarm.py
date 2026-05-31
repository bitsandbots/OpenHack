"""
Sandbox verifier swarm agent.

Spawns one sandbox verifier per confirmed finding and runs them concurrently
against the live sandboxed application. All verifiers share the same sandbox
instance — the app is started once and torn down after all verifiers finish.
"""

import asyncio
import logging
from typing import Optional

from .sandbox_verifier import SandboxVerifierAgent
from .llm import LLMClient
from .session import Session
from ..sandbox.orchestrator import SandboxOrchestrator, SandboxConfig
from ..sandbox.runner import ExploitRunner
from openhack.tools.registry import ToolRegistry
from openhack.config import settings

logger = logging.getLogger(__name__)


class SandboxVerifierSwarmAgent:
    """Runs sandbox verification for all confirmed findings concurrently."""

    name = "sandbox_verifier_swarm"
    description = "Sandbox exploit verification swarm"

    def __init__(
        self,
        llm: LLMClient,
        tools: ToolRegistry,
        session: Session,
        sandbox_config: Optional[SandboxConfig] = None,
    ):
        self.llm = llm
        self.tools = tools
        self.session = session
        self.sandbox_config = sandbox_config
        self.total_cost: float = 0.0
        self.total_tokens: int = 0
        self.total_input_tokens: int = 0
        self.total_output_tokens: int = 0

    def _create_llm_for_verifier(self) -> LLMClient:
        model = self.llm.model
        return LLMClient(model=model, temperature=0.0, max_tokens=8192, provider=self.llm.provider, prompt_cache_key=self.llm.prompt_cache_key)

    async def run(self, task: str, context: Optional[dict] = None) -> dict:
        context = context or {}
        findings = context.get("confirmed_findings", [])

        if not findings:
            return {
                "raw_output": "No findings to verify in sandbox",
                "exploitable": [],
                "not_exploitable": [],
                "type": "sandbox_verification_complete",
            }

        self.session.add_trace(
            agent=self.name, event_type="swarm_start",
            content={"findings_count": len(findings)},
        )

        target_dir = self.tools.target_dir
        orchestrator = SandboxOrchestrator(target_dir, self.sandbox_config)

        self.session.add_trace(
            agent=self.name, event_type="sandbox_starting",
            content="Building and starting sandbox containers…",
        )

        try:
            sandbox_status = await orchestrator.start()
            sandbox_url = sandbox_status.base_url

            self.session.add_trace(
                agent=self.name, event_type="sandbox_ready",
                content={"base_url": sandbox_url, "host_port": sandbox_status.host_port},
            )

            # Create exploit runner
            async with ExploitRunner(sandbox_url) as runner:
                # Spawn verifiers
                semaphore = asyncio.Semaphore(settings.max_concurrent_validators)
                # Fail-fast: if N consecutive verifiers crash with the same
                # error (e.g. "Insufficient credits"), abort the remaining
                # ones rather than burning through all findings silently.
                FAIL_FAST_THRESHOLD = 3
                abort_event = asyncio.Event()
                error_streak: list[str] = []
                fatal_error: Optional[str] = None

                async def run_verifier(idx: int, finding: dict) -> tuple[int, dict]:
                    nonlocal fatal_error
                    verifier_name = f"sandbox_verifier:finding_{idx}"
                    self.session.add_trace(
                        agent=verifier_name, event_type="queued",
                        content={"finding_index": idx, "title": finding.get("title", "")},
                    )

                    if abort_event.is_set():
                        self.session.add_trace(
                            agent=verifier_name, event_type="skipped",
                            content="Skipped — swarm aborted due to repeated failures",
                        )
                        llm = self._create_llm_for_verifier()
                        return idx, {
                            "exploit_result": {
                                "finding_index": idx, "status": "skipped",
                                "confidence": "none", "evidence": "Aborted",
                                "attempts_made": 0, "reason": fatal_error or "Aborted",
                            },
                            "type": "sandbox_verification_skipped",
                        }, llm

                    async with semaphore:
                        if abort_event.is_set():
                            self.session.add_trace(
                                agent=verifier_name, event_type="skipped",
                                content="Skipped — swarm aborted due to repeated failures",
                            )
                            llm = self._create_llm_for_verifier()
                            return idx, {
                                "exploit_result": {
                                    "finding_index": idx, "status": "skipped",
                                    "confidence": "none", "evidence": "Aborted",
                                    "attempts_made": 0, "reason": fatal_error or "Aborted",
                                },
                                "type": "sandbox_verification_skipped",
                            }, llm

                        llm = self._create_llm_for_verifier()
                        verifier = SandboxVerifierAgent(
                            llm, self.tools, self.session,
                            sandbox_url=sandbox_url,
                            exploit_runner=runner,
                            sandbox_orchestrator=orchestrator,
                            finding_index=idx,
                            max_attempts=settings.sandbox_max_exploit_attempts,
                        )
                        try:
                            sub_context = {
                                "finding": finding,
                                "project_context": context.get("project_context", {}),
                            }
                            result = await verifier.run(
                                "Verify this vulnerability by exploiting it in the sandbox.",
                                context=sub_context,
                            )
                            error_streak.clear()
                            return idx, result, llm
                        except Exception as e:
                            error_msg = str(e)
                            logger.error(f"Sandbox verifier for finding {idx} failed: {e}")
                            self.session.add_trace(
                                agent=verifier_name, event_type="error",
                                content=f"Verifier crashed: {e}",
                            )
                            error_streak.append(error_msg)
                            if (
                                len(error_streak) >= FAIL_FAST_THRESHOLD
                                and len(set(error_streak[-FAIL_FAST_THRESHOLD:])) == 1
                            ):
                                fatal_error = error_msg
                                abort_event.set()
                                self.session.add_trace(
                                    agent=self.name, event_type="swarm_aborted",
                                    content=(
                                        f"Aborting: {FAIL_FAST_THRESHOLD} consecutive "
                                        f"verifiers failed with: {error_msg}"
                                    ),
                                )
                            return idx, {
                                "exploit_result": {
                                    "finding_index": idx,
                                    "status": "not_exploitable",
                                    "confidence": "low",
                                    "evidence": f"Verifier crashed: {error_msg}",
                                    "attempts_made": 0,
                                    "reason": "Internal error",
                                },
                                "type": "sandbox_verification_failed",
                            }, llm

                tasks = [
                    asyncio.create_task(run_verifier(idx, finding))
                    for idx, finding in enumerate(findings)
                ]

                try:
                    results = await asyncio.gather(*tasks)
                except asyncio.CancelledError:
                    for t in tasks:
                        t.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
                    raise

            # Collect results
            exploitable = []
            not_exploitable = []

            for idx, result, llm_client in results:
                self.total_cost += llm_client.total_cost
                self.total_tokens += llm_client.total_tokens
                self.total_input_tokens += llm_client.total_input_tokens
                self.total_output_tokens += llm_client.total_output_tokens

                exploit_result = result.get("exploit_result") if result else None
                if not exploit_result:
                    not_exploitable.append({"finding_index": idx, "status": "error", "confidence": "low"})
                    continue
                if exploit_result.get("status") == "exploitable":
                    exploitable.append(exploit_result)
                else:
                    not_exploitable.append(exploit_result)

            self.session.add_trace(
                agent=self.name, event_type="swarm_complete",
                content={
                    "total_exploitable": len(exploitable),
                    "total_not_exploitable": len(not_exploitable),
                    "total_cost": self.total_cost,
                    "total_tokens": self.total_tokens,
                    "fatal_error": fatal_error,
                },
            )

            result_dict = {
                "raw_output": (
                    f"Sandbox verification complete: {len(exploitable)} exploitable, "
                    f"{len(not_exploitable)} not exploitable out of {len(findings)} findings"
                ),
                "exploitable": exploitable,
                "not_exploitable": not_exploitable,
                "type": "sandbox_verification_complete",
            }
            if fatal_error:
                result_dict["fatal_error"] = fatal_error
            return result_dict

        finally:
            # Always tear down the sandbox
            self.session.add_trace(
                agent=self.name, event_type="sandbox_teardown",
                content="Stopping sandbox containers",
            )
            await orchestrator.stop()
