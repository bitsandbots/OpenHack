"""
Exploit runner for sandbox verification.

Executes HTTP requests and scripts against a running sandboxed application.
Returns full response details so the agent can analyze whether the exploit worked.
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class ExploitResult:
    """Result of an exploit attempt."""
    success: bool
    status_code: Optional[int] = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed_ms: float = 0.0
    error: Optional[str] = None
    attempt: int = 1

    def to_dict(self) -> dict:
        d = {
            "success": self.success,
            "status_code": self.status_code,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "attempt": self.attempt,
        }
        if self.headers:
            # Only include security-relevant headers
            relevant = {}
            for k, v in self.headers.items():
                kl = k.lower()
                if kl in (
                    "content-type", "set-cookie", "location",
                    "x-powered-by", "server", "access-control-allow-origin",
                    "www-authenticate", "x-frame-options",
                    "content-security-policy", "x-content-type-options",
                ):
                    relevant[k] = v
            d["headers"] = relevant
        if self.body:
            d["body"] = self.body[:5000]  # Cap body size for context window
        if self.error:
            d["error"] = self.error
        return d


class ExploitRunner:
    """Executes exploit requests against a sandboxed application."""

    def __init__(self, base_url: str, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self._session = aiohttp.ClientSession(timeout=self.timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._session:
            await self._session.close()

    async def execute_request(
        self,
        method: str,
        path: str,
        headers: Optional[dict[str, str]] = None,
        body: Optional[str] = None,
        json_body: Optional[dict] = None,
        follow_redirects: bool = False,
        attempt: int = 1,
    ) -> ExploitResult:
        """Execute a single HTTP request against the sandbox."""
        url = f"{self.base_url}{path}" if path.startswith("/") else path

        if not self._session:
            self._session = aiohttp.ClientSession(timeout=self.timeout)

        start = time.time()
        try:
            kwargs: dict[str, Any] = {
                "method": method.upper(),
                "url": url,
                "headers": headers or {},
                "allow_redirects": follow_redirects,
            }

            if json_body is not None:
                kwargs["json"] = json_body
            elif body is not None:
                kwargs["data"] = body

            async with self._session.request(**kwargs) as resp:
                elapsed = (time.time() - start) * 1000
                resp_body = await resp.text()
                resp_headers = dict(resp.headers)

                return ExploitResult(
                    success=True,
                    status_code=resp.status,
                    headers=resp_headers,
                    body=resp_body,
                    elapsed_ms=elapsed,
                    attempt=attempt,
                )

        except asyncio.TimeoutError:
            return ExploitResult(
                success=False,
                error=f"Request timed out after {self.timeout.total}s",
                elapsed_ms=(time.time() - start) * 1000,
                attempt=attempt,
            )
        except aiohttp.ClientError as e:
            return ExploitResult(
                success=False,
                error=f"Connection error: {str(e)}",
                elapsed_ms=(time.time() - start) * 1000,
                attempt=attempt,
            )
        except Exception as e:
            return ExploitResult(
                success=False,
                error=f"Unexpected error: {str(e)}",
                elapsed_ms=(time.time() - start) * 1000,
                attempt=attempt,
            )

    async def execute_multi_step(
        self,
        steps: list[dict],
    ) -> list[ExploitResult]:
        """Execute a sequence of requests (for multi-step exploits).

        Each step is a dict with: method, path, headers, body/json_body.
        Later steps can reference earlier responses via {step_N_body} placeholders.
        """
        results: list[ExploitResult] = []

        for i, step in enumerate(steps):
            # Substitute placeholders from previous results
            step_str = json.dumps(step)
            for j, prev in enumerate(results):
                placeholder = f"{{step_{j}_body}}"
                if placeholder in step_str:
                    escaped = json.dumps(prev.body)[1:-1]  # Remove outer quotes
                    step_str = step_str.replace(placeholder, escaped)

            step = json.loads(step_str)

            result = await self.execute_request(
                method=step.get("method", "GET"),
                path=step.get("path", "/"),
                headers=step.get("headers"),
                body=step.get("body"),
                json_body=step.get("json_body"),
                follow_redirects=step.get("follow_redirects", False),
                attempt=i + 1,
            )
            results.append(result)

            # If a step fails at the connection level, stop the chain
            if not result.success:
                break

        return results
