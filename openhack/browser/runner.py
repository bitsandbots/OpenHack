"""
Browser runner for browser-based verification.

Drives a Playwright Chromium browser to verify vulnerabilities
that require real browser interaction. Counterpart to sandbox/runner.py.
"""

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class BrowserResult:
    """Result of a browser action."""
    success: bool
    page_url: str = ""
    page_title: str = ""
    page_content: str = ""
    console_logs: list[str] = field(default_factory=list)
    screenshot_path: Optional[str] = None
    elapsed_ms: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "success": self.success,
            "elapsed_ms": round(self.elapsed_ms, 1),
        }
        if self.page_url:
            d["page_url"] = self.page_url
        if self.page_title:
            d["page_title"] = self.page_title
        if self.page_content:
            d["page_content"] = self.page_content[:5000]
        if self.console_logs:
            d["console_logs"] = self.console_logs[-20:]
        if self.screenshot_path:
            d["screenshot_path"] = self.screenshot_path
        if self.error:
            d["error"] = self.error
        return d


class BrowserContext:
    """Isolated browser context for a single finding verification."""

    def __init__(self, context, page, evidence_dir: Path):
        self.context = context
        self.page = page
        self.evidence_dir = evidence_dir
        self.console_logs: list[str] = []
        self._screenshot_counter = 0

        page.on("console", lambda msg: self.console_logs.append(
            f"[{msg.type}] {msg.text}"
        ))

    @property
    def next_screenshot_index(self) -> int:
        self._screenshot_counter += 1
        return self._screenshot_counter

    async def close(self):
        try:
            await self.context.close()
        except Exception:
            pass


class BrowserRunner:
    """Drives a Playwright browser for exploit verification."""

    def __init__(
        self,
        base_url: str,
        evidence_dir: Path,
        headless: bool = True,
        timeout: int = 30000,
    ):
        try:
            from playwright.async_api import async_playwright  # noqa: F401
        except ImportError:
            raise ImportError(
                "Playwright is required for browser verification.\n"
                "Install with:\n"
                "  pip install playwright\n"
                "  playwright install chromium"
            )

        self.base_url = base_url.rstrip("/")
        self.evidence_dir = evidence_dir
        self.headless = headless
        self.timeout = timeout
        self._playwright = None
        self._browser = None

    async def __aenter__(self):
        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()
        try:
            self._browser = await self._playwright.chromium.launch(
                headless=self.headless,
            )
        except Exception as e:
            await self._playwright.stop()
            self._playwright = None
            raise RuntimeError(
                f"Failed to launch Chromium: {e}\n"
                "Run: playwright install chromium"
            ) from e
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()

    async def create_context(self, finding_index: int) -> "BrowserContext":
        ctx_evidence_dir = self.evidence_dir / f"finding_{finding_index}"
        ctx_evidence_dir.mkdir(parents=True, exist_ok=True)

        context = await self._browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1280, "height": 720},
        )
        context.set_default_timeout(self.timeout)
        page = await context.new_page()

        return BrowserContext(context, page, ctx_evidence_dir)

    async def navigate(
        self, ctx: BrowserContext, url: str, wait_until: str = "networkidle",
    ) -> BrowserResult:
        start = time.time()
        full_url = url if url.startswith("http") else f"{self.base_url}{url}"
        try:
            await ctx.page.goto(full_url, wait_until=wait_until)
            elapsed = (time.time() - start) * 1000
            snap = await self.snapshot(ctx)
            return BrowserResult(
                success=True,
                page_url=ctx.page.url,
                page_title=await ctx.page.title(),
                page_content=snap.get("snapshot", ""),
                console_logs=list(ctx.console_logs),
                elapsed_ms=elapsed,
            )
        except Exception as e:
            return BrowserResult(
                success=False,
                page_url=ctx.page.url,
                error=str(e),
                elapsed_ms=(time.time() - start) * 1000,
            )

    async def click(
        self, ctx: BrowserContext, selector: str, selector_type: str = "css",
    ) -> BrowserResult:
        start = time.time()
        click_error = None
        try:
            locator = self._resolve_locator(ctx, selector, selector_type)
            await locator.click()
            await ctx.page.wait_for_load_state("networkidle", timeout=5000)
        except Exception as e:
            click_error = str(e)

        try:
            elapsed = (time.time() - start) * 1000
            snap = await self.snapshot(ctx)
            return BrowserResult(
                success=click_error is None,
                page_url=ctx.page.url,
                page_title=await ctx.page.title(),
                page_content=snap.get("snapshot", ""),
                console_logs=list(ctx.console_logs),
                error=click_error,
                elapsed_ms=elapsed,
            )
        except Exception as e:
            return BrowserResult(
                success=False,
                page_url=ctx.page.url,
                error=f"Click failed: {click_error or e}",
                elapsed_ms=(time.time() - start) * 1000,
            )

    async def fill(
        self, ctx: BrowserContext, selector: str, value: str,
    ) -> BrowserResult:
        start = time.time()
        css = self._selector_to_css(selector)
        try:
            await ctx.page.fill(css, value)
            elapsed = (time.time() - start) * 1000
            return BrowserResult(
                success=True,
                page_url=ctx.page.url,
                elapsed_ms=elapsed,
            )
        except Exception as e:
            return BrowserResult(
                success=False,
                page_url=ctx.page.url,
                error=f"Fill failed: {e}",
                elapsed_ms=(time.time() - start) * 1000,
            )

    async def screenshot(
        self, ctx: BrowserContext, name: str,
    ) -> dict:
        idx = ctx.next_screenshot_index
        filename = f"{idx:02d}_{name}.png"
        path = ctx.evidence_dir / filename
        try:
            await ctx.page.screenshot(path=str(path), full_page=True)
            return {"path": str(path), "saved": True}
        except Exception as e:
            return {"path": "", "saved": False, "error": str(e)}

    async def get_content(
        self,
        ctx: BrowserContext,
        selector: Optional[str] = None,
        fmt: str = "text",
    ) -> dict:
        try:
            if selector:
                element = ctx.page.locator(selector)
                if fmt == "html":
                    content = await element.inner_html()
                else:
                    content = await element.inner_text()
            else:
                if fmt == "html":
                    content = await ctx.page.content()
                else:
                    content = await ctx.page.inner_text("body")
            return {"content": content[:5000], "url": ctx.page.url}
        except Exception as e:
            return {"content": "", "url": ctx.page.url, "error": str(e)}

    async def execute_js(
        self, ctx: BrowserContext, script: str,
    ) -> dict:
        try:
            result = await ctx.page.evaluate(script)
            serialized = json.dumps(result, default=str) if result is not None else "null"
            return {"result": serialized[:5000]}
        except Exception as e:
            return {"result": None, "error": str(e)}

    async def wait_for(
        self,
        ctx: BrowserContext,
        selector: str,
        timeout: int = 5000,
        state: str = "visible",
    ) -> dict:
        start = time.time()
        try:
            await ctx.page.wait_for_selector(selector, timeout=timeout, state=state)
            return {
                "found": True,
                "elapsed_ms": round((time.time() - start) * 1000, 1),
            }
        except Exception:
            return {
                "found": False,
                "elapsed_ms": round((time.time() - start) * 1000, 1),
            }

    async def get_cookies(self, ctx: BrowserContext) -> dict:
        try:
            cookies = await ctx.context.cookies()
            safe_cookies = []
            for c in cookies:
                safe_cookies.append({
                    "name": c.get("name"),
                    "domain": c.get("domain"),
                    "path": c.get("path"),
                    "httpOnly": c.get("httpOnly"),
                    "secure": c.get("secure"),
                    "sameSite": c.get("sameSite"),
                    "expires": c.get("expires"),
                })
            return {"cookies": safe_cookies}
        except Exception as e:
            return {"cookies": [], "error": str(e)}

    async def snapshot(self, ctx: BrowserContext) -> dict:
        """Tag every interactive element with @eN refs and return a compact map.

        After calling this, the agent can use refs like @e3 in click/fill instead
        of guessing CSS selectors. Refs persist on the page until the next snapshot
        or navigation.
        """
        snapshot_js = r"""
        (() => {
            document.querySelectorAll('[data-openhack-ref]').forEach(el => el.removeAttribute('data-openhack-ref'));
            const sel = 'a[href], button, input, textarea, select, '
              + '[role="button"], [role="link"], [role="checkbox"], [role="radio"], '
              + '[role="textbox"], [role="combobox"], [role="menuitem"], [role="tab"], '
              + '[onclick], [contenteditable="true"]';
            const els = document.querySelectorAll(sel);
            const out = [];
            let n = 0;
            for (const el of els) {
                const rect = el.getBoundingClientRect();
                const style = getComputedStyle(el);
                if (rect.width === 0 && rect.height === 0) continue;
                if (style.display === 'none' || style.visibility === 'hidden') continue;
                n++;
                const ref = 'e' + n;
                el.setAttribute('data-openhack-ref', ref);
                const text = ((el.innerText || '').trim()
                              || el.value
                              || el.placeholder
                              || el.getAttribute('aria-label')
                              || el.getAttribute('title')
                              || '').toString().replace(/\s+/g, ' ').slice(0, 80);
                out.push({
                    ref: '@' + ref,
                    tag: el.tagName.toLowerCase(),
                    type: el.type || '',
                    role: el.getAttribute('role') || '',
                    name: el.name || el.id || '',
                    text,
                    href: el.tagName === 'A' ? (el.getAttribute('href') || '') : '',
                });
            }
            return {count: n, elements: out, url: location.href, title: document.title};
        })()
        """

        try:
            result = await ctx.page.evaluate(snapshot_js)
        except Exception as e:
            return {"snapshot": "", "count": 0, "error": str(e)}

        lines = [f"Page: {result['title']} ({result['url']})"]
        lines.append(f"{result['count']} interactive element(s):")
        for el in result["elements"]:
            parts = [el["ref"], f"<{el['tag']}"]
            if el["type"]:
                parts.append(f"type={el['type']!r}")
            if el["role"]:
                parts.append(f"role={el['role']!r}")
            if el["name"]:
                parts.append(f"name={el['name']!r}")
            if el["href"]:
                parts.append(f"href={el['href']!r}")
            head = " ".join(parts) + ">"
            tail = f' "{el["text"]}"' if el["text"] else ""
            lines.append(f"  {head}{tail}")

        return {
            "snapshot": "\n".join(lines),
            "count": result["count"],
            "url": result["url"],
        }

    def _selector_to_css(self, selector: str) -> str:
        """Convert a @eN ref to a [data-openhack-ref=eN] CSS selector. Pass-through otherwise."""
        if selector.startswith("@e") and selector[2:].isdigit():
            return f'[data-openhack-ref="{selector[1:]}"]'
        return selector

    def _resolve_locator(self, ctx: BrowserContext, selector: str, selector_type: str):
        if selector.startswith("@e") and selector[2:].isdigit():
            return ctx.page.locator(f'[data-openhack-ref="{selector[1:]}"]')
        if selector_type == "text":
            return ctx.page.get_by_text(selector)
        elif selector_type == "role":
            return ctx.page.get_by_role(selector)
        else:
            return ctx.page.locator(selector)
