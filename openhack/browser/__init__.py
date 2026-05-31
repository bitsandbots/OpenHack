"""
Browser-based verification layer for OpenHack.

Drives a headless Chromium browser via Playwright to verify
vulnerabilities that require real browser interaction: XSS
confirmation via DOM inspection, CSRF token handling, login
flows, multi-step UI interactions, and screenshot evidence.
"""

from .runner import BrowserRunner, BrowserResult

__all__ = ["BrowserRunner", "BrowserResult"]
