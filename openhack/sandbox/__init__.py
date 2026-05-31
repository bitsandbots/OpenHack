"""
Sandbox verification layer for OpenHack.

Spins up target applications in Docker containers and runs
exploit PoCs against them to confirm vulnerabilities with
real execution evidence.
"""

from .orchestrator import SandboxOrchestrator
from .runner import ExploitRunner

__all__ = ["SandboxOrchestrator", "ExploitRunner"]
