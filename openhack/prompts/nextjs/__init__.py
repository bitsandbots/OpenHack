"""
Next.js vulnerability detection prompts, organized by attack type.
"""

from .idor import NEXTJS_IDOR_PROMPT
from .xss import NEXTJS_XSS_PROMPT
from .csrf import NEXTJS_CSRF_PROMPT
from .ssrf import NEXTJS_SSRF_PROMPT
from .injection import NEXTJS_INJECTION_PROMPT
from .auth_bypass import NEXTJS_AUTH_BYPASS_PROMPT
from .data_exposure import NEXTJS_DATA_EXPOSURE_PROMPT
from .middleware_bypass import NEXTJS_MIDDLEWARE_BYPASS_PROMPT
from .server_actions import NEXTJS_SERVER_ACTIONS_PROMPT
from .misconfiguration import NEXTJS_MISCONFIGURATION_PROMPT

# Assembled dictionary for code that looks up prompts by category key
NEXTJS_PROMPTS = {
    "idor": NEXTJS_IDOR_PROMPT,
    "xss": NEXTJS_XSS_PROMPT,
    "csrf": NEXTJS_CSRF_PROMPT,
    "ssrf": NEXTJS_SSRF_PROMPT,
    "injection": NEXTJS_INJECTION_PROMPT,
    "auth_bypass": NEXTJS_AUTH_BYPASS_PROMPT,
    "data_exposure": NEXTJS_DATA_EXPOSURE_PROMPT,
    "middleware_bypass": NEXTJS_MIDDLEWARE_BYPASS_PROMPT,
    "server_actions": NEXTJS_SERVER_ACTIONS_PROMPT,
    "misconfiguration": NEXTJS_MISCONFIGURATION_PROMPT,
}

__all__ = [
    "NEXTJS_PROMPTS",
    "NEXTJS_IDOR_PROMPT",
    "NEXTJS_XSS_PROMPT",
    "NEXTJS_CSRF_PROMPT",
    "NEXTJS_SSRF_PROMPT",
    "NEXTJS_INJECTION_PROMPT",
    "NEXTJS_AUTH_BYPASS_PROMPT",
    "NEXTJS_DATA_EXPOSURE_PROMPT",
    "NEXTJS_MIDDLEWARE_BYPASS_PROMPT",
    "NEXTJS_SERVER_ACTIONS_PROMPT",
    "NEXTJS_MISCONFIGURATION_PROMPT",
]
