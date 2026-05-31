"""
Express.js vulnerability detection prompts, organized by attack type.
"""

from .injection import EXPRESS_INJECTION_PROMPT
from .auth_bypass import EXPRESS_AUTH_BYPASS_PROMPT
from .idor import EXPRESS_IDOR_PROMPT
from .ssrf import EXPRESS_SSRF_PROMPT
from .data_exposure import EXPRESS_DATA_EXPOSURE_PROMPT
from .misconfiguration import EXPRESS_MISCONFIGURATION_PROMPT

EXPRESS_PROMPTS = {
    "injection": EXPRESS_INJECTION_PROMPT,
    "auth_bypass": EXPRESS_AUTH_BYPASS_PROMPT,
    "idor": EXPRESS_IDOR_PROMPT,
    "ssrf": EXPRESS_SSRF_PROMPT,
    "data_exposure": EXPRESS_DATA_EXPOSURE_PROMPT,
    "misconfiguration": EXPRESS_MISCONFIGURATION_PROMPT,
}

__all__ = [
    "EXPRESS_PROMPTS",
    "EXPRESS_INJECTION_PROMPT",
    "EXPRESS_AUTH_BYPASS_PROMPT",
    "EXPRESS_IDOR_PROMPT",
    "EXPRESS_SSRF_PROMPT",
    "EXPRESS_DATA_EXPOSURE_PROMPT",
    "EXPRESS_MISCONFIGURATION_PROMPT",
]
