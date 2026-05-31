"""
Django vulnerability detection prompts, organized by attack type.
"""

from .injection import DJANGO_INJECTION_PROMPT
from .auth_bypass import DJANGO_AUTH_BYPASS_PROMPT
from .idor import DJANGO_IDOR_PROMPT
from .csrf import DJANGO_CSRF_PROMPT
from .data_exposure import DJANGO_DATA_EXPOSURE_PROMPT
from .ssrf import DJANGO_SSRF_PROMPT
from .misconfiguration import DJANGO_MISCONFIGURATION_PROMPT

DJANGO_PROMPTS = {
    "injection": DJANGO_INJECTION_PROMPT,
    "auth_bypass": DJANGO_AUTH_BYPASS_PROMPT,
    "idor": DJANGO_IDOR_PROMPT,
    "csrf": DJANGO_CSRF_PROMPT,
    "data_exposure": DJANGO_DATA_EXPOSURE_PROMPT,
    "ssrf": DJANGO_SSRF_PROMPT,
    "misconfiguration": DJANGO_MISCONFIGURATION_PROMPT,
}

__all__ = [
    "DJANGO_PROMPTS",
    "DJANGO_INJECTION_PROMPT",
    "DJANGO_AUTH_BYPASS_PROMPT",
    "DJANGO_IDOR_PROMPT",
    "DJANGO_CSRF_PROMPT",
    "DJANGO_DATA_EXPOSURE_PROMPT",
    "DJANGO_SSRF_PROMPT",
    "DJANGO_MISCONFIGURATION_PROMPT",
]
