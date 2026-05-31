"""
Flask vulnerability detection prompts, organized by attack type.
"""

from .injection import FLASK_INJECTION_PROMPT
from .auth_bypass import FLASK_AUTH_BYPASS_PROMPT
from .idor import FLASK_IDOR_PROMPT
from .ssrf import FLASK_SSRF_PROMPT
from .data_exposure import FLASK_DATA_EXPOSURE_PROMPT
from .misconfiguration import FLASK_MISCONFIGURATION_PROMPT

FLASK_PROMPTS = {
    "injection": FLASK_INJECTION_PROMPT,
    "auth_bypass": FLASK_AUTH_BYPASS_PROMPT,
    "idor": FLASK_IDOR_PROMPT,
    "ssrf": FLASK_SSRF_PROMPT,
    "data_exposure": FLASK_DATA_EXPOSURE_PROMPT,
    "misconfiguration": FLASK_MISCONFIGURATION_PROMPT,
}

__all__ = [
    "FLASK_PROMPTS",
    "FLASK_INJECTION_PROMPT",
    "FLASK_AUTH_BYPASS_PROMPT",
    "FLASK_IDOR_PROMPT",
    "FLASK_SSRF_PROMPT",
    "FLASK_DATA_EXPOSURE_PROMPT",
    "FLASK_MISCONFIGURATION_PROMPT",
]
