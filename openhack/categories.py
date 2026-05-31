"""
Canonical vulnerability categories.

Every finding reported by the scanner MUST use one of these exact category
strings.  This eliminates the cross-scan drift where the LLM invents
slightly different labels for the same vulnerability class.

The `normalize_category` function maps freeform LLM output to the closest
canonical category using keyword matching.
"""

from __future__ import annotations

CATEGORIES: list[str] = [
    "SQL Injection",
    "Command Injection",
    "XSS",
    "SSRF",
    "Open Redirect",
    "Path Traversal",
    "IDOR",
    "Authentication Bypass",
    "Authorization Bypass",
    "CSRF",
    "Data Exposure",
    "Information Disclosure",
    "Hardcoded Secret",
    "Security Misconfiguration",
    "Missing RLS",
    "RPC Function Abuse",
    "Storage Misconfiguration",
    "Mass Assignment",
    "Business Logic Flaw",
    "Denial of Service",
    "RCE",
]

_CANONICAL_LOWER: dict[str, str] = {c.lower(): c for c in CATEGORIES}

_KEYWORD_MAP: list[tuple[set[str], str]] = [
    ({"sqli", "sql injection", "sql inject"}, "SQL Injection"),
    ({"command injection", "command inject", "child_process", "exec injection", "rce", "remote code"}, "RCE"),
    ({"xss", "cross-site scripting", "cross site scripting", "dangerouslysetinnerhtml", "innerhtml"}, "XSS"),
    ({"ssrf", "server-side request", "server side request"}, "SSRF"),
    ({"open redirect", "redirect", "returnto", "redirectto", "callbackurl"}, "Open Redirect"),
    ({"path traversal", "directory traversal", "lfi", "local file inclusion"}, "Path Traversal"),
    ({"idor", "insecure direct object", "broken object level"}, "IDOR"),
    ({"authentication bypass", "auth bypass", "broken authentication"}, "Authentication Bypass"),
    ({"authorization bypass", "broken access", "missing authorization", "privilege escalation", "access control"}, "Authorization Bypass"),
    ({"csrf", "cross-site request forgery", "cross site request forgery"}, "CSRF"),
    ({"missing rls", "row level security", "rls policy", "cross-tenant", "tenant isolation", "missing delete policy"}, "Missing RLS"),
    ({"data exposure", "data leak", "pii exposure", "sensitive data", "token exposure",
      "credential exposure", "plaintext", "write access"}, "Data Exposure"),
    ({"information disclosure", "info disclosure", "verbose error", "error message", "stack trace"}, "Information Disclosure"),
    ({"hardcoded secret", "hardcoded credential", "hardcoded key", "hardcoded password", "embedded secret"}, "Hardcoded Secret"),
    ({"misconfiguration", "security header", "cors", "missing header", "insecure config",
      "insecure documentation", "auth misconfiguration"}, "Security Misconfiguration"),
    ({"rpc function", "rpc abuse", "security definer"}, "RPC Function Abuse"),
    ({"storage misconfiguration", "storage bucket", "storage policy", "public bucket", "insecure storage"}, "Storage Misconfiguration"),
    ({"mass assignment", "over-posting", "parameter pollution"}, "Mass Assignment"),
    ({"business logic", "logic flaw", "logic error", "race condition",
      "broken functionality"}, "Business Logic Flaw"),
    ({"denial of service", "dos", "redos", "resource exhaustion",
      "rate limit", "missing rate"}, "Denial of Service"),
]

CATEGORY_SEVERITY: dict[str, str] = {
    "SQL Injection":            "critical",
    "Command Injection":        "critical",
    "RCE":                      "critical",
    "Authentication Bypass":   "critical",
    "Missing RLS":              "critical",
    "SSRF":                     "high",
    "Path Traversal":           "high",
    "IDOR":                     "high",
    "Authorization Bypass":     "high",
    "Hardcoded Secret":         "high",
    "Data Exposure":            "high",
    "RPC Function Abuse":       "high",
    "Storage Misconfiguration": "high",
    "Open Redirect":            "medium",
    "XSS":                      "medium",
    "CSRF":                     "medium",
    "Mass Assignment":          "medium",
    "Business Logic Flaw":      "medium",
    "Denial of Service":        "medium",
    "Information Disclosure":   "low",
    "Security Misconfiguration":"medium",
}


def normalize_severity(
    findings: list[dict],
    *,
    use_category_default: bool = True,
) -> list[dict]:
    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    SEVERITY_NAMES = {v: k for k, v in SEVERITY_ORDER.items()}

    out = [dict(f) for f in findings]

    for i, f in enumerate(out):
        canonical = normalize_category(f.get("category", ""))
        current = SEVERITY_ORDER.get((f.get("severity") or "info").lower(), 4)

        if use_category_default:
            default_sev = SEVERITY_ORDER.get(
                CATEGORY_SEVERITY.get(canonical, "medium").lower(), 2
            )
            if current > default_sev:
                out[i]["severity"] = SEVERITY_NAMES[default_sev]

    return out


def normalize_category(raw: str) -> str:
    if not raw:
        return "Security Misconfiguration"

    lower = raw.strip().lower()

    if lower in _CANONICAL_LOWER:
        return _CANONICAL_LOWER[lower]

    for keywords, canonical in _KEYWORD_MAP:
        for kw in keywords:
            if kw in lower:
                return canonical

    return raw.strip().title()
