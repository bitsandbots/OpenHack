"""
Deterministic quality gates for scan findings.

These run AFTER validation and BEFORE final report generation.
No LLM calls -- pure code logic.
"""

from __future__ import annotations

import re
from typing import Optional

from openhack.categories import normalize_category

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_NAMES = {v: k for k, v in SEVERITY_ORDER.items()}

_GENERIC_SEGMENTS: set[str] = {
    "src", "app", "apps", "api", "v1", "v2", "v3",
    "modules", "controllers", "handlers", "routes", "routers",
    "lib", "libs", "utils", "helpers", "common", "shared",
    "pages", "components", "services", "middleware",
    "server", "client", "core", "internal", "external",
    "pkg", "packages", "node_modules", "dist", "build",
    "ee", "ce", "oss", "pro", "test", "tests", "spec",
    "config", "configs", "types", "interfaces", "models",
    "index", "main", "setup", "init",
    "organizations", "org", "orgs",
    "callback", "callbacks", "appstore", "extensions",
    "actions", "events", "webhooks", "hooks",
    "auth", "oauth", "sso", "saml", "oidc",
    "store", "stores", "plugin", "plugins",
    "provider", "providers", "adapter", "adapters",
    "handler", "listener", "worker", "workers",
    "schema", "schemas", "migration", "migrations",
}

_CHAINED_VULN_PHRASES: list[str] = [
    "via xss", "requires xss", "through xss",
    "via subdomain takeover", "subdomain control", "requires subdomain",
    "via mitm", "man-in-the-middle", "requires mitm",
    "via another vulnerability", "requires another vulnerability",
    "malicious browser extension", "ability to set cookies",
    "ability to set a cookie", "cookie manipulation",
    "via dns rebinding", "dns rebinding",
    "local malware", "via local code execution", "requires local access",
]

_DEPRECATION_RES: list[re.Pattern] = [
    re.compile(r"@deprecated", re.IGNORECASE),
    re.compile(r"\bdeprecated\b", re.IGNORECASE),
    re.compile(r"todo[:\s]+(remove|migrate|replace|switch)", re.IGNORECASE),
    re.compile(r"will be removed", re.IGNORECASE),
    re.compile(r"no longer (supported|recommended)", re.IGNORECASE),
    re.compile(r"use .{3,40} instead", re.IGNORECASE),
    re.compile(r"security[:\s]+warn", re.IGNORECASE),
]


def _extract_significant_segments(file_path: str) -> set[str]:
    parts = file_path.lower().replace("\\", "/").split("/")
    if parts:
        last = parts[-1]
        dot = last.rfind(".")
        if dot > 0:
            last = last[:dot]
        parts[-1] = last

    significant: set[str] = set()
    for part in parts:
        cleaned = part.strip().replace("-", "").replace("_", "")
        if cleaned and cleaned not in _GENERIC_SEGMENTS and len(cleaned) > 2:
            significant.add(cleaned)
    return significant


def _segments_share_integration(segs_a: set[str], segs_b: set[str]) -> bool:
    for a in segs_a:
        for b in segs_b:
            if a == b:
                return True
            shorter, longer = (a, b) if len(a) <= len(b) else (b, a)
            if len(shorter) >= 5 and shorter in longer:
                return True
    return False


def cross_file_dedup(
    validated: list[dict],
    potential_findings: list[dict],
) -> list[dict]:
    n = len(validated)
    if n <= 1:
        return validated

    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        pa, pb = find(a), find(b)
        if pa != pb:
            parent[pa] = pb

    meta: list[tuple[str, set[str]]] = []
    for v in validated:
        idx = v.get("original_index")
        if idx is not None and 0 <= idx < len(potential_findings):
            orig = potential_findings[idx]
            cat = normalize_category(orig.get("category", "")).lower()
            segs = _extract_significant_segments(orig.get("file_path", ""))
        else:
            cat, segs = "", set()
        meta.append((cat, segs))

    for i in range(n):
        for j in range(i + 1, n):
            cat_i, segs_i = meta[i]
            cat_j, segs_j = meta[j]
            if cat_i and cat_i == cat_j and _segments_share_integration(segs_i, segs_j):
                union(i, j)

    groups: dict[int, list[int]] = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(i)

    result: list[dict] = []
    for indices in groups.values():
        if len(indices) == 1:
            result.append(validated[indices[0]])
        else:
            best = min(indices, key=lambda i: (
                SEVERITY_ORDER.get(
                    (potential_findings[validated[i].get("original_index", 0)].get("severity") or "info").lower(), 4
                ),
                -len(potential_findings[validated[i].get("original_index", 0)].get("description") or ""),
            ))
            result.append(validated[best])

    return result


def has_chained_prerequisite(finding: dict) -> bool:
    text = " ".join([
        (finding.get("description") or ""),
        (finding.get("code_snippet") or ""),
        (finding.get("poc") or ""),
    ]).lower()

    for phrase in _CHAINED_VULN_PHRASES:
        if phrase in text:
            return True
    return False


def has_deprecation_marker(
    file_path: str,
    line_number: Optional[int],
    fs_tools,
) -> bool:
    if not fs_tools or not file_path:
        return False

    if file_path.startswith(("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "http")):
        return False

    try:
        if line_number and line_number > 0:
            offset = max(0, line_number - 10)
            result = fs_tools.read_file(file_path, offset=offset, limit=20)
        else:
            result = fs_tools.read_file(file_path, offset=0, limit=30)

        content = result.get("content", "")
        if not content:
            return False

        for pattern in _DEPRECATION_RES:
            if pattern.search(content):
                return True
    except Exception:
        pass

    return False


def run_quality_gates(
    validated: list[dict],
    potential_findings: list[dict],
    fs_tools=None,
) -> tuple[list[dict], dict]:
    stats = {
        "input_count": len(validated),
        "cross_file_dedup_removed": 0,
        "chained_prereq_downgraded": 0,
        "deprecated_downgraded": 0,
    }

    deduped = cross_file_dedup(validated, potential_findings)
    stats["cross_file_dedup_removed"] = len(validated) - len(deduped)

    for v in deduped:
        idx = v.get("original_index")
        if idx is None or idx < 0 or idx >= len(potential_findings):
            continue
        orig = potential_findings[idx]
        current_sev = SEVERITY_ORDER.get(
            (orig.get("severity") or "info").lower(), 4
        )

        if current_sev < 3 and has_chained_prerequisite(orig):
            orig["severity"] = "low"
            orig["_quality_note"] = "Downgraded: requires pre-existing vulnerability to exploit"
            stats["chained_prereq_downgraded"] += 1
            continue

        if current_sev < 3 and has_deprecation_marker(
            orig.get("file_path", ""),
            orig.get("line_number"),
            fs_tools,
        ):
            orig["severity"] = "low"
            orig["_quality_note"] = "Downgraded: code already has deprecation markers"
            stats["deprecated_downgraded"] += 1

    stats["output_count"] = len(deduped)
    return deduped, stats
