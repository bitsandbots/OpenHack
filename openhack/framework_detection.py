"""
Deterministic framework detection for vulnerability scanning.

Detects the tech stack of a target repository by reading indicator files
(package.json, manage.py, requirements.txt, etc.) and returns a list of
detected frameworks with their root directories. Supports monorepos where
multiple frameworks live in different subdirectories.

No LLM calls -- pure file existence + content checks.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from openhack.tools.filesystem import FileSystemTools


SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "venv", ".venv",
    "dist", "build", ".next", "coverage", ".nyc_output",
    "vendor", ".tox", "egg-info", ".eggs",
}


def _read_raw(fs: FileSystemTools, path: str) -> str | None:
    """Read a file via FileSystemTools and return raw content (no line numbers)."""
    result = fs.read_file(path)
    if "error" in result:
        return None
    lines = result["content"].split("\n")
    return "\n".join(
        line.split("\t", 1)[1] if "\t" in line else line for line in lines
    )


def _parse_json(fs: FileSystemTools, path: str) -> dict | None:
    raw = _read_raw(fs, path)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None


def _dir_of(path: str) -> str:
    """Return the parent directory of a file path, or '.' for root-level files."""
    parent = str(Path(path).parent)
    return "." if parent == "." or parent == "" else parent


def _glob_no_skip(fs: FileSystemTools, pattern: str) -> list[str]:
    """Glob for files, filtering out matches inside SKIP_DIRS."""
    result = fs.glob(pattern)
    if "error" in result:
        return []
    matches = []
    for m in result.get("matches", []):
        parts = Path(m).parts
        if not SKIP_DIRS.intersection(parts):
            matches.append(m)
    return matches


def _detect_nextjs(fs: FileSystemTools) -> list[dict]:
    """Detect Next.js projects by next.config.* or 'next' in package.json deps."""
    found: list[dict] = []
    seen_roots: set[str] = set()

    for config_name in ("next.config.js", "next.config.ts", "next.config.mjs"):
        for match in _glob_no_skip(fs, f"**/{config_name}"):
            root = _dir_of(match)
            if root not in seen_roots:
                seen_roots.add(root)
                found.append({"framework": "nextjs", "root": root})

    for pkg_path in _glob_no_skip(fs, "**/package.json"):
        root = _dir_of(pkg_path)
        if root in seen_roots:
            continue
        pkg = _parse_json(fs, pkg_path)
        if pkg is None:
            continue
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
        if "next" in deps:
            seen_roots.add(root)
            found.append({"framework": "nextjs", "root": root})

    return found


def _detect_express(fs: FileSystemTools) -> list[dict]:
    """Detect Express.js projects by 'express' in package.json deps."""
    found: list[dict] = []
    seen_roots: set[str] = set()

    for pkg_path in _glob_no_skip(fs, "**/package.json"):
        root = _dir_of(pkg_path)
        if root in seen_roots:
            continue
        pkg = _parse_json(fs, pkg_path)
        if pkg is None:
            continue
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
        if "express" in deps:
            seen_roots.add(root)
            found.append({"framework": "express", "root": root})

    return found


def _detect_django(fs: FileSystemTools) -> list[dict]:
    """Detect Django by manage.py + django in Python dependency files."""
    found: list[dict] = []
    seen_roots: set[str] = set()

    for manage_path in _glob_no_skip(fs, "**/manage.py"):
        root = _dir_of(manage_path)
        if root in seen_roots:
            continue

        content = _read_raw(fs, manage_path)
        if content and "django" not in content.lower():
            continue

        has_django_dep = False
        for dep_file in ("requirements.txt", "Pipfile", "pyproject.toml", "setup.cfg"):
            dep_path = f"{root}/{dep_file}" if root != "." else dep_file
            dep_content = _read_raw(fs, dep_path)
            if dep_content and re.search(r"django", dep_content, re.IGNORECASE):
                has_django_dep = True
                break

        if not has_django_dep:
            settings_matches = _glob_no_skip(fs, f"{'**/' if root == '.' else root + '/'}**/settings.py")
            if settings_matches:
                has_django_dep = True

        if has_django_dep:
            seen_roots.add(root)
            found.append({"framework": "django", "root": root})

    return found


def _detect_flask(fs: FileSystemTools) -> list[dict]:
    """Detect Flask by dependency files or app = Flask( pattern."""
    found: list[dict] = []
    seen_roots: set[str] = set()

    for dep_file in ("requirements.txt", "Pipfile", "pyproject.toml", "setup.cfg"):
        for dep_path in _glob_no_skip(fs, f"**/{dep_file}"):
            root = _dir_of(dep_path)
            if root in seen_roots:
                continue
            content = _read_raw(fs, dep_path)
            if content and re.search(r"(?:^|\s|['\"])flask(?:\s|['\"><=,\[]|$)", content, re.IGNORECASE | re.MULTILINE):
                seen_roots.add(root)
                found.append({"framework": "flask", "root": root})

    return found


def _detect_rails(fs: FileSystemTools) -> list[dict]:
    """Detect Rails by Gemfile with 'rails' or config/routes.rb."""
    found: list[dict] = []
    seen_roots: set[str] = set()

    for gemfile_path in _glob_no_skip(fs, "**/Gemfile"):
        root = _dir_of(gemfile_path)
        if root in seen_roots:
            continue
        content = _read_raw(fs, gemfile_path)
        if content and re.search(r"['\"]rails['\"]", content):
            seen_roots.add(root)
            found.append({"framework": "rails", "root": root})

    for routes_path in _glob_no_skip(fs, "**/config/routes.rb"):
        root = str(Path(_dir_of(routes_path)).parent)
        if root == "":
            root = "."
        if root not in seen_roots:
            seen_roots.add(root)
            found.append({"framework": "rails", "root": root})

    return found


def _detect_spring(fs: FileSystemTools) -> list[dict]:
    """Detect Spring Boot by pom.xml or build.gradle with spring-boot."""
    found: list[dict] = []
    seen_roots: set[str] = set()

    for pom_path in _glob_no_skip(fs, "**/pom.xml"):
        root = _dir_of(pom_path)
        if root in seen_roots:
            continue
        content = _read_raw(fs, pom_path)
        if content and "spring-boot" in content:
            seen_roots.add(root)
            found.append({"framework": "spring", "root": root})

    for gradle_path in _glob_no_skip(fs, "**/build.gradle"):
        root = _dir_of(gradle_path)
        if root in seen_roots:
            continue
        content = _read_raw(fs, gradle_path)
        if content and "spring" in content.lower():
            seen_roots.add(root)
            found.append({"framework": "spring", "root": root})

    return found


def _detect_laravel(fs: FileSystemTools) -> list[dict]:
    """Detect Laravel by artisan + composer.json with laravel."""
    found: list[dict] = []
    seen_roots: set[str] = set()

    for artisan_path in _glob_no_skip(fs, "**/artisan"):
        root = _dir_of(artisan_path)
        if root in seen_roots:
            continue
        composer_path = f"{root}/composer.json" if root != "." else "composer.json"
        composer = _parse_json(fs, composer_path)
        if composer is None:
            continue
        require = {**composer.get("require", {}), **composer.get("require-dev", {})}
        if any("laravel" in k for k in require):
            seen_roots.add(root)
            found.append({"framework": "laravel", "root": root})

    return found


def detect_frameworks(fs: FileSystemTools) -> list[dict]:
    """Detect all frameworks in the target repository.

    Returns a list of dicts, each with:
        - framework: str  (e.g. "nextjs", "django", "express", "flask")
        - root: str       (directory path relative to repo root, or "." for root)

    Supports monorepos: a single repo can yield multiple entries.
    """
    results: list[dict] = []

    results.extend(_detect_nextjs(fs))
    results.extend(_detect_django(fs))
    results.extend(_detect_express(fs))
    results.extend(_detect_flask(fs))
    results.extend(_detect_rails(fs))
    results.extend(_detect_spring(fs))
    results.extend(_detect_laravel(fs))

    # Deduplicate: if both nextjs and express are detected at the same root
    # (common for Next.js apps that also list express as a dep), keep nextjs
    # since it's more specific.
    nextjs_roots = {r["root"] for r in results if r["framework"] == "nextjs"}
    results = [
        r for r in results
        if not (r["framework"] == "express" and r["root"] in nextjs_roots)
    ]

    return results
