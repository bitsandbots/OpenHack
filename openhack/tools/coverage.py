"""
Static attack surface discovery and coverage computation.

All discovery is deterministic (no LLM) -- pure glob + regex.
Used to measure what percentage of the application the scanner actually analyzed.
Also provides enrichment (import resolution, danger pattern pre-scan) for
coverage-guided second-pass hunting.

Supports multiple project types:
- Next.js (API routes, server actions, tRPC, middleware)
- Supabase (migration SQL: RLS policies, RPC functions, storage policies)
- Express / Fastify / Hono (route handlers)
- Small codebases (< 30 source files -- treat everything as attack surface)
"""

import os
import re
from typing import Optional

from .filesystem import FileSystemTools


def discover_attack_surface(
    fs_tools: FileSystemTools,
    nextjs_tools=None,
) -> dict:
    """Deterministically enumerate every security-relevant entry point.

    Detects the project type and runs the appropriate discovery strategy.
    Falls back to "all source files" for small codebases.
    """
    surface: dict = {
        "api_routes": [],
        "server_actions": [],
        "trpc_procedures": [],
        "callback_handlers": [],
        "middleware": [],
        "supabase_migrations": [],
        "route_handlers": [],
        "source_files": [],
        "total_endpoints": 0,
    }

    discovered_files: set[str] = set()

    # --- Next.js discovery (when nextjs_tools are available) ---
    if nextjs_tools is not None:
        route_map = nextjs_tools.get_route_map()
        surface["api_routes"] = route_map.get("api_routes", [])
        for ep in surface["api_routes"]:
            discovered_files.add(ep["file"])

        actions = nextjs_tools.get_server_actions()
        surface["server_actions"] = actions.get("server_actions", [])
        for ep in surface["server_actions"]:
            discovered_files.add(ep["file"])

        mw = nextjs_tools.get_middleware_config()
        if "error" not in mw:
            surface["middleware"] = [{"file": mw["file"]}]
            discovered_files.add(mw["file"])

    # --- tRPC (works for any project with tRPC) ---
    surface["trpc_procedures"] = _discover_trpc_procedures(fs_tools)
    for ep in surface["trpc_procedures"]:
        discovered_files.add(ep["file"])

    # --- Callback handlers ---
    surface["callback_handlers"] = _discover_callback_handlers(fs_tools)
    for ep in surface["callback_handlers"]:
        discovered_files.add(ep["file"])

    # --- Supabase discovery (migration SQL files) ---
    surface["supabase_migrations"] = _discover_supabase_surface(fs_tools)
    for ep in surface["supabase_migrations"]:
        discovered_files.add(ep["file"])

    # --- Express / Fastify / Hono route handlers ---
    surface["route_handlers"] = _discover_route_handlers(fs_tools)
    for ep in surface["route_handlers"]:
        discovered_files.add(ep["file"])

    # --- Django views, URLs, serializers ---
    surface.setdefault("django_views", [])
    surface["django_views"] = _discover_django_surface(fs_tools)
    for ep in surface["django_views"]:
        discovered_files.add(ep["file"])

    # --- Flask routes ---
    surface.setdefault("flask_routes", [])
    surface["flask_routes"] = _discover_flask_surface(fs_tools)
    for ep in surface["flask_routes"]:
        discovered_files.add(ep["file"])

    # --- Rails controllers, services, middleware ---
    surface.setdefault("rails_controllers", [])
    rails_discovered = _discover_rails_surface(fs_tools)
    surface["rails_controllers"] = rails_discovered
    for ep in rails_discovered:
        discovered_files.add(ep["file"])

    # --- Vuln-pattern discovery (framework-agnostic) ---
    # Grep the entire repo for high-signal vulnerability patterns.
    # This catches utility modules (e.g. jinja_context.py, template helpers)
    # that framework-specific discovery misses because they have no route decorators.
    surface.setdefault("danger_files", [])
    danger_discovered = _discover_danger_pattern_files(fs_tools, discovered_files)
    surface["danger_files"] = danger_discovered
    for ep in danger_discovered:
        discovered_files.add(ep["file"])

    # --- Import-chain following ---
    # For each discovered file, resolve imports 1-2 levels deep to find
    # utility modules, DB clients, and helpers that may contain vulnerabilities
    # but have no route decorators (e.g. SqliteClient.ts, email helpers).
    import_deps = _follow_import_chains(fs_tools, discovered_files, max_depth=2)
    surface["imported_dependencies"] = import_deps
    for ep in import_deps:
        discovered_files.add(ep["file"])

    # --- Small codebase fallback ---
    # If we found very few endpoints via structured discovery, enumerate all
    # source files. For small projects this ensures nothing is missed.
    if len(discovered_files) < 5:
        surface["source_files"] = _discover_all_source_files(fs_tools, discovered_files)
        for ep in surface["source_files"]:
            discovered_files.add(ep["file"])

    # Compute total
    surface["total_endpoints"] = len(discovered_files)

    return surface


def _discover_trpc_procedures(fs_tools: FileSystemTools) -> list[dict]:
    """Find tRPC procedure definitions by grepping for procedure builders."""
    procedures: list[dict] = []

    search_dirs = ["packages/trpc", "src/server/trpc", "server/trpc", "src/trpc", "app/trpc"]
    trpc_files: set[str] = set()

    for search_dir in search_dirs:
        result = fs_tools.glob("**/*.ts", search_dir)
        for f in result.get("matches", []):
            if "node_modules" not in f:
                trpc_files.add(f)

    fallback = fs_tools.glob("**/routers/**/*.ts", ".")
    for f in fallback.get("matches", []):
        if "node_modules" not in f:
            trpc_files.add(f)

    procedure_pattern = re.compile(
        r"\b(\w+)\s*[:=]\s*(?:router\.)?"
        r"(publicProcedure|authedProcedure|protectedProcedure|"
        r"authedAdminProcedure|importHandler|organizationProcedure)"
    )

    for file_path in sorted(trpc_files):
        content_result = fs_tools.read_file(file_path)
        if "error" in content_result:
            continue

        raw = content_result.get("content", "")
        lines = raw.split("\n")
        for line in lines:
            raw_line = line.split("\t", 1)[1] if "\t" in line else line
            match = procedure_pattern.search(raw_line)
            if match:
                proc_name = match.group(1)
                auth_level = match.group(2)
                if proc_name in ("const", "export", "let", "var", "return", "type", "interface"):
                    continue
                procedures.append({
                    "file": file_path,
                    "procedure": proc_name,
                    "auth_level": auth_level,
                })

    return procedures


def _discover_callback_handlers(fs_tools: FileSystemTools) -> list[dict]:
    """Find OAuth / integration callback handler files."""
    callbacks: list[dict] = []
    seen_files: set[str] = set()

    patterns = [
        ("**/callback.ts", "."),
        ("**/callback.js", "."),
        ("**/callback/route.ts", "."),
        ("**/callback/route.js", "."),
    ]
    for pattern, base in patterns:
        result = fs_tools.glob(pattern, base)
        for f in result.get("matches", []):
            if "node_modules" not in f and f not in seen_files:
                seen_files.add(f)
                route = f
                if "/api/" in f:
                    route = "/api/" + f.split("/api/", 1)[1]
                callbacks.append({"file": f, "route": route})

    return callbacks


def _discover_supabase_surface(fs_tools: FileSystemTools) -> list[dict]:
    """Find Supabase migration SQL files, config, and edge functions."""
    endpoints: list[dict] = []
    seen: set[str] = set()

    # Migration SQL files
    for pattern in ["supabase/migrations/**/*.sql", "supabase/migrations/*.sql"]:
        result = fs_tools.glob(pattern, ".")
        for f in result.get("matches", []):
            if f not in seen:
                seen.add(f)
                endpoints.append({
                    "file": f,
                    "type": "migration",
                    "label": os.path.basename(f),
                })

    # Supabase config
    for config_file in ["supabase/config.toml", "supabase/config.ts"]:
        result = fs_tools.read_file(config_file)
        if "error" not in result and config_file not in seen:
            seen.add(config_file)
            endpoints.append({
                "file": config_file,
                "type": "config",
                "label": config_file,
            })

    # Edge functions
    result = fs_tools.glob("supabase/functions/**/index.ts", ".")
    for f in result.get("matches", []):
        if f not in seen:
            seen.add(f)
            endpoints.append({"file": f, "type": "edge_function", "label": f})

    return endpoints


def _discover_route_handlers(fs_tools: FileSystemTools) -> list[dict]:
    """Find Express / Fastify / Hono / generic HTTP route handler files."""
    handlers: list[dict] = []
    seen: set[str] = set()

    _ROUTE_PATTERN = re.compile(
        r"(?:app|router|server|hono)\s*\.\s*"
        r"(?:get|post|put|patch|delete|all|use|register|route)\s*\(",
        re.IGNORECASE,
    )

    # Search common server source directories
    search_dirs = [
        "src", "server", "api", "routes", "lib",
        "src/gateway", "src/server", "src/api", "src/routes",
    ]
    source_files: set[str] = set()

    for d in search_dirs:
        for ext in ["**/*.ts", "**/*.js", "**/*.mts", "**/*.mjs"]:
            result = fs_tools.glob(ext, d)
            for f in result.get("matches", []):
                if "node_modules" not in f and "test" not in f.lower():
                    source_files.add(f)

    for file_path in sorted(source_files):
        content_result = fs_tools.read_file(file_path)
        if "error" in content_result:
            continue
        raw = content_result.get("content", "")
        lines = raw.split("\n")
        for line in lines:
            raw_line = line.split("\t", 1)[1] if "\t" in line else line
            if _ROUTE_PATTERN.search(raw_line):
                if file_path not in seen:
                    seen.add(file_path)
                    handlers.append({"file": file_path, "label": file_path})
                break

    return handlers


def _discover_django_surface(fs_tools: FileSystemTools) -> list[dict]:
    """Find Django views, URL configs, serializers, and viewsets."""
    endpoints: list[dict] = []
    seen: set[str] = set()

    for pattern in [
        "**/views.py", "**/views/**/*.py",
        "**/urls.py",
        "**/serializers.py", "**/serializers/**/*.py",
        "**/viewsets.py", "**/viewsets/**/*.py",
        "**/api/*.py", "**/api/**/*.py",
        "**/forms.py",
        "**/admin.py",
    ]:
        result = fs_tools.glob(pattern, ".")
        for f in result.get("matches", []):
            parts = set(f.split("/"))
            if parts.intersection({"node_modules", "venv", ".venv", "__pycache__", "site-packages"}):
                continue
            if "__init__" in f or "test" in f.lower() or "migrations" in f:
                continue
            if f not in seen:
                seen.add(f)
                label = f
                if "views" in f:
                    label = f"Django view: {f}"
                elif "urls" in f:
                    label = f"Django URL config: {f}"
                elif "serializer" in f:
                    label = f"DRF serializer: {f}"
                endpoints.append({"file": f, "label": label})

    return endpoints


def _discover_flask_surface(fs_tools: FileSystemTools) -> list[dict]:
    """Find Flask route files by grepping for @app.route / @blueprint.route."""
    endpoints: list[dict] = []
    seen: set[str] = set()

    _FLASK_ROUTE = re.compile(
        r"@\w+\.route\s*\(|@\w+\.before_request|@\w+\.errorhandler",
    )

    py_files: set[str] = set()
    for d in [".", "src", "app", "api", "routes", "blueprints", "views"]:
        result = fs_tools.glob("**/*.py", d)
        for f in result.get("matches", []):
            parts = set(f.split("/"))
            if parts.intersection({"node_modules", "venv", ".venv", "__pycache__", "site-packages", "migrations"}):
                continue
            py_files.add(f)

    for file_path in sorted(py_files):
        if file_path in seen:
            continue
        content_result = fs_tools.read_file(file_path)
        if "error" in content_result:
            continue
        raw = content_result.get("content", "")
        lines = raw.split("\n")
        for line in lines:
            raw_line = line.split("\t", 1)[1] if "\t" in line else line
            if _FLASK_ROUTE.search(raw_line):
                seen.add(file_path)
                endpoints.append({"file": file_path, "label": f"Flask route: {file_path}"})
                break

    return endpoints


_SKIP_DIRS = {"node_modules", "venv", ".venv", "__pycache__", "site-packages",
              "migrations", ".git", "dist", "build", ".next", "coverage",
              "test", "tests", "__tests__", "spec", "fixtures", "mocks"}

# High-signal patterns worth grepping the entire repo for.
# These are sinks that almost always indicate a real vulnerability when
# combined with user input — worth reading regardless of file location.
_HIGH_SIGNAL_GREP_PATTERNS: list[tuple[str, str, str]] = [
    # SSTI
    (r"render_template_string\s*\(", "SSTI", "Flask render_template_string"),
    (r"mark_safe\s*\(", "SSTI", "Django mark_safe"),
    (r"Environment\s*\(.*\)\.from_string", "SSTI", "Jinja2 from_string"),
    (r"ejs\.render\s*\(", "SSTI", "EJS render"),
    (r"nunjucks\.renderString\s*\(", "SSTI", "Nunjucks renderString"),
    # Command injection (Python)
    (r"subprocess\.\w+\(.*shell\s*=\s*True", "RCE", "subprocess shell=True"),
    (r"os\.system\s*\(", "RCE", "os.system"),
    (r"os\.popen\s*\(", "RCE", "os.popen"),
    # SQL injection (ORM escape hatches)
    (r"\.raw\s*\(\s*f['\"]", "SQLi", "ORM .raw() with f-string"),
    (r"\.extra\s*\(\s*(?:select|where|tables)", "SQLi", "Django .extra()"),
    (r"RawSQL\s*\(", "SQLi", "Django RawSQL"),
    (r"text\s*\(\s*f['\"]", "SQLi", "SQLAlchemy text() with f-string"),
    # Prototype pollution
    (r"__proto__", "Prototype Pollution", "__proto__ reference"),
    (r"(?:lodash|_)\.(?:merge|defaultsDeep)\s*\(", "Prototype Pollution", "lodash deep merge"),
    # Path traversal (Python)
    (r"send_file\s*\(", "Path Traversal", "Flask send_file"),
    (r"FileResponse\s*\(", "Path Traversal", "Django FileResponse"),
    (r"sendFile\s*\(", "Path Traversal", "Express sendFile"),
]


def _discover_rails_surface(fs_tools: FileSystemTools) -> list[dict]:
    """Discover Rails controllers, services, middleware, and GraphQL resolvers."""
    entries: list[dict] = []
    seen: set[str] = set()

    patterns = [
        ("app/controllers/**/*.rb", "controller"),
        ("app/services/**/*.rb", "service"),
        ("app/middleware/**/*.rb", "middleware"),
        ("app/graphql/**/*.rb", "graphql"),
    ]

    for pattern, kind in patterns:
        result = fs_tools.glob(pattern, ".")
        for filepath in result.get("matches", []):
            if filepath in seen:
                continue
            if any(skip in filepath for skip in [
                "test/", "spec/", "concerns/", "node_modules/", "vendor/gems/",
            ]):
                continue
            seen.add(filepath)

            danger_signals = []
            if kind == "controller":
                danger_signals.append({"description": "Rails controller — handles HTTP requests"})
            elif kind == "middleware":
                danger_signals.append({"description": "Middleware — request/response processing"})
            elif kind == "service":
                danger_signals.append({"description": "Service layer — business logic"})

            entries.append({
                "file": filepath,
                "trigger": f"rails_{kind}",
                "danger_signals": danger_signals,
            })

    return entries


def _discover_danger_pattern_files(
    fs_tools: FileSystemTools,
    already_discovered: set[str],
) -> list[dict]:
    """Grep the entire repo for high-signal vulnerability patterns.

    Returns files NOT already in the attack surface that contain dangerous sinks.
    Uses a single combined grep for speed on large repos.
    """
    # Single combined grep to find all candidate files
    combined = "|".join(f"({p})" for p, _, _ in _HIGH_SIGNAL_GREP_PATTERNS)
    result = fs_tools.grep(combined, ".")

    candidate_files: set[str] = set()
    for match in result.get("matches", []):
        file_path = match if isinstance(match, str) else match.get("file", "")
        if not file_path:
            continue
        parts = set(file_path.split("/"))
        if parts.intersection(_SKIP_DIRS):
            continue
        if file_path in already_discovered:
            continue
        candidate_files.add(file_path)

    if not candidate_files:
        return []

    # Read each candidate file once and categorize by pattern
    found: list[dict] = []
    seen: set[str] = set()
    compiled = [(re.compile(p, re.IGNORECASE), cat, desc)
                for p, cat, desc in _HIGH_SIGNAL_GREP_PATTERNS]

    for file_path in sorted(candidate_files):
        content_result = fs_tools.read_file(file_path)
        if "error" in content_result:
            continue
        raw = content_result.get("content", "")

        for regex, category, description in compiled:
            if regex.search(raw):
                if file_path not in seen:
                    seen.add(file_path)
                    found.append({
                        "file": file_path,
                        "label": f"Danger pattern ({category}): {file_path}",
                        "category": "danger_pattern",
                        "trigger": description,
                    })
                break

    return found


def _follow_import_chains(
    fs_tools: FileSystemTools,
    seed_files: set[str],
    max_depth: int = 2,
) -> list[dict]:
    """Follow imports from discovered files to find transitive dependencies.

    Starting from seed files (route handlers, danger pattern files, etc.),
    resolve relative imports up to `max_depth` levels deep. Returns files NOT
    already in the seed set — these are utility modules, DB clients, helpers,
    etc. that may contain vulnerabilities but have no route decorators.
    """
    visited: set[str] = set(seed_files)
    frontier: set[str] = set(seed_files)
    found: list[dict] = []

    max_frontier = 100

    for depth in range(max_depth):
        next_frontier: set[str] = set()

        work = sorted(frontier)[:max_frontier]
        for file_path in work:
            if not file_path.endswith((".ts", ".tsx", ".js", ".jsx", ".py")):
                continue

            content_result = fs_tools.read_file(file_path)
            if "error" in content_result:
                continue

            raw = content_result.get("content", "")
            lines = raw.split("\n")

            for line in lines:
                raw_line = line.split("\t", 1)[1] if "\t" in line else line

                # JS/TS imports
                for m in _IMPORT_RE.finditer(raw_line):
                    source = m.group(1) or m.group(2)
                    if source and source.startswith("."):
                        resolved = _resolve_import(source, file_path, fs_tools)
                        if resolved and resolved not in visited:
                            parts = set(resolved.split("/"))
                            if not parts.intersection(_SKIP_DIRS):
                                visited.add(resolved)
                                next_frontier.add(resolved)

                # Python imports (from .foo import bar / from ..utils import x)
                py_match = re.match(
                    r"from\s+(\.+\w[\w.]*)\s+import",
                    raw_line.strip(),
                )
                if py_match and file_path.endswith(".py"):
                    rel_module = py_match.group(1)
                    resolved = _resolve_python_import(rel_module, file_path, fs_tools)
                    if resolved and resolved not in visited:
                        parts = set(resolved.split("/"))
                        if not parts.intersection(_SKIP_DIRS):
                            visited.add(resolved)
                            next_frontier.add(resolved)

        # Run danger scan on newly found files to prioritize them
        for new_file in next_frontier:
            content_result = fs_tools.read_file(new_file)
            signals = []
            if "error" not in content_result:
                raw = content_result.get("content", "")
                signals = _quick_danger_scan(raw)

            label = f"Import dep (depth={depth + 1}): {new_file}"
            if signals:
                signal_cats = ", ".join(sorted(set(s["category"] for s in signals)))
                label = f"Import dep [{signal_cats}] (depth={depth + 1}): {new_file}"

            found.append({
                "file": new_file,
                "label": label,
                "category": "imported_dependency",
                "depth": depth + 1,
                "has_danger_signals": bool(signals),
                "danger_signals": signals[:5],
            })

        frontier = next_frontier

    return found


def _resolve_python_import(
    rel_module: str,
    from_file: str,
    fs_tools: FileSystemTools,
) -> Optional[str]:
    """Resolve a Python relative import (e.g. '.utils' or '..models') to a file path."""
    # Count leading dots
    dots = 0
    for ch in rel_module:
        if ch == ".":
            dots += 1
        else:
            break

    module_path = rel_module[dots:].replace(".", "/")
    from_dir = os.path.dirname(from_file)

    # Go up directories based on dot count (1 dot = same package, 2 = parent, etc.)
    base_dir = from_dir
    for _ in range(dots - 1):
        base_dir = os.path.dirname(base_dir)

    candidate_base = os.path.normpath(os.path.join(base_dir, module_path))

    # Try as module file or package __init__
    for suffix in [".py", "/__init__.py"]:
        candidate = candidate_base + suffix
        result = fs_tools.read_file(candidate)
        if "error" not in result:
            return candidate

    return None


def _discover_all_source_files(
    fs_tools: FileSystemTools,
    already_discovered: set[str] | None = None,
) -> list[dict]:
    """For small codebases, enumerate source files as attack surface.

    All files with danger signals are included regardless of cap.
    Files without signals are capped at 50.
    """
    if already_discovered is None:
        already_discovered = set()

    files: list[dict] = []
    plain_files: list[dict] = []
    seen: set[str] = set()

    all_source: list[str] = []
    for ext in ["**/*.ts", "**/*.js", "**/*.tsx", "**/*.jsx", "**/*.py",
                "**/*.sql", "**/*.toml"]:
        result = fs_tools.glob(ext, ".")
        for f in result.get("matches", []):
            parts = set(f.split("/"))
            if not parts.intersection(_SKIP_DIRS) and f not in seen and f not in already_discovered:
                seen.add(f)
                all_source.append(f)

    # Scan every file for danger signals; include all that match, cap the rest
    for f in all_source:
        content_result = fs_tools.read_file(f)
        if "error" in content_result:
            plain_files.append({"file": f, "label": f})
            continue
        raw = content_result.get("content", "")
        signals = _quick_danger_scan(raw)
        if signals:
            signal_cats = ", ".join(sorted(set(s["category"] for s in signals)))
            files.append({"file": f, "label": f"[{signal_cats}] {f}"})
        else:
            plain_files.append({"file": f, "label": f})

    # Add capped non-signal files
    files.extend(plain_files[:50])

    return files


def _all_endpoint_files(surface: dict) -> list[dict]:
    """Flatten all endpoints from the surface into a unified list."""
    endpoints: list[dict] = []
    for ep in surface.get("api_routes", []):
        endpoints.append({"file": ep["file"], "category": "api_route", "label": ep.get("route", ep["file"])})
    for ep in surface.get("server_actions", []):
        endpoints.append({"file": ep["file"], "category": "server_action", "label": ep.get("function", ep["file"])})
    for ep in surface.get("trpc_procedures", []):
        endpoints.append({"file": ep["file"], "category": "trpc", "label": ep.get("procedure", ep["file"])})
    for ep in surface.get("callback_handlers", []):
        endpoints.append({"file": ep["file"], "category": "callback", "label": ep.get("route", ep["file"])})
    for ep in surface.get("middleware", []):
        endpoints.append({"file": ep["file"], "category": "middleware", "label": ep["file"]})
    for ep in surface.get("supabase_migrations", []):
        endpoints.append({"file": ep["file"], "category": "supabase", "label": ep.get("label", ep["file"])})
    for ep in surface.get("route_handlers", []):
        endpoints.append({"file": ep["file"], "category": "route_handler", "label": ep.get("label", ep["file"])})
    for ep in surface.get("django_views", []):
        endpoints.append({"file": ep["file"], "category": "django_view", "label": ep.get("label", ep["file"])})
    for ep in surface.get("flask_routes", []):
        endpoints.append({"file": ep["file"], "category": "flask_route", "label": ep.get("label", ep["file"])})
    for ep in surface.get("danger_files", []):
        endpoints.append({"file": ep["file"], "category": "danger_pattern", "label": ep.get("label", ep["file"])})
    for ep in surface.get("imported_dependencies", []):
        endpoints.append({"file": ep["file"], "category": "imported_dependency", "label": ep.get("label", ep["file"])})
    for ep in surface.get("source_files", []):
        endpoints.append({"file": ep["file"], "category": "source_file", "label": ep.get("label", ep["file"])})
    return endpoints


def compute_coverage(attack_surface: dict, files_analyzed: list[str]) -> dict:
    """Compare the static attack surface against files the LLM actually read.

    Returns a coverage report with covered/missed endpoints and a percentage.
    """
    analyzed_set = {f.lower() for f in files_analyzed}

    all_endpoints = _all_endpoint_files(attack_surface)

    # Deduplicate endpoints by file (multiple procedures in the same file count as one)
    unique_files: dict[str, dict] = {}
    for ep in all_endpoints:
        key = ep["file"].lower()
        if key not in unique_files:
            unique_files[key] = ep

    covered: list[dict] = []
    missed: list[dict] = []
    for key, ep in unique_files.items():
        if key in analyzed_set:
            covered.append(ep)
        else:
            missed.append(ep)

    total = len(covered) + len(missed)

    # Per-category breakdown
    categories = {}
    for ep in covered:
        cat = ep["category"]
        categories.setdefault(cat, {"covered": 0, "missed": 0})
        categories[cat]["covered"] += 1
    for ep in missed:
        cat = ep["category"]
        categories.setdefault(cat, {"covered": 0, "missed": 0})
        categories[cat]["missed"] += 1

    return {
        "total_endpoints": total,
        "covered_count": len(covered),
        "missed_count": len(missed),
        "coverage_pct": round(len(covered) / total * 100, 1) if total > 0 else 100.0,
        "categories": categories,
        "covered": covered,
        "missed": missed,
        "files_analyzed_count": len(files_analyzed),
    }


# ---------------------------------------------------------------------------
# Enrichment: build context clusters for coverage-guided second pass
# ---------------------------------------------------------------------------

# Patterns from ASTTools.find_dangerous_patterns -- kept in sync
_DANGER_PATTERNS = [
    # --- XSS ---
    (r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:", "XSS", "dangerouslySetInnerHTML usage"),
    (r"innerHTML\s*=", "XSS", "innerHTML assignment"),
    (r"document\.write\s*\(", "XSS", "document.write usage"),
    (r"v-html\s*=", "XSS", "Vue v-html directive"),
    (r"\|\s*safe\b", "XSS", "Django |safe filter (unescaped output)"),
    (r"mark_safe\s*\(", "XSS", "Django mark_safe (unescaped output)"),
    (r"Markup\s*\(", "XSS", "Flask/Jinja2 Markup() (unescaped output)"),
    # --- SSTI / Template Injection ---
    (r"render_template_string\s*\(", "SSTI", "Flask render_template_string (template injection sink)"),
    (r"Template\s*\(\s*(?:req|request|data|user|input|params|body|f['\"])", "SSTI", "Template constructed from user input"),
    (r"Environment\s*\(.*\)\.from_string\s*\(", "SSTI", "Jinja2 Environment.from_string (template injection)"),
    (r"\.render\s*\(\s*(?:req|request|data|user|input|params|body)", "SSTI", "Template render with user-controlled data"),
    (r"ejs\.render\s*\(", "SSTI", "EJS render (potential SSTI)"),
    (r"nunjucks\.renderString\s*\(", "SSTI", "Nunjucks renderString (template injection)"),
    (r"pug\.render\s*\(", "SSTI", "Pug render from string"),
    # --- RCE / Command Injection ---
    (r"eval\s*\(", "RCE", "eval() usage"),
    (r"new\s+Function\s*\(", "RCE", "Function constructor"),
    (r"exec\s*\(\s*[`'\"].*\$\{", "RCE", "Command injection risk"),
    (r"child_process.*exec", "RCE", "child_process exec usage"),
    (r"subprocess\.\w+\(.*shell\s*=\s*True", "RCE", "Python subprocess with shell=True"),
    (r"os\.system\s*\(", "RCE", "os.system() call"),
    (r"os\.popen\s*\(", "RCE", "os.popen() call"),
    (r"commands\.getoutput\s*\(", "RCE", "commands.getoutput() call"),
    # --- SQL Injection ---
    (r"\$\{.*\}\s*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)", "SQLi", "String interpolation in SQL"),
    (r"\.raw\s*\(\s*(?:f['\"]|['\"].*%|['\"].*\+|['\"].*format)", "SQLi", "Django/SQLAlchemy .raw() with string formatting"),
    (r"\.extra\s*\(", "SQLi", "Django .extra() (raw SQL injection risk)"),
    (r"RawSQL\s*\(", "SQLi", "Django RawSQL expression"),
    (r"text\s*\(\s*f['\"]", "SQLi", "SQLAlchemy text() with f-string"),
    (r"execute\s*\(\s*f['\"]", "SQLi", "Raw SQL execute with f-string"),
    (r"Sequelize\.literal\s*\(", "SQLi", "Sequelize.literal (raw SQL)"),
    (r"knex\.raw\s*\(", "SQLi", "Knex.raw (raw SQL)"),
    # --- Path Traversal ---
    (r"sendFile\s*\(\s*(?:req|request|params|query|path)", "Path Traversal", "Express sendFile with user input"),
    (r"res\.download\s*\(\s*(?:req|request|params|query|path)", "Path Traversal", "Express res.download with user input"),
    (r"open\s*\(\s*(?:req|request|params|os\.path\.join.*request)", "Path Traversal", "File open with user-controlled path"),
    (r"send_file\s*\(\s*(?:req|request|path|os\.path\.join)", "Path Traversal", "Flask send_file with user input"),
    (r"FileResponse\s*\(\s*(?:req|request|path|os\.path\.join)", "Path Traversal", "Django FileResponse with user input"),
    (r"\.\.\/|\.\.\\", "Path Traversal", "Directory traversal sequence in code"),
    # --- Prototype Pollution ---
    (r"__proto__", "Prototype Pollution", "__proto__ reference"),
    (r"Object\.assign\s*\(\s*\{\s*\}\s*,\s*(?:req|request|body|params|input)", "Prototype Pollution", "Object.assign from user input"),
    (r"(?:lodash|_)\.merge\s*\(", "Prototype Pollution", "lodash.merge (deep merge, pollution risk)"),
    (r"(?:lodash|_)\.defaultsDeep\s*\(", "Prototype Pollution", "lodash.defaultsDeep (pollution risk)"),
    (r"deepmerge|deep-extend|merge-deep", "Prototype Pollution", "Deep merge library import"),
    # --- Open Redirect ---
    (r"redirect\s*\(\s*(?:req|request|params|query|searchParams|state|returnTo|url|res)", "Open Redirect", "User-controlled redirect"),
    (r"(?:NextResponse\.redirect|res\.redirect)\s*\(", "Open Redirect", "Redirect call"),
    (r"(?:returnTo|redirectTo|onErrorReturnTo|callbackUrl|redirect_url)", "Open Redirect", "Redirect parameter name"),
    # --- SSRF ---
    (r"(?:fetch|axios|http\.request|urllib\.request|requests\.get|requests\.post)\s*\(\s*(?:req|request|params|query|url|data)", "SSRF", "User-controlled URL in request"),
    # --- Hardcoded Secrets ---
    (r"(?:password|secret|key|token)\s*=\s*['\"][^'\"]+['\"]", "Hardcoded Secret", "Hardcoded credential"),
    # --- IDOR ---
    (r"findUnique\s*\(\s*\{\s*where\s*:\s*\{\s*id", "IDOR", "Lookup by ID without ownership check"),
    # --- Race Conditions ---
    (r"\.save\s*\(\s*\).*\.save\s*\(\s*\)", "Race Condition", "Multiple .save() calls (non-atomic update)"),
    (r"balance|inventory|quantity|stock|credits", "Race Condition", "Financial/inventory field (check atomicity)"),
]

_IMPORT_RE = re.compile(
    r"""(?:import\s+(?:\w+|\{[^}]+\}|\*\s+as\s+\w+)\s+from\s+['\"]([^'\"]+)['\"]"""
    r"""|require\s*\(\s*['\"]([^'\"]+)['\"]\s*\))""",
)


def _resolve_import(source: str, from_file: str, fs_tools: FileSystemTools) -> Optional[str]:
    """Resolve a relative import to an actual file path."""
    if not source.startswith("."):
        return None

    from_dir = os.path.dirname(from_file)
    candidate_base = os.path.normpath(os.path.join(from_dir, source))

    extensions = ["", ".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.js"]
    for ext in extensions:
        candidate = candidate_base + ext
        result = fs_tools.read_file(candidate)
        if "error" not in result:
            return candidate
    return None


def _quick_danger_scan(content: str) -> list[dict]:
    """Run regex danger patterns on raw file content. Returns matches."""
    findings = []
    lines = content.split("\n")
    for pattern_str, category, description in _DANGER_PATTERNS:
        pattern = re.compile(pattern_str, re.IGNORECASE)
        for i, line in enumerate(lines, 1):
            raw_line = line.split("\t", 1)[1] if "\t" in line else line
            if pattern.search(raw_line):
                findings.append({
                    "line": i,
                    "category": category,
                    "description": description,
                    "content": raw_line.strip()[:150],
                })
    return findings


def enrich_missed_endpoints(
    missed: list[dict],
    fs_tools: FileSystemTools,
) -> list[dict]:
    """Build context clusters for missed attack surface files.

    For each missed file:
    1. Run danger pattern pre-scan (smoke signals)
    2. Resolve local imports (dependency context)

    Returns enriched endpoint dicts with 'danger_signals' and 'imports' fields.
    """
    enriched: list[dict] = []

    for ep in missed:
        file_path = ep["file"]
        cluster: dict = {
            **ep,
            "danger_signals": [],
            "imports": [],
        }

        content_result = fs_tools.read_file(file_path)
        if "error" in content_result:
            enriched.append(cluster)
            continue

        raw_content = content_result.get("content", "")

        # Danger pattern pre-scan
        cluster["danger_signals"] = _quick_danger_scan(raw_content)

        # Import resolution
        lines = raw_content.split("\n")
        for line in lines:
            raw_line = line.split("\t", 1)[1] if "\t" in line else line
            for m in _IMPORT_RE.finditer(raw_line):
                source = m.group(1) or m.group(2)
                if source and source.startswith("."):
                    resolved = _resolve_import(source, file_path, fs_tools)
                    if resolved:
                        cluster["imports"].append(resolved)

        enriched.append(cluster)

    return enriched


def build_researcher_zones(
    attack_surface: dict,
    num_zones: int = 7,
    max_files_per_zone: int = 50,
) -> list[dict]:
    """Divide attack surface files into zones for parallel researcher assignment.

    Groups files by directory boundary, balances by count and danger signals,
    and returns zones with file lists and formatted scope text for prompt injection.

    Returns empty list if the codebase is too small to benefit from zoning
    (threshold: num_zones * 4 unique files).

    Each zone dict contains:
    - name: human-readable zone label
    - files: list of {file, categories, danger_signals} dicts
    - file_count: number of unique files
    - danger_summary: {category: count}
    - scope_text: formatted text for researcher prompt
    """
    file_meta: dict[str, dict] = {}

    for section_key, entries in attack_surface.items():
        if not isinstance(entries, list):
            continue
        for ep in entries:
            fp = ep.get("file", "")
            if not fp:
                continue
            if fp not in file_meta:
                file_meta[fp] = {
                    "file": fp,
                    "categories": [],
                    "danger_signals": [],
                }
            file_meta[fp]["categories"].append(section_key)
            if ep.get("trigger"):
                file_meta[fp]["danger_signals"].append(ep["trigger"])
            for sig in ep.get("danger_signals", []):
                desc = sig.get("description", "") if isinstance(sig, dict) else str(sig)
                if desc:
                    file_meta[fp]["danger_signals"].append(desc)

    min_for_zoning = max(num_zones * 2, 10)
    if len(file_meta) < min_for_zoning:
        return []

    # Group by directory prefix (2 levels deep, skipping noise prefixes)
    _NOISE_PREFIXES = {".", "src", ""}
    dir_groups: dict[str, list[dict]] = {}
    for fp, meta in file_meta.items():
        parts = fp.split("/")
        meaningful = [p for p in parts[:-1] if p not in _NOISE_PREFIXES]
        if len(meaningful) >= 2:
            key = "/".join(meaningful[:2])
        elif meaningful:
            key = meaningful[0]
        else:
            key = "_root"
        dir_groups.setdefault(key, []).append(meta)

    def _group_score(group: list[dict]) -> float:
        danger = sum(len(m["danger_signals"]) for m in group)
        return danger * 2 + len(group)

    # Sort largest / most dangerous groups first for greedy assignment
    sorted_dirs = sorted(dir_groups.items(), key=lambda x: -_group_score(x[1]))

    # Split oversized groups, then use greedy bin-packing into num_zones bins
    groups_to_assign: list[tuple[str, list[dict]]] = []
    for dir_name, files in sorted_dirs:
        if len(files) > max_files_per_zone:
            for i in range(0, len(files), max_files_per_zone):
                chunk = files[i:i + max_files_per_zone]
                suffix = f" (part {i // max_files_per_zone + 1})" if i > 0 else ""
                groups_to_assign.append((f"{dir_name}{suffix}", chunk))
        else:
            groups_to_assign.append((dir_name, files))

    # Greedy bin-packing: assign each group to the zone with fewest files
    actual_zones = min(num_zones, len(groups_to_assign))
    zones: list[dict] = [{"names": [], "files": []} for _ in range(actual_zones)]

    for dir_name, files in groups_to_assign:
        smallest_zone = min(zones, key=lambda z: len(z["files"]))
        smallest_zone["files"].extend(files)
        smallest_zone["names"].append(dir_name)

    # Convert to final format
    final_zones: list[dict] = []
    for z in zones:
        if z["files"]:
            final_zones.append({
                "name": " + ".join(z["names"][:3]),
                "files": z["files"],
            })
    zones = final_zones

    # Annotate each zone with metadata and scope text
    for zone in zones:
        zone["file_count"] = len(zone["files"])
        zone["file_paths"] = {m["file"] for m in zone["files"]}

        danger_summary: dict[str, int] = {}
        for meta in zone["files"]:
            for sig in meta.get("danger_signals", []):
                cat = sig.split("(")[0].strip().split(":")[0].strip() if sig else "Unknown"
                danger_summary[cat] = danger_summary.get(cat, 0) + 1
        zone["danger_summary"] = danger_summary

        lines = []
        for meta in zone["files"]:
            cat_str = ", ".join(sorted(set(meta["categories"])))
            line = f"  - `{meta['file']}` ({cat_str})"
            if meta["danger_signals"]:
                line += f" — DANGER: {meta['danger_signals'][0]}"
            lines.append(line)

        danger_text = ""
        if danger_summary:
            parts = [f"{cat}: {cnt}" for cat, cnt in
                     sorted(danger_summary.items(), key=lambda x: -x[1])[:5]]
            danger_text = f"\n\nDanger signals in this zone: {', '.join(parts)}"

        zone["scope_text"] = (
            f"ZONE SCOPE — You are assigned to these {zone['file_count']} files. "
            f"Read and analyze EACH file. Do not skip any.\n"
            f"You may follow imports outside your zone for context, but focus hunting here.\n\n"
            f"Files:\n" + "\n".join(lines) + danger_text
        )

    return zones


def build_second_pass_tasks(
    enriched_endpoints: list[dict],
    max_files_per_task: int = 8,
) -> list[str]:
    """Build focused hunter tasks from enriched missed endpoints.

    Prioritizes files with danger signals and groups them into manageable
    task descriptions for second-pass sub-hunters.
    """
    # Sort: files with danger signals first, then by category
    prioritized = sorted(
        enriched_endpoints,
        key=lambda ep: (
            0 if ep.get("danger_signals") else 1,
            ep.get("category", "z"),
        ),
    )

    tasks: list[str] = []
    for i in range(0, len(prioritized), max_files_per_task):
        batch = prioritized[i : i + max_files_per_task]
        file_descriptions: list[str] = []

        for ep in batch:
            desc = f"  - `{ep['file']}` ({ep.get('category', 'unknown')})"
            signals = ep.get("danger_signals", [])
            if signals:
                signal_summary = ", ".join(
                    sorted(set(s["category"] for s in signals))
                )
                desc += f" -- DANGER SIGNALS: {signal_summary}"
                top_signals = signals[:3]
                for s in top_signals:
                    desc += f"\n    Line {s['line']}: {s['description']}: `{s['content']}`"
            imports = ep.get("imports", [])
            if imports:
                desc += f"\n    Key imports: {', '.join(imports[:5])}"
            file_descriptions.append(desc)

        file_list = "\n".join(file_descriptions)
        task = (
            "COVERAGE SECOND PASS: The following attack surface files were NOT analyzed "
            "in the first hunting pass. Read EACH file listed below and hunt for "
            "vulnerabilities. Do NOT skip any file.\n\n"
            f"Files to analyze ({len(batch)}):\n{file_list}\n\n"
            "For each file:\n"
            "1. Use read_file to read the FULL file content\n"
            "2. If danger signals are noted, investigate those specific lines\n"
            "3. Follow key imports if they contain validation/sanitization logic\n"
            "4. Report any confirmed vulnerabilities using report_finding\n"
            "5. Call finish_hunt when done analyzing ALL files in this batch"
        )
        tasks.append(task)

    return tasks
