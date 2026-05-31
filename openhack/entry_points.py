"""
Entry point detector — deterministic extraction of all attack surface entry points.

For each detected framework, runs the appropriate extractor to find all
routes/endpoints/handlers. Returns a structured list that can be displayed
in the TUI and used for scan planning.
"""

import json
import logging
import re
from typing import Optional

from .tools.filesystem import FileSystemTools

logger = logging.getLogger(__name__)


def detect_entry_points(fs: FileSystemTools, classifications: list[dict]) -> list[dict]:
    """Detect all entry points based on framework classifications.

    Returns a list of entry point dicts:
        - path: HTTP path or function signature (e.g., "/api/users/:id")
        - method: HTTP method or "FUNC" for libraries (e.g., "GET", "POST", "FUNC")
        - file: source file containing the handler
        - line: line number (if detected)
        - framework: which framework this belongs to
        - auth: detected auth middleware (if any)
        - status: "unscanned" (default)
    """
    all_entries = []

    for classification in classifications:
        root = classification["root"]
        frameworks = classification["frameworks"]
        language = classification["language"]

        for framework in frameworks:
            extractor = _EXTRACTORS.get(framework)
            if extractor:
                try:
                    entries = extractor(fs, root)
                    for entry in entries:
                        entry["framework"] = framework
                        entry.setdefault("status", "unscanned")
                    all_entries.extend(entries)
                except Exception as e:
                    logger.warning(f"Entry point extraction failed for {framework} at {root}: {e}")

    # Deduplicate by file + path + method
    seen = set()
    deduped = []
    for entry in all_entries:
        key = f"{entry.get('file', '')}::{entry.get('path', '')}::{entry.get('method', '')}"
        if key not in seen:
            seen.add(key)
            deduped.append(entry)

    logger.info(f"Detected {len(deduped)} entry points across {len(classifications)} framework(s)")
    return deduped


# ============================================================
# Framework-specific extractors
# ============================================================

def _extract_nextjs(fs: FileSystemTools, root: str) -> list[dict]:
    """Extract Next.js API routes from app/api/ directory."""
    entries = []

    # App Router: app/**/route.ts
    for pattern in ["app/**/route.ts", "app/**/route.js", "src/app/**/route.ts", "src/app/**/route.js"]:
        result = fs.glob(pattern, root)
        for filepath in result.get("matches", []):
            if "node_modules" in filepath:
                continue
            # Convert file path to route: app/api/users/[id]/route.ts -> /api/users/:id
            route = _filepath_to_nextjs_route(filepath)
            # Read file to detect methods
            methods = _detect_nextjs_methods(fs, filepath)
            for method in methods:
                entries.append({
                    "path": route,
                    "method": method,
                    "file": filepath,
                    "line": None,
                    "auth": None,
                })

    # Server actions
    for pattern in ["app/**/actions.ts", "app/**/actions.js", "src/app/**/actions.ts"]:
        result = fs.glob(pattern, root)
        for filepath in result.get("matches", []):
            if "node_modules" in filepath:
                continue
            entries.append({
                "path": f"[server-action] {filepath}",
                "method": "POST",
                "file": filepath,
                "line": None,
                "auth": None,
            })

    return entries


def _filepath_to_nextjs_route(filepath: str) -> str:
    """Convert Next.js file path to HTTP route."""
    # Remove app/ prefix and /route.ts suffix
    route = filepath
    for prefix in ["src/app/", "app/"]:
        if route.startswith(prefix):
            route = route[len(prefix):]
    route = re.sub(r"/route\.(ts|js)$", "", route)
    # Convert [param] to :param
    route = re.sub(r"\[\.\.\.(\w+)\]", r"*\1", route)
    route = re.sub(r"\[(\w+)\]", r":\1", route)
    return f"/{route}" if route else "/"


def _detect_nextjs_methods(fs: FileSystemTools, filepath: str) -> list[str]:
    """Detect which HTTP methods a Next.js route handler exports."""
    result = fs.read_file(filepath)
    if "error" in result:
        return ["GET"]
    content = result.get("content", "")
    methods = []
    for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]:
        if re.search(rf"export\s+(async\s+)?function\s+{method}\b", content):
            methods.append(method)
    return methods or ["GET"]


def _extract_express(fs: FileSystemTools, root: str) -> list[dict]:
    """Extract Express.js route definitions."""
    entries = []
    # Find all JS/TS files and grep for route definitions
    for pattern in ["**/*.js", "**/*.ts"]:
        result = fs.glob(pattern, root)
        for filepath in result.get("matches", []):
            if any(skip in filepath for skip in ["node_modules/", "test/", "dist/", "build/", ".next/"]):
                continue
            read_result = fs.read_file(filepath)
            if "error" in read_result:
                continue
            content = read_result.get("content", "")
            lines = content.split("\n")
            for i, line in enumerate(lines):
                raw_line = line.split("\t", 1)[1] if "\t" in line else line
                # Match: router.get('/path', ...), app.post('/path', ...), etc.
                match = re.search(
                    r"(?:router|app|server)\.(get|post|put|patch|delete|all|use)\s*\(\s*['\"]([^'\"]+)['\"]",
                    raw_line, re.IGNORECASE
                )
                if match:
                    method = match.group(1).upper()
                    path = match.group(2)
                    if method == "USE":
                        method = "MIDDLEWARE"
                    entries.append({
                        "path": path,
                        "method": method,
                        "file": filepath,
                        "line": i + 1,
                        "auth": None,
                    })
    return entries


def _extract_django(fs: FileSystemTools, root: str) -> list[dict]:
    """Extract Django URL patterns."""
    entries = []
    # Find urls.py files
    result = fs.glob("**/urls.py", root)
    for filepath in result.get("matches", []):
        if any(skip in filepath for skip in ["test/", ".venv/", "migrations/"]):
            continue
        read_result = fs.read_file(filepath)
        if "error" in read_result:
            continue
        content = read_result.get("content", "")
        lines = content.split("\n")
        for i, line in enumerate(lines):
            raw_line = line.split("\t", 1)[1] if "\t" in line else line
            # Match: path('api/users/', views.UserView), re_path(r'^api/', ...)
            match = re.search(r"(?:path|re_path)\s*\(\s*['\"]([^'\"]*)['\"]", raw_line)
            if match:
                path = match.group(1)
                entries.append({
                    "path": f"/{path}" if not path.startswith("/") else path,
                    "method": "ALL",
                    "file": filepath,
                    "line": i + 1,
                    "auth": None,
                })
    return entries


def _extract_flask(fs: FileSystemTools, root: str) -> list[dict]:
    """Extract Flask route decorators."""
    entries = []
    result = fs.glob("**/*.py", root)
    for filepath in result.get("matches", []):
        if any(skip in filepath for skip in ["test/", ".venv/", "migrations/"]):
            continue
        read_result = fs.read_file(filepath)
        if "error" in read_result:
            continue
        content = read_result.get("content", "")
        lines = content.split("\n")
        for i, line in enumerate(lines):
            raw_line = line.split("\t", 1)[1] if "\t" in line else line
            match = re.search(r"@\w+\.route\s*\(\s*['\"]([^'\"]+)['\"]", raw_line)
            if match:
                path = match.group(1)
                # Try to extract methods
                methods_match = re.search(r"methods\s*=\s*\[([^\]]+)\]", raw_line)
                methods = "ALL"
                if methods_match:
                    methods = methods_match.group(1).replace("'", "").replace('"', '').strip()
                entries.append({
                    "path": path,
                    "method": methods,
                    "file": filepath,
                    "line": i + 1,
                    "auth": None,
                })
    return entries


def _extract_fastapi(fs: FileSystemTools, root: str) -> list[dict]:
    """Extract FastAPI route decorators."""
    entries = []
    result = fs.glob("**/*.py", root)
    for filepath in result.get("matches", []):
        if any(skip in filepath for skip in ["test/", ".venv/", "migrations/"]):
            continue
        read_result = fs.read_file(filepath)
        if "error" in read_result:
            continue
        content = read_result.get("content", "")
        lines = content.split("\n")
        for i, line in enumerate(lines):
            raw_line = line.split("\t", 1)[1] if "\t" in line else line
            match = re.search(
                r"@(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)['\"]",
                raw_line, re.IGNORECASE
            )
            if match:
                method = match.group(1).upper()
                path = match.group(2)
                entries.append({
                    "path": path,
                    "method": method,
                    "file": filepath,
                    "line": i + 1,
                    "auth": None,
                })
    return entries


def _extract_laravel(fs: FileSystemTools, root: str) -> list[dict]:
    """Extract Laravel route definitions."""
    entries = []
    for route_file in ["routes/web.php", "routes/api.php"]:
        filepath = f"{root}/{route_file}" if root != "." else route_file
        read_result = fs.read_file(filepath)
        if "error" in read_result:
            continue
        content = read_result.get("content", "")
        lines = content.split("\n")
        for i, line in enumerate(lines):
            raw_line = line.split("\t", 1)[1] if "\t" in line else line
            match = re.search(
                r"Route::(get|post|put|patch|delete|any)\s*\(\s*['\"]([^'\"]+)['\"]",
                raw_line, re.IGNORECASE
            )
            if match:
                method = match.group(1).upper()
                path = match.group(2)
                entries.append({
                    "path": f"/{path}" if not path.startswith("/") else path,
                    "method": method,
                    "file": filepath,
                    "line": i + 1,
                    "auth": None,
                })
    return entries


def _extract_rails(fs: FileSystemTools, root: str) -> list[dict]:
    """Extract Rails entry points from controllers and routes."""
    entries = []

    # Scan controllers directly — more reliable than parsing complex routes.rb
    controller_patterns = [
        "app/controllers/**/*_controller.rb",
        "app/controllers/**/*_controller.rb",
    ]
    seen_files = set()
    for pattern in controller_patterns:
        result = fs.glob(pattern, root)
        for filepath in result.get("matches", []):
            if filepath in seen_files:
                continue
            if any(skip in filepath for skip in ["test/", "spec/", "concerns/application"]):
                continue
            seen_files.add(filepath)
            read_result = fs.read_file(filepath)
            if "error" in read_result:
                entries.append({
                    "path": f"/{filepath}",
                    "method": "ALL",
                    "file": filepath,
                    "line": 1,
                    "auth": None,
                })
                continue
            content = read_result.get("content", "")
            lines = content.split("\n")
            found = False
            for i, line in enumerate(lines):
                raw_line = line.split("\t", 1)[1] if "\t" in line else line
                match = re.search(r"def\s+(\w+)", raw_line)
                if match:
                    action = match.group(1)
                    if action.startswith("_"):
                        continue
                    ctrl = filepath.replace("app/controllers/", "").replace("_controller.rb", "")
                    entries.append({
                        "path": f"/{ctrl}#{action}",
                        "method": "ALL",
                        "file": filepath,
                        "line": i + 1,
                        "auth": None,
                    })
                    found = True
            if not found:
                entries.append({
                    "path": f"/{filepath}",
                    "method": "ALL",
                    "file": filepath,
                    "line": 1,
                    "auth": None,
                })

    # Also scan services, middleware, and GraphQL for deeper attack surface
    extra_patterns = [
        ("app/services/**/*.rb", "service"),
        ("app/middleware/**/*.rb", "middleware"),
        ("app/graphql/**/*.rb", "graphql"),
    ]
    for pattern, kind in extra_patterns:
        result = fs.glob(pattern, root)
        for filepath in result.get("matches", []):
            if filepath in seen_files:
                continue
            if any(skip in filepath for skip in ["test/", "spec/"]):
                continue
            seen_files.add(filepath)
            entries.append({
                "path": f"[{kind}] {filepath}",
                "method": "ALL",
                "file": filepath,
                "line": 1,
                "auth": None,
            })

    return entries


def _extract_spring(fs: FileSystemTools, root: str) -> list[dict]:
    """Extract Spring Boot controller mappings."""
    entries = []
    result = fs.glob("**/*.java", root)
    for filepath in result.get("matches", []):
        if any(skip in filepath for skip in ["test/", "Test.java"]):
            continue
        read_result = fs.read_file(filepath)
        if "error" in read_result:
            continue
        content = read_result.get("content", "")
        lines = content.split("\n")
        class_path = ""
        for i, line in enumerate(lines):
            raw_line = line.split("\t", 1)[1] if "\t" in line else line
            # Class-level @RequestMapping
            class_match = re.search(r'@RequestMapping\s*\(\s*["\']([^"\']+)', raw_line)
            if class_match:
                class_path = class_match.group(1)
            # Method-level mappings
            method_match = re.search(
                r'@(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)\s*\(\s*(?:value\s*=\s*)?["\']([^"\']*)',
                raw_line
            )
            if method_match:
                annotation = method_match.group(1)
                path = method_match.group(2)
                method_map = {
                    "GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT",
                    "PatchMapping": "PATCH", "DeleteMapping": "DELETE", "RequestMapping": "ALL",
                }
                method = method_map.get(annotation, "ALL")
                full_path = f"{class_path}{path}" if class_path else path
                entries.append({
                    "path": f"/{full_path}" if not full_path.startswith("/") else full_path,
                    "method": method,
                    "file": filepath,
                    "line": i + 1,
                    "auth": None,
                })
    return entries


def _extract_gin(fs: FileSystemTools, root: str) -> list[dict]:
    """Extract Go Gin routes."""
    entries = []
    result = fs.glob("**/*.go", root)
    for filepath in result.get("matches", []):
        if any(skip in filepath for skip in ["test/", "_test.go", "vendor/"]):
            continue
        read_result = fs.read_file(filepath)
        if "error" in read_result:
            continue
        content = read_result.get("content", "")
        lines = content.split("\n")
        for i, line in enumerate(lines):
            raw_line = line.split("\t", 1)[1] if "\t" in line else line
            match = re.search(
                r"\.(GET|POST|PUT|PATCH|DELETE|Any|Handle)\s*\(\s*\"([^\"]+)\"",
                raw_line
            )
            if match:
                method = match.group(1).upper()
                path = match.group(2)
                entries.append({
                    "path": path,
                    "method": method,
                    "file": filepath,
                    "line": i + 1,
                    "auth": None,
                })
    return entries


def _extract_go_http(fs: FileSystemTools, root: str) -> list[dict]:
    """Extract Go net/http and common router routes."""
    entries = []
    result = fs.glob("**/*.go", root)
    for filepath in result.get("matches", []):
        if any(skip in filepath for skip in ["test/", "_test.go", "vendor/"]):
            continue
        read_result = fs.read_file(filepath)
        if "error" in read_result:
            continue
        content = read_result.get("content", "")
        lines = content.split("\n")
        for i, line in enumerate(lines):
            raw_line = line.split("\t", 1)[1] if "\t" in line else line
            # http.HandleFunc, mux.HandleFunc, r.HandleFunc
            match = re.search(r'(?:HandleFunc|Handle)\s*\(\s*"([^"]+)"', raw_line)
            if match:
                path = match.group(1)
                entries.append({
                    "path": path,
                    "method": "ALL",
                    "file": filepath,
                    "line": i + 1,
                    "auth": None,
                })
    return entries


def _extract_graphql(fs: FileSystemTools, root: str) -> list[dict]:
    """Extract GraphQL queries and mutations."""
    entries = []
    for pattern in ["**/*.graphql", "**/*.gql"]:
        result = fs.glob(pattern, root)
        for filepath in result.get("matches", []):
            if "node_modules" in filepath:
                continue
            read_result = fs.read_file(filepath)
            if "error" in read_result:
                continue
            content = read_result.get("content", "")
            lines = content.split("\n")
            current_type = None
            for i, line in enumerate(lines):
                raw_line = line.split("\t", 1)[1] if "\t" in line else line
                # Detect type Query { or type Mutation {
                type_match = re.search(r"(?:extend\s+)?type\s+(Query|Mutation|Subscription)\s*\{", raw_line)
                if type_match:
                    current_type = type_match.group(1)
                    continue
                if current_type and raw_line.strip() == "}":
                    current_type = None
                    continue
                if current_type:
                    # Extract field name
                    field_match = re.search(r"(\w+)\s*(?:\(|:)", raw_line.strip())
                    if field_match and not raw_line.strip().startswith("#"):
                        field_name = field_match.group(1)
                        method = "QUERY" if current_type == "Query" else "MUTATION" if current_type == "Mutation" else "SUBSCRIPTION"
                        entries.append({
                            "path": f"[GraphQL] {current_type}.{field_name}",
                            "method": method,
                            "file": filepath,
                            "line": i + 1,
                            "auth": None,
                        })
    return entries


def _extract_c_library(fs: FileSystemTools, root: str) -> list[dict]:
    """Extract public C/C++ API functions from header files."""
    entries = []
    for pattern in ["**/*.h", "include/**/*.h"]:
        result = fs.glob(pattern, root)
        for filepath in result.get("matches", []):
            if any(skip in filepath for skip in ["test/", "internal/", "private/"]):
                continue
            read_result = fs.read_file(filepath)
            if "error" in read_result:
                continue
            content = read_result.get("content", "")
            lines = content.split("\n")
            for i, line in enumerate(lines):
                raw_line = line.split("\t", 1)[1] if "\t" in line else line
                # Match function declarations (simplified)
                match = re.search(
                    r"(?:extern\s+)?(?:const\s+)?(?:unsigned\s+)?(?:int|void|char|size_t|ssize_t|bool|\w+_t|\w+\s*\*)\s+(\w+)\s*\(",
                    raw_line
                )
                if match and not raw_line.strip().startswith("//") and not raw_line.strip().startswith("*"):
                    func_name = match.group(1)
                    # Skip common non-API patterns
                    if func_name.startswith("_") or func_name in ("main", "static", "inline"):
                        continue
                    entries.append({
                        "path": f"[C] {func_name}()",
                        "method": "FUNC",
                        "file": filepath,
                        "line": i + 1,
                        "auth": None,
                    })
    return entries


def _extract_sails(fs: FileSystemTools, root: str) -> list[dict]:
    """Extract Sails.js routes from config/routes.js."""
    entries = []
    filepath = f"{root}/config/routes.js" if root != "." else "config/routes.js"
    # Also check server/config/routes.js
    for fp in [filepath, f"{root}/server/config/routes.js" if root != "." else "server/config/routes.js"]:
        read_result = fs.read_file(fp)
        if "error" in read_result:
            continue
        content = read_result.get("content", "")
        lines = content.split("\n")
        for i, line in enumerate(lines):
            raw_line = line.split("\t", 1)[1] if "\t" in line else line
            # Match: 'GET /api/users': 'users/list'
            match = re.search(r"['\"](?:(GET|POST|PUT|PATCH|DELETE)\s+)?(/[^'\"]+)['\"]", raw_line)
            if match:
                method = match.group(1) or "ALL"
                path = match.group(2)
                entries.append({
                    "path": path,
                    "method": method,
                    "file": fp,
                    "line": i + 1,
                    "auth": None,
                })
        break  # Found routes file, stop looking
    return entries


def _extract_nestjs(fs: FileSystemTools, root: str) -> list[dict]:
    """Extract NestJS controller routes from decorators."""
    entries = []
    result = fs.glob("**/*.ts", root)
    for filepath in result.get("matches", []):
        if any(skip in filepath for skip in ["node_modules/", "test/", "dist/", ".spec.", ".test."]):
            continue
        # Only look at controller and gateway files
        if not any(kw in filepath.lower() for kw in ["controller", "gateway", "resolver"]):
            continue
        read_result = fs.read_file(filepath)
        if "error" in read_result:
            continue
        content = read_result.get("content", "")
        lines = content.split("\n")
        class_path = ""
        for i, line in enumerate(lines):
            raw_line = line.split("\t", 1)[1] if "\t" in line else line
            # Class-level @Controller('/path')
            controller_match = re.search(r"@Controller\s*\(\s*['\"]([^'\"]*)['\"]", raw_line)
            if controller_match:
                class_path = controller_match.group(1)
                continue
            # Method-level @Get(), @Post(), etc.
            method_match = re.search(
                r"@(Get|Post|Put|Patch|Delete|All)\s*\(\s*(?:['\"]([^'\"]*)['\"])?\s*\)",
                raw_line
            )
            if method_match:
                method = method_match.group(1).upper()
                path = method_match.group(2) or ""
                full_path = f"/{class_path}/{path}".replace("//", "/").rstrip("/") or "/"
                entries.append({
                    "path": full_path,
                    "method": method,
                    "file": filepath,
                    "line": i + 1,
                    "auth": None,
                })
            # WebSocket @SubscribeMessage
            ws_match = re.search(r"@SubscribeMessage\s*\(\s*['\"]([^'\"]+)['\"]", raw_line)
            if ws_match:
                entries.append({
                    "path": f"[WebSocket] {ws_match.group(1)}",
                    "method": "WS",
                    "file": filepath,
                    "line": i + 1,
                    "auth": None,
                })
            # GraphQL @Query, @Mutation
            gql_match = re.search(r"@(Query|Mutation|Subscription)\s*\(", raw_line)
            if gql_match:
                gql_type = gql_match.group(1).upper()
                # Try to get the function name from next line
                func_match = re.search(r"(?:async\s+)?(\w+)\s*\(", lines[min(i+1, len(lines)-1)] if i+1 < len(lines) else "")
                func_name = func_match.group(1) if func_match else "unknown"
                entries.append({
                    "path": f"[GraphQL] {gql_type}.{func_name}",
                    "method": gql_type,
                    "file": filepath,
                    "line": i + 1,
                    "auth": None,
                })
    return entries


def _extract_php_raw(fs: FileSystemTools, root: str) -> list[dict]:
    """Extract entry points from PHP — focus on controllers and route handlers, not all files."""
    entries = []
    # Look for files in controller-like directories
    controller_patterns = [
        "**/controllers/**/*.php",
        "**/Controller/**/*.php",
        "**/Controllers/**/*.php",
        "**/api/**/*.php",
        "**/routes/**/*.php",
        "**/handlers/**/*.php",
        "**/actions/**/*.php",
        "**/endpoints/**/*.php",
    ]
    seen_files = set()
    for pattern in controller_patterns:
        result = fs.glob(pattern, root)
        for filepath in result.get("matches", []):
            if any(skip in filepath for skip in ["vendor/", "test/", "migrations/", "node_modules/"]):
                continue
            if filepath in seen_files:
                continue
            seen_files.add(filepath)

            # Read the file and try to extract routes/actions
            read_result = fs.read_file(filepath)
            if "error" in read_result:
                entries.append({
                    "path": f"/{filepath}",
                    "method": "ALL",
                    "file": filepath,
                    "line": 1,
                    "auth": None,
                })
                continue

            content = read_result.get("content", "")
            lines = content.split("\n")
            found_methods = False
            for i, line in enumerate(lines):
                raw_line = line.split("\t", 1)[1] if "\t" in line else line
                # Match public function names in controllers
                match = re.search(r"public\s+function\s+(\w+)\s*\(", raw_line)
                if match:
                    func_name = match.group(1)
                    if func_name.startswith("__"):  # Skip magic methods
                        continue
                    entries.append({
                        "path": f"/{filepath}::{func_name}()",
                        "method": "ALL",
                        "file": filepath,
                        "line": i + 1,
                        "auth": None,
                    })
                    found_methods = True

            if not found_methods:
                entries.append({
                    "path": f"/{filepath}",
                    "method": "ALL",
                    "file": filepath,
                    "line": 1,
                    "auth": None,
                })

    return entries


# Map framework names to their extractors
_EXTRACTORS = {
    "nextjs": _extract_nextjs,
    "express": _extract_express,
    "fastify": _extract_express,  # Similar enough pattern
    "nestjs": _extract_nestjs,
    "hono": _extract_express,
    "koa": _extract_express,
    "sails": _extract_sails,
    "nuxt": _extract_nextjs,      # Similar file-based routing
    "sveltekit": _extract_nextjs,
    "django": _extract_django,
    "django_rest": _extract_django,
    "flask": _extract_flask,
    "fastapi": _extract_fastapi,
    "starlette": _extract_fastapi,
    "laravel": _extract_laravel,
    "symfony": _extract_laravel,   # Similar routing patterns
    "codeigniter": _extract_php_raw,
    "php_raw": _extract_php_raw,
    "rails": _extract_rails,
    "sinatra": _extract_flask,     # Similar decorator pattern
    "spring": _extract_spring,
    "gin": _extract_gin,
    "echo": _extract_gin,         # Similar pattern
    "fiber": _extract_gin,
    "chi": _extract_go_http,
    "net_http": _extract_go_http,
    "gorilla": _extract_go_http,
    "graphql": _extract_graphql,
    "c": _extract_c_library,
    "cpp": _extract_c_library,
    # Frameworks without specific extractors fall through to manager agent
}
