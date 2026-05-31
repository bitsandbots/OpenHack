"""
Next.js specific analysis tools for vulnerability scanning.
"""

import json
import re
from pathlib import Path
from typing import Optional

from .filesystem import FileSystemTools


class NextJSTools:
    """Tools for analyzing Next.js application structure and patterns."""

    def __init__(self, fs_tools: FileSystemTools):
        self.fs = fs_tools
        self._route_cache: Optional[dict] = None
        self._project_info_cache: Optional[dict] = None

    def get_project_info(self) -> dict:
        """Get Next.js project information including router type, TypeScript usage, and version."""
        if self._project_info_cache:
            return self._project_info_cache

        info = {
            "framework": "nextjs",
            "router_type": None,
            "has_src_dir": False,
            "typescript": False,
            "nextjs_version": None,
            "has_middleware": False,
            "has_app_dir": False,
            "has_pages_dir": False,
        }

        pkg_result = self.fs.read_file("package.json")
        if "content" in pkg_result:
            try:
                lines = pkg_result["content"].split("\n")
                content = "\n".join(line.split("\t", 1)[1] if "\t" in line else line for line in lines)
                pkg = json.loads(content)
                deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
                if "next" in deps:
                    info["nextjs_version"] = deps["next"]
                info["typescript"] = "typescript" in deps
            except (json.JSONDecodeError, IndexError):
                pass

        src_check = self.fs.list_dir("src")
        info["has_src_dir"] = "error" not in src_check

        base = "src" if info["has_src_dir"] else "."

        app_check = self.fs.list_dir(f"{base}/app")
        info["has_app_dir"] = "error" not in app_check

        pages_check = self.fs.list_dir(f"{base}/pages")
        info["has_pages_dir"] = "error" not in pages_check

        if info["has_app_dir"]:
            info["router_type"] = "app"
        elif info["has_pages_dir"]:
            info["router_type"] = "pages"

        mw_ts = self.fs.read_file("middleware.ts")
        mw_js = self.fs.read_file("middleware.js")
        src_mw_ts = self.fs.read_file("src/middleware.ts")
        src_mw_js = self.fs.read_file("src/middleware.js")
        info["has_middleware"] = any(
            "error" not in r for r in [mw_ts, mw_js, src_mw_ts, src_mw_js]
        )

        self._project_info_cache = info
        return info

    def get_route_map(self) -> dict:
        """Extract all routes from the Next.js application (pages, API routes, route handlers)."""
        if self._route_cache:
            return self._route_cache

        info = self.get_project_info()
        routes = {"app_routes": [], "page_routes": [], "api_routes": []}

        base = "src" if info["has_src_dir"] else "."

        if info["has_app_dir"]:
            app_files = self.fs.glob("**/page.{js,jsx,ts,tsx}", f"{base}/app")
            for f in app_files.get("matches", []):
                route = self._file_to_route(f, f"{base}/app", "app")
                routes["app_routes"].append({"file": f, "route": route, "type": "page"})

            route_files = self.fs.glob("**/route.{js,ts}", f"{base}/app")
            for f in route_files.get("matches", []):
                route = self._file_to_route(f, f"{base}/app", "app")
                routes["api_routes"].append({"file": f, "route": route, "type": "route_handler"})

        if info["has_pages_dir"]:
            page_files = self.fs.glob("**/*.{js,jsx,ts,tsx}", f"{base}/pages")
            for f in page_files.get("matches", []):
                if "/api/" in f or f.startswith("api/"):
                    route = self._file_to_route(f, f"{base}/pages", "pages")
                    routes["api_routes"].append({"file": f, "route": route, "type": "api_route"})
                elif not f.startswith("_") and "/_" not in f:
                    route = self._file_to_route(f, f"{base}/pages", "pages")
                    routes["page_routes"].append({"file": f, "route": route, "type": "page"})

        self._route_cache = routes
        return routes

    def _file_to_route(self, file_path: str, base_dir: str, router_type: str) -> str:
        """Convert a file path to a route path."""
        route = file_path
        if route.startswith(base_dir):
            route = route[len(base_dir):]
        if route.startswith("/"):
            route = route[1:]

        route = re.sub(r"\.(js|jsx|ts|tsx)$", "", route)
        route = re.sub(r"/(page|route|index)$", "", route)

        route = re.sub(r"\[\.\.\.(\w+)\]", r"*", route)
        route = re.sub(r"\[(\w+)\]", r":\1", route)

        if not route.startswith("/"):
            route = "/" + route

        if route == "/":
            return "/"
        return route.rstrip("/")

    def get_server_actions(self) -> dict:
        """Find all server actions ('use server') in the codebase."""
        actions = []

        ts_files = self.fs.glob("**/*.{ts,tsx}", ".")
        js_files = self.fs.glob("**/*.{js,jsx}", ".")

        all_files = ts_files.get("matches", []) + js_files.get("matches", [])

        for file_path in all_files:
            if "node_modules" in file_path:
                continue

            content_result = self.fs.read_file(file_path)
            if "error" in content_result:
                continue

            content = content_result["content"]

            if '"use server"' in content or "'use server'" in content:
                lines = content.split("\n")
                for i, line in enumerate(lines):
                    if "async function" in line or "export async function" in line:
                        match = re.search(r"(?:export\s+)?async\s+function\s+(\w+)", line)
                        if match:
                            actions.append({
                                "file": file_path,
                                "function": match.group(1),
                                "line": i + 1,
                            })

        return {"server_actions": actions}

    def get_middleware_config(self) -> dict:
        """Get the middleware configuration and matcher patterns."""
        locations = ["middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js"]

        for loc in locations:
            result = self.fs.read_file(loc)
            if "error" not in result:
                content = result["content"]
                config = {"file": loc, "content": content, "matcher": None}

                matcher_match = re.search(r"matcher\s*[=:]\s*(\[[\s\S]*?\]|['\"][^'\"]+['\"])", content)
                if matcher_match:
                    config["matcher"] = matcher_match.group(1)

                return config

        return {"error": "No middleware found"}

    def check_dependencies(self) -> dict:
        """Check package.json for security-relevant dependencies."""
        result = self.fs.read_file("package.json")
        if "error" in result:
            return {"error": "Could not read package.json"}

        try:
            lines = result["content"].split("\n")
            content = "\n".join(line.split("\t", 1)[1] if "\t" in line else line for line in lines)
            pkg = json.loads(content)
        except (json.JSONDecodeError, IndexError):
            return {"error": "Could not parse package.json"}

        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}

        security_relevant = {
            "auth": ["next-auth", "@auth/core", "lucia", "clerk", "@clerk/nextjs", "supabase", "@supabase/supabase-js"],
            "database": ["prisma", "@prisma/client", "drizzle-orm", "mongoose", "pg", "mysql2", "better-sqlite3"],
            "validation": ["zod", "yup", "joi", "superstruct", "valibot"],
            "sanitization": ["dompurify", "xss", "sanitize-html", "isomorphic-dompurify"],
            "csrf": ["csrf", "csurf"],
            "rate_limiting": ["rate-limiter-flexible", "express-rate-limit", "upstash"],
        }

        found = {}
        for category, packages in security_relevant.items():
            found[category] = [p for p in packages if p in deps]

        return {
            "all_dependencies": deps,
            "security_relevant": found,
        }

    def get_tool_definitions(self) -> list[dict]:
        """Return OpenAI-compatible tool definitions."""
        return [
            {
                "name": "get_project_info",
                "description": "Get Next.js project information including router type, TypeScript usage, and version.",
                "parameters": {"type": "object", "properties": {}},
            },
            {
                "name": "get_route_map",
                "description": "Extract all routes from the Next.js application (pages, API routes, route handlers).",
                "parameters": {"type": "object", "properties": {}},
            },
            {
                "name": "get_server_actions",
                "description": "Find all server actions ('use server') in the codebase.",
                "parameters": {"type": "object", "properties": {}},
            },
            {
                "name": "get_middleware_config",
                "description": "Get the middleware configuration and matcher patterns.",
                "parameters": {"type": "object", "properties": {}},
            },
            {
                "name": "check_dependencies",
                "description": "Check package.json for security-relevant dependencies.",
                "parameters": {"type": "object", "properties": {}},
            },
        ]

    def execute_tool(self, name: str, arguments: dict) -> dict:
        """Execute a tool by name with the given arguments."""
        tools = {
            "get_project_info": self.get_project_info,
            "get_route_map": self.get_route_map,
            "get_server_actions": self.get_server_actions,
            "get_middleware_config": self.get_middleware_config,
            "check_dependencies": self.check_dependencies,
        }
        if name not in tools:
            return {"error": f"Unknown tool: {name}"}
        # These tools take no arguments - ignore any hallucinated arguments from LLM
        return tools[name]()
