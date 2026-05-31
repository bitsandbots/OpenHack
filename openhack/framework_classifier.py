"""
Framework classifier — detects frameworks by reading dependency files.

Walks the repo, finds all dependency files (package.json, requirements.txt, etc.),
reads them, and maps each directory to its framework(s). Handles monorepos with
multiple frameworks in different directories.

This replaces the old framework_detection.py approach of guessing from folder names.
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Optional

from .tools.filesystem import FileSystemTools

logger = logging.getLogger(__name__)


# Framework detection rules: dependency file → package name → framework
PACKAGE_JSON_FRAMEWORKS = {
    # JavaScript/TypeScript web frameworks
    "next": "nextjs",
    "express": "express",
    "@nestjs/core": "nestjs",
    "fastify": "fastify",
    "hono": "hono",
    "koa": "koa",
    "@hapi/hapi": "hapi",
    "sails": "sails",
    "nuxt": "nuxt",
    "@sveltejs/kit": "sveltekit",
    "@remix-run/node": "remix",
    # Protocol/API frameworks
    "@trpc/server": "trpc",
    "graphql": "graphql",
    "apollo-server": "graphql",
    "@apollo/server": "graphql",
    "mercurius": "graphql",
    "graphql-yoga": "graphql",
    "socket.io": "websocket",
    "ws": "websocket",
    "@grpc/grpc-js": "grpc",
    # Auth libraries (supplementary detection)
    "passport": "passport",
    "next-auth": "nextauth",
    "@auth/core": "authjs",
}

PYTHON_FRAMEWORKS = {
    "django": "django",
    "djangorestframework": "django_rest",
    "django-rest-framework": "django_rest",
    "flask": "flask",
    "fastapi": "fastapi",
    "starlette": "starlette",
    "tornado": "tornado",
    "sanic": "sanic",
    "aiohttp": "aiohttp",
    "graphene": "graphql",
    "strawberry-graphql": "graphql",
    "ariadne": "graphql",
    "channels": "websocket",
    "celery": "celery",
    "grpcio": "grpc",
}

RUBY_FRAMEWORKS = {
    "rails": "rails",
    "sinatra": "sinatra",
    "grape": "grape",
    "graphql": "graphql",
    "action_cable": "websocket",
}

PHP_FRAMEWORKS = {
    "laravel/framework": "laravel",
    "symfony/framework-bundle": "symfony",
    "symfony/http-kernel": "symfony",
    "codeigniter4/framework": "codeigniter",
    "cakephp/cakephp": "cakephp",
    "slim/slim": "slim",
}

GO_FRAMEWORKS = {
    "github.com/gin-gonic/gin": "gin",
    "github.com/labstack/echo": "echo",
    "github.com/gofiber/fiber": "fiber",
    "github.com/go-chi/chi": "chi",
    "google.golang.org/grpc": "grpc",
    "github.com/gorilla/mux": "gorilla",
    "github.com/gorilla/websocket": "websocket",
    "net/http": "net_http",
}

JAVA_FRAMEWORKS = {
    "spring-boot-starter-web": "spring",
    "spring-boot-starter-webflux": "spring_webflux",
    "javax.ws.rs": "jaxrs",
    "jakarta.ws.rs": "jaxrs",
    "io.quarkus": "quarkus",
    "io.micronaut": "micronaut",
}

DOTNET_FRAMEWORKS = {
    "Microsoft.AspNetCore": "aspnet",
    "Microsoft.AspNetCore.Mvc": "aspnet_mvc",
    "Microsoft.AspNetCore.SignalR": "signalr",
}

RUST_FRAMEWORKS = {
    "actix-web": "actix",
    "axum": "axum",
    "rocket": "rocket",
    "warp": "warp",
    "tonic": "grpc",
}


def classify_frameworks(fs: FileSystemTools) -> list[dict]:
    """Classify frameworks in the repository by reading dependency files.

    Returns a list of dicts, each with:
        - root: directory path relative to repo root
        - language: python, javascript, ruby, php, go, java, dotnet, rust, c
        - frameworks: list of detected framework names
        - dep_file: path to the dependency file used for detection
    """
    classifications = []

    # Find all dependency files
    dep_file_patterns = [
        ("package.json", _parse_package_json),
        ("requirements.txt", _parse_requirements_txt),
        ("pyproject.toml", _parse_pyproject_toml),
        ("Pipfile", _parse_pipfile),
        ("Gemfile", _parse_gemfile),
        ("composer.json", _parse_composer_json),
        ("go.mod", _parse_go_mod),
        ("Cargo.toml", _parse_cargo_toml),
    ]

    for filename, parser in dep_file_patterns:
        matches = fs.glob(f"**/{filename}", ".")
        for filepath in matches.get("matches", []):
            # Skip node_modules, vendor, etc.
            if any(skip in filepath for skip in [
                "node_modules/", "vendor/", ".venv/", "__pycache__/",
                "test/", "tests/", "fixtures/", "examples/", "demo/",
            ]):
                continue

            result = fs.read_file(filepath)
            if "error" in result:
                continue

            content = result.get("content", "")
            # Strip line number prefixes from read_file
            lines = []
            for line in content.split("\n"):
                if "\t" in line:
                    lines.append(line.split("\t", 1)[1])
                else:
                    lines.append(line)
            clean_content = "\n".join(lines)

            try:
                classification = parser(clean_content, filepath)
                if classification and classification.get("frameworks"):
                    classifications.append(classification)
            except Exception as e:
                logger.debug(f"Failed to parse {filepath}: {e}")

    # Also detect C/C++ projects (no dependency file, use Makefile/CMakeLists)
    c_class = _detect_c_project(fs)
    if c_class:
        classifications.append(c_class)

    # Also detect Java projects via pom.xml / build.gradle
    java_class = _detect_java_project(fs)
    if java_class:
        classifications.append(java_class)

    # Also detect .NET projects via .csproj
    dotnet_class = _detect_dotnet_project(fs)
    if dotnet_class:
        classifications.append(dotnet_class)

    # Also detect Rails projects via config/application.rb (handles Gemfile.d/ patterns)
    rails_class = _detect_rails_project(fs)
    if rails_class:
        classifications.append(rails_class)

    # Deduplicate — if same root has multiple dep files, merge
    merged = _merge_classifications(classifications)

    logger.info(f"Classified {len(merged)} framework(s): "
                + ", ".join(f"{c['root']}={c['frameworks']}" for c in merged))

    return merged


def _get_root(filepath: str) -> str:
    """Get the directory of a dependency file relative to repo root."""
    parts = filepath.split("/")
    if len(parts) <= 1:
        return "."
    return "/".join(parts[:-1])


def _parse_package_json(content: str, filepath: str) -> Optional[dict]:
    """Parse package.json for framework dependencies."""
    try:
        pkg = json.loads(content)
    except json.JSONDecodeError:
        return None

    deps = {}
    deps.update(pkg.get("dependencies", {}))
    deps.update(pkg.get("devDependencies", {}))

    frameworks = []
    for package_name, framework_name in PACKAGE_JSON_FRAMEWORKS.items():
        if package_name in deps:
            frameworks.append(framework_name)

    if not frameworks:
        return None

    return {
        "root": _get_root(filepath),
        "language": "javascript",
        "frameworks": sorted(set(frameworks)),
        "dep_file": filepath,
    }


def _parse_requirements_txt(content: str, filepath: str) -> Optional[dict]:
    """Parse requirements.txt for Python framework dependencies."""
    frameworks = []
    for line in content.split("\n"):
        line = line.strip().lower()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Extract package name (before ==, >=, ~=, etc.)
        pkg = re.split(r"[=<>~!;\[]", line)[0].strip()
        if pkg in PYTHON_FRAMEWORKS:
            frameworks.append(PYTHON_FRAMEWORKS[pkg])

    if not frameworks:
        return None

    return {
        "root": _get_root(filepath),
        "language": "python",
        "frameworks": sorted(set(frameworks)),
        "dep_file": filepath,
    }


def _parse_pyproject_toml(content: str, filepath: str) -> Optional[dict]:
    """Parse pyproject.toml for Python framework dependencies."""
    frameworks = []
    # Simple TOML parsing — look for dependency declarations
    for line in content.split("\n"):
        line_lower = line.strip().lower()
        for pkg, framework in PYTHON_FRAMEWORKS.items():
            if pkg in line_lower:
                frameworks.append(framework)

    if not frameworks:
        return None

    return {
        "root": _get_root(filepath),
        "language": "python",
        "frameworks": sorted(set(frameworks)),
        "dep_file": filepath,
    }


def _parse_pipfile(content: str, filepath: str) -> Optional[dict]:
    """Parse Pipfile for Python framework dependencies."""
    return _parse_pyproject_toml(content, filepath)  # Similar enough format


def _parse_gemfile(content: str, filepath: str) -> Optional[dict]:
    """Parse Gemfile for Ruby framework dependencies."""
    frameworks = []
    for line in content.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # gem 'rails', '~> 7.0'
        match = re.match(r"gem\s+['\"]([^'\"]+)['\"]", line)
        if match:
            gem_name = match.group(1).lower()
            if gem_name in RUBY_FRAMEWORKS:
                frameworks.append(RUBY_FRAMEWORKS[gem_name])

    if not frameworks:
        return None

    return {
        "root": _get_root(filepath),
        "language": "ruby",
        "frameworks": sorted(set(frameworks)),
        "dep_file": filepath,
    }


def _parse_composer_json(content: str, filepath: str) -> Optional[dict]:
    """Parse composer.json for PHP framework dependencies."""
    try:
        pkg = json.loads(content)
    except json.JSONDecodeError:
        return None

    deps = pkg.get("require", {})
    frameworks = []
    for package_name, framework_name in PHP_FRAMEWORKS.items():
        if package_name in deps:
            frameworks.append(framework_name)

    if not frameworks:
        # Check if it's raw PHP (has composer.json but no framework)
        return {
            "root": _get_root(filepath),
            "language": "php",
            "frameworks": ["php_raw"],
            "dep_file": filepath,
        }

    return {
        "root": _get_root(filepath),
        "language": "php",
        "frameworks": sorted(set(frameworks)),
        "dep_file": filepath,
    }


def _parse_go_mod(content: str, filepath: str) -> Optional[dict]:
    """Parse go.mod for Go framework dependencies."""
    frameworks = []
    for line in content.split("\n"):
        line = line.strip()
        for module_path, framework_name in GO_FRAMEWORKS.items():
            if module_path in line:
                frameworks.append(framework_name)

    if not frameworks:
        # Go project with no detected framework — could be net/http
        frameworks = ["net_http"]

    return {
        "root": _get_root(filepath),
        "language": "go",
        "frameworks": sorted(set(frameworks)),
        "dep_file": filepath,
    }


def _parse_cargo_toml(content: str, filepath: str) -> Optional[dict]:
    """Parse Cargo.toml for Rust framework dependencies."""
    frameworks = []
    for line in content.split("\n"):
        line = line.strip().lower()
        for crate_name, framework_name in RUST_FRAMEWORKS.items():
            if crate_name in line:
                frameworks.append(framework_name)

    if not frameworks:
        return None

    return {
        "root": _get_root(filepath),
        "language": "rust",
        "frameworks": sorted(set(frameworks)),
        "dep_file": filepath,
    }


def _detect_c_project(fs: FileSystemTools) -> Optional[dict]:
    """Detect C/C++ projects by looking for Makefile/CMakeLists."""
    for indicator in ["Makefile", "CMakeLists.txt", "configure", "meson.build"]:
        result = fs.glob(indicator, ".")
        if result.get("matches"):
            # Verify there are actually C files
            c_files = fs.glob("**/*.c", ".")
            h_files = fs.glob("**/*.h", ".")
            cpp_files = fs.glob("**/*.cpp", ".")
            total = (len(c_files.get("matches", [])) +
                     len(h_files.get("matches", [])) +
                     len(cpp_files.get("matches", [])))
            if total > 5:
                lang = "cpp" if len(cpp_files.get("matches", [])) > len(c_files.get("matches", [])) else "c"
                return {
                    "root": ".",
                    "language": lang,
                    "frameworks": [lang],
                    "dep_file": indicator,
                }
    return None


def _detect_java_project(fs: FileSystemTools) -> Optional[dict]:
    """Detect Java projects via pom.xml or build.gradle."""
    for indicator in ["pom.xml", "build.gradle", "build.gradle.kts"]:
        result = fs.glob(indicator, ".")
        if result.get("matches"):
            filepath = result["matches"][0]
            read_result = fs.read_file(filepath)
            if "error" in read_result:
                continue
            content = read_result.get("content", "")
            frameworks = []
            for pattern, framework in JAVA_FRAMEWORKS.items():
                if pattern.lower() in content.lower():
                    frameworks.append(framework)
            if not frameworks:
                frameworks = ["java_raw"]
            return {
                "root": _get_root(filepath),
                "language": "java",
                "frameworks": frameworks,
                "dep_file": filepath,
            }
    return None


def _detect_dotnet_project(fs: FileSystemTools) -> Optional[dict]:
    """Detect .NET projects via .csproj files."""
    result = fs.glob("**/*.csproj", ".")
    matches = result.get("matches", [])
    if not matches:
        return None

    filepath = matches[0]
    read_result = fs.read_file(filepath)
    if "error" in read_result:
        return None

    content = read_result.get("content", "")
    frameworks = []
    for pattern, framework in DOTNET_FRAMEWORKS.items():
        if pattern.lower() in content.lower():
            frameworks.append(framework)
    if not frameworks:
        frameworks = ["dotnet_raw"]

    return {
        "root": _get_root(filepath),
        "language": "dotnet",
        "frameworks": frameworks,
        "dep_file": filepath,
    }


def _detect_rails_project(fs: FileSystemTools) -> Optional[dict]:
    """Detect Rails projects via config/application.rb or Gemfile.d/."""
    for indicator in ["config/application.rb"]:
        result = fs.glob(indicator, ".")
        if result.get("matches"):
            filepath = result["matches"][0]
            read_result = fs.read_file(filepath)
            content = read_result.get("content", "") if "error" not in read_result else ""
            if "Rails" in content or "rails" in content.lower():
                root = _get_root(filepath).rsplit("/config", 1)[0] if "/config" in filepath else "."
                frameworks = ["rails"]
                if "graphql" in content.lower():
                    frameworks.append("graphql")
                return {
                    "root": root,
                    "language": "ruby",
                    "frameworks": frameworks,
                    "dep_file": filepath,
                }

    for gemfile_d in ["Gemfile.d/app.rb", "Gemfile.d"]:
        result = fs.glob(gemfile_d, ".")
        if result.get("matches"):
            filepath = result["matches"][0]
            if filepath.endswith(".rb"):
                read_result = fs.read_file(filepath)
                if "error" not in read_result:
                    content = read_result.get("content", "")
                    for line in content.split("\n"):
                        if "gem" in line and "rails" in line.lower() and "rubocop" not in line.lower():
                            root = _get_root(filepath).rsplit("/Gemfile.d", 1)[0] if "/Gemfile.d" in filepath else "."
                            return {
                                "root": root,
                                "language": "ruby",
                                "frameworks": ["rails"],
                                "dep_file": filepath,
                            }
    return None


def _merge_classifications(classifications: list[dict]) -> list[dict]:
    """Merge classifications with the same root directory."""
    by_root: dict[str, dict] = {}
    for c in classifications:
        root = c["root"]
        if root in by_root:
            existing = by_root[root]
            existing["frameworks"] = sorted(set(existing["frameworks"] + c["frameworks"]))
            # Keep the more specific language
            if existing["language"] == "javascript" and c["language"] != "javascript":
                existing["language"] = c["language"]
        else:
            by_root[root] = dict(c)
    return list(by_root.values())
