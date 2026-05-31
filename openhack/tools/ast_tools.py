"""
AST and code analysis tools for vulnerability scanning.
"""

import re
from pathlib import Path
from typing import Optional

from .filesystem import FileSystemTools


class ASTTools:
    """Tools for code analysis and pattern detection."""

    def __init__(self, fs_tools: FileSystemTools):
        self.fs = fs_tools

    def _get_raw_content(self, file_result: dict) -> str:
        """Extract raw content from file read result (remove line numbers)."""
        if "error" in file_result:
            return ""
        lines = file_result["content"].split("\n")
        return "\n".join(line.split("\t", 1)[1] if "\t" in line else line for line in lines)

    def extract_functions(self, path: str) -> dict:
        """Extract all function definitions from a file."""
        result = self.fs.read_file(path)
        if "error" in result:
            return result

        content = self._get_raw_content(result)
        functions = []

        patterns = [
            (r"(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)", "function"),
            (r"(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>", "arrow"),
            (r"(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s+)?function\s*\(([^)]*)\)", "function_expr"),
        ]

        for pattern, func_type in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[: match.start()].count("\n") + 1
                functions.append({
                    "name": match.group(1),
                    "params": match.group(2).strip(),
                    "type": func_type,
                    "line": line_num,
                })

        return {"file": path, "functions": functions}

    def extract_exports(self, path: str) -> dict:
        """Extract all exports from a file."""
        result = self.fs.read_file(path)
        if "error" in result:
            return result

        content = self._get_raw_content(result)
        exports = {"named": [], "default": None}

        named_pattern = r"export\s+(?:const|let|var|function|class|async\s+function)\s+(\w+)"
        for match in re.finditer(named_pattern, content):
            exports["named"].append(match.group(1))

        export_list_pattern = r"export\s*\{([^}]+)\}"
        for match in re.finditer(export_list_pattern, content):
            items = [item.strip().split(" as ")[0].strip() for item in match.group(1).split(",")]
            exports["named"].extend(items)

        default_patterns = [
            r"export\s+default\s+(?:function|class)\s+(\w+)",
            r"export\s+default\s+(\w+)",
        ]
        for pattern in default_patterns:
            match = re.search(pattern, content)
            if match:
                exports["default"] = match.group(1)
                break

        return {"file": path, "exports": exports}

    def extract_imports(self, path: str) -> dict:
        """Extract all imports from a file."""
        result = self.fs.read_file(path)
        if "error" in result:
            return result

        content = self._get_raw_content(result)
        imports = []

        patterns = [
            r"import\s+(\w+)\s+from\s+['\"]([^'\"]+)['\"]",
            r"import\s*\{([^}]+)\}\s*from\s*['\"]([^'\"]+)['\"]",
            r"import\s*\*\s*as\s+(\w+)\s+from\s+['\"]([^'\"]+)['\"]",
            r"import\s+['\"]([^'\"]+)['\"]",
        ]

        for match in re.finditer(patterns[0], content):
            imports.append({"type": "default", "name": match.group(1), "source": match.group(2)})

        for match in re.finditer(patterns[1], content):
            names = [n.strip().split(" as ")[0].strip() for n in match.group(1).split(",")]
            imports.append({"type": "named", "names": names, "source": match.group(2)})

        for match in re.finditer(patterns[2], content):
            imports.append({"type": "namespace", "name": match.group(1), "source": match.group(2)})

        for match in re.finditer(patterns[3], content):
            if not any(match.group(1) in str(i.get("source", "")) for i in imports):
                imports.append({"type": "side_effect", "source": match.group(1)})

        return {"file": path, "imports": imports}

    def find_api_handlers(self, path: str) -> dict:
        """Find HTTP method handlers (GET, POST, etc.) in a route file."""
        result = self.fs.read_file(path)
        if "error" in result:
            return result

        content = self._get_raw_content(result)
        handlers = []

        http_methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

        for method in http_methods:
            patterns = [
                rf"export\s+(?:async\s+)?function\s+{method}\s*\(",
                rf"export\s+const\s+{method}\s*=",
            ]
            for pattern in patterns:
                match = re.search(pattern, content)
                if match:
                    line_num = content[: match.start()].count("\n") + 1
                    handlers.append({"method": method, "line": line_num})

        if "export default" in content:
            handler_match = re.search(
                r"export\s+default\s+(?:async\s+)?function\s*(?:\w*)?\s*\(\s*req",
                content,
            )
            if handler_match:
                handlers.append({"method": "DEFAULT_HANDLER", "line": content[: handler_match.start()].count("\n") + 1})

        return {"file": path, "handlers": handlers}

    def trace_variable(self, path: str, variable_name: str) -> dict:
        """Trace all usages of a variable through a file to understand data flow."""
        result = self.fs.read_file(path)
        if "error" in result:
            return result

        content = self._get_raw_content(result)
        usages = []

        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            if re.search(rf"\b{re.escape(variable_name)}\b", line):
                context = "unknown"
                if re.search(rf"(?:const|let|var)\s+.*{re.escape(variable_name)}", line):
                    context = "declaration"
                elif re.search(rf"{re.escape(variable_name)}\s*=", line):
                    context = "assignment"
                elif re.search(rf"(?:params|query|body|searchParams).*{re.escape(variable_name)}", line):
                    context = "input_source"
                elif re.search(rf"(?:sql|query|exec|eval|innerHTML|dangerouslySetInnerHTML).*{re.escape(variable_name)}", line):
                    context = "dangerous_sink"
                elif re.search(rf"return.*{re.escape(variable_name)}", line):
                    context = "return"
                else:
                    context = "usage"

                usages.append({"line": i, "content": line.strip(), "context": context})

        return {"file": path, "variable": variable_name, "usages": usages}

    def find_dangerous_patterns(self, path: str) -> dict:
        """Find potentially dangerous code patterns (eval, innerHTML, SQL injection, etc.)."""
        result = self.fs.read_file(path)
        if "error" in result:
            return result

        content = self._get_raw_content(result)
        findings = []

        dangerous_patterns = [
            (r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:", "XSS", "dangerouslySetInnerHTML usage"),
            (r"eval\s*\(", "RCE", "eval() usage"),
            (r"new\s+Function\s*\(", "RCE", "Function constructor"),
            (r"innerHTML\s*=", "XSS", "innerHTML assignment"),
            (r"document\.write\s*\(", "XSS", "document.write usage"),
            (r"\$\{.*\}\s*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)", "SQLi", "String interpolation in SQL"),
            (r"exec\s*\(\s*[`'\"].*\$\{", "RCE", "Command injection risk"),
            (r"child_process.*exec", "RCE", "child_process exec usage"),
            (r"redirect\s*\(\s*(?:req|request|params|query|searchParams)", "Open Redirect", "User-controlled redirect"),
            (r"(?:fetch|axios|http\.request)\s*\(\s*(?:req|request|params|query|url)", "SSRF", "User-controlled URL in request"),
            (r"\.env\b", "Info Leak", "Potential env file access"),
            (r"(?:password|secret|key|token)\s*=\s*['\"][^'\"]+['\"]", "Hardcoded Secret", "Hardcoded credential"),
        ]

        lines = content.split("\n")
        for pattern, category, description in dangerous_patterns:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "line": i,
                        "category": category,
                        "description": description,
                        "content": line.strip()[:200],
                    })

        return {"file": path, "findings": findings}

    def get_tool_definitions(self) -> list[dict]:
        """Return OpenAI-compatible tool definitions."""
        return [
            {
                "name": "extract_functions",
                "description": "Extract all function definitions from a file.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path to analyze"},
                    },
                    "required": ["path"],
                },
            },
            {
                "name": "extract_exports",
                "description": "Extract all exports from a file.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path to analyze"},
                    },
                    "required": ["path"],
                },
            },
            {
                "name": "extract_imports",
                "description": "Extract all imports from a file.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path to analyze"},
                    },
                    "required": ["path"],
                },
            },
            {
                "name": "find_api_handlers",
                "description": "Find HTTP method handlers (GET, POST, etc.) in a route file.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path to analyze"},
                    },
                    "required": ["path"],
                },
            },
            {
                "name": "trace_variable",
                "description": "Trace all usages of a variable through a file to understand data flow.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path to analyze"},
                        "variable_name": {"type": "string", "description": "Variable name to trace"},
                    },
                    "required": ["path", "variable_name"],
                },
            },
            {
                "name": "find_dangerous_patterns",
                "description": "Find potentially dangerous code patterns (eval, innerHTML, SQL injection, etc.).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path to analyze"},
                    },
                    "required": ["path"],
                },
            },
        ]

    def execute_tool(self, name: str, arguments: dict) -> dict:
        """Execute a tool by name with the given arguments.

        Filters out unexpected keyword arguments that the LLM may hallucinate.
        """
        import inspect

        tools = {
            "extract_functions": self.extract_functions,
            "extract_exports": self.extract_exports,
            "extract_imports": self.extract_imports,
            "find_api_handlers": self.find_api_handlers,
            "trace_variable": self.trace_variable,
            "find_dangerous_patterns": self.find_dangerous_patterns,
        }
        if name not in tools:
            return {"error": f"Unknown tool: {name}"}

        func = tools[name]
        sig = inspect.signature(func)
        valid_params = set(sig.parameters.keys())
        filtered_args = {k: v for k, v in arguments.items() if k in valid_params}
        return func(**filtered_args)
