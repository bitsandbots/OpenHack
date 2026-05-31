"""
Tool registry for vulnerability scanning.
Manages all available tools and dispatches tool calls.
"""

from pathlib import Path
from typing import Any

from .filesystem import FileSystemTools
from .nextjs import NextJSTools
from .ast_tools import ASTTools


class ToolRegistry:
    """Registry that manages all scanning tools and their execution."""

    def __init__(self, target_dir: Path):
        self.target_dir = target_dir
        self.fs_tools = FileSystemTools(target_dir)
        self.nextjs_tools = NextJSTools(self.fs_tools)
        self.ast_tools = ASTTools(self.fs_tools)

        self._tool_handlers = {}
        self._register_tools()

    def _register_tools(self):
        for tool in self.fs_tools.get_tool_definitions():
            self._tool_handlers[tool["name"]] = self.fs_tools.execute_tool

        for tool in self.nextjs_tools.get_tool_definitions():
            self._tool_handlers[tool["name"]] = self.nextjs_tools.execute_tool

        for tool in self.ast_tools.get_tool_definitions():
            self._tool_handlers[tool["name"]] = self.ast_tools.execute_tool

    def get_all_tool_definitions(self) -> list[dict]:
        tools = []
        tools.extend(self.fs_tools.get_tool_definitions())
        tools.extend(self.nextjs_tools.get_tool_definitions())
        tools.extend(self.ast_tools.get_tool_definitions())
        return tools

    def is_async_tool(self, name: str) -> bool:
        return False

    def execute_tool(self, name: str, arguments: dict) -> Any:
        if name not in self._tool_handlers:
            return {"error": f"Unknown tool: {name}"}
        return self._tool_handlers[name](name, arguments)

    async def execute_tool_async(self, name: str, arguments: dict) -> Any:
        return self.execute_tool(name, arguments)
