import json
from pathlib import Path

import pytest

from openhack.tools.filesystem import FileSystemTools
from openhack.tools.registry import ToolRegistry


@pytest.fixture
def fs_tools(tmp_path):
    return FileSystemTools(jail_dir=tmp_path)


@pytest.fixture
def tool_registry(tmp_path):
    return ToolRegistry(target_dir=tmp_path)


def write_file(base: Path, rel_path: str, content: str) -> Path:
    p = base / rel_path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


def write_json(base: Path, rel_path: str, data: dict) -> Path:
    return write_file(base, rel_path, json.dumps(data, indent=2))
