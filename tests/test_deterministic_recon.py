import json
from pathlib import Path
from tests.conftest import write_file, write_json

from openhack.tools.registry import ToolRegistry
from openhack.deterministic_recon import run_deterministic_recon


class TestFeatureDetection:
    def test_detects_file_upload(self, tmp_path):
        write_file(tmp_path, "upload.py", """
from flask import request

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['document']
    file.save('/uploads/' + file.filename)
""")
        write_json(tmp_path, "package.json", {"dependencies": {}})
        tools = ToolRegistry(target_dir=tmp_path)
        result = run_deterministic_recon(tools)
        features = result.get("features", {})
        assert "file_uploads" in features

    def test_detects_auth_system(self, tmp_path):
        write_file(tmp_path, "auth.py", """
import jwt
from flask import request

def verify_token(token):
    return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
""")
        tools = ToolRegistry(target_dir=tmp_path)
        result = run_deterministic_recon(tools)
        features = result.get("features", {})
        assert "auth_system" in features

    def test_empty_project(self, tmp_path):
        write_file(tmp_path, "readme.md", "# empty project")
        tools = ToolRegistry(target_dir=tmp_path)
        result = run_deterministic_recon(tools)
        assert "summary" in result
        assert "attack_surface" in result


class TestReconOutput:
    def test_returns_expected_keys(self, tmp_path):
        write_json(tmp_path, "package.json", {"dependencies": {"express": "4.0.0"}})
        write_file(tmp_path, "index.js", "const express = require('express');\nconst app = express();\n")
        tools = ToolRegistry(target_dir=tmp_path)
        result = run_deterministic_recon(tools)
        assert "summary" in result
        assert "type" in result
        assert result["type"] == "recon_complete"
        assert "attack_surface" in result
