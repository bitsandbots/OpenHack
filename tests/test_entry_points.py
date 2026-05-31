import json
from pathlib import Path
from tests.conftest import write_file, write_json

from openhack.tools.filesystem import FileSystemTools
from openhack.entry_points import detect_entry_points


class TestNextjsEntryPoints:
    def test_extracts_app_router_routes(self, tmp_path):
        write_json(tmp_path, "package.json", {"dependencies": {"next": "14.0.0"}})
        write_file(tmp_path, "app/api/users/route.ts", """
export async function GET(request: Request) { return Response.json([]); }
export async function POST(request: Request) { return Response.json({}); }
""")
        fs = FileSystemTools(jail_dir=tmp_path)
        classifications = [{"root": ".", "language": "javascript", "frameworks": ["nextjs"], "dep_file": "package.json"}]
        eps = detect_entry_points(fs, classifications)
        paths = [ep["path"] for ep in eps]
        assert any("/api/users" in p for p in paths)


class TestExpressEntryPoints:
    def test_extracts_routes(self, tmp_path):
        write_json(tmp_path, "package.json", {"dependencies": {"express": "4.18.0"}})
        write_file(tmp_path, "routes/users.js", """
const express = require('express');
const router = express.Router();
router.get('/users', getUsers);
router.post('/users', createUser);
router.delete('/users/:id', deleteUser);
module.exports = router;
""")
        fs = FileSystemTools(jail_dir=tmp_path)
        classifications = [{"root": ".", "language": "javascript", "frameworks": ["express"], "dep_file": "package.json"}]
        eps = detect_entry_points(fs, classifications)
        methods = {ep["method"] for ep in eps}
        assert "GET" in methods or "get" in methods.union({m.upper() for m in methods})


class TestFlaskEntryPoints:
    def test_extracts_decorators(self, tmp_path):
        write_file(tmp_path, "requirements.txt", "flask==3.0.0\n")
        write_file(tmp_path, "app.py", """
from flask import Flask
app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    pass

@app.route('/users')
def get_users():
    pass
""")
        fs = FileSystemTools(jail_dir=tmp_path)
        classifications = [{"root": ".", "language": "python", "frameworks": ["flask"], "dep_file": "requirements.txt"}]
        eps = detect_entry_points(fs, classifications)
        assert len(eps) >= 2
        paths = [ep["path"] for ep in eps]
        assert any("/login" in p for p in paths)


class TestDjangoEntryPoints:
    def test_extracts_url_patterns(self, tmp_path):
        write_file(tmp_path, "requirements.txt", "Django==5.0\n")
        write_file(tmp_path, "urls.py", """
from django.urls import path
from . import views

urlpatterns = [
    path('api/users/', views.user_list),
    path('api/users/<int:pk>/', views.user_detail),
]
""")
        fs = FileSystemTools(jail_dir=tmp_path)
        classifications = [{"root": ".", "language": "python", "frameworks": ["django"], "dep_file": "requirements.txt"}]
        eps = detect_entry_points(fs, classifications)
        assert len(eps) >= 2


class TestEmptyProject:
    def test_no_entry_points(self, tmp_path):
        fs = FileSystemTools(jail_dir=tmp_path)
        result = detect_entry_points(fs, [])
        assert result == []
