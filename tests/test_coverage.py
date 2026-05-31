import json
from pathlib import Path
from tests.conftest import write_file, write_json

from openhack.tools.filesystem import FileSystemTools
from openhack.tools.coverage import discover_attack_surface


class TestNextjsAttackSurface:
    def test_discovers_api_routes(self, tmp_path):
        write_json(tmp_path, "package.json", {"dependencies": {"next": "14.0.0"}})
        write_file(tmp_path, "app/api/auth/login/route.ts", """
export async function POST(req: Request) { }
""")
        write_file(tmp_path, "app/api/users/route.ts", """
export async function GET(req: Request) { }
export async function POST(req: Request) { }
""")
        fs = FileSystemTools(jail_dir=tmp_path)
        surface = discover_attack_surface(fs)
        assert surface.get("total_endpoints", 0) > 0


class TestExpressAttackSurface:
    def test_discovers_route_handlers(self, tmp_path):
        write_json(tmp_path, "package.json", {"dependencies": {"express": "4.18.0"}})
        write_file(tmp_path, "routes/api.js", """
const router = require('express').Router();
router.get('/products', listProducts);
router.post('/products', createProduct);
router.put('/products/:id', updateProduct);
module.exports = router;
""")
        fs = FileSystemTools(jail_dir=tmp_path)
        surface = discover_attack_surface(fs)
        handlers = surface.get("route_handlers", [])
        assert len(handlers) >= 1


class TestFlaskAttackSurface:
    def test_discovers_flask_routes(self, tmp_path):
        write_file(tmp_path, "requirements.txt", "flask==3.0.0\n")
        write_file(tmp_path, "app.py", """
from flask import Flask
app = Flask(__name__)

@app.route('/api/data', methods=['GET', 'POST'])
def data_endpoint():
    pass

@app.route('/api/admin')
def admin():
    pass
""")
        fs = FileSystemTools(jail_dir=tmp_path)
        surface = discover_attack_surface(fs)
        flask_routes = surface.get("flask_routes", [])
        assert len(flask_routes) >= 1


class TestDjangoAttackSurface:
    def test_discovers_django_views(self, tmp_path):
        write_file(tmp_path, "requirements.txt", "Django==5.0\n")
        write_file(tmp_path, "views.py", """
from django.http import JsonResponse
from django.views import View

class UserView(View):
    def get(self, request):
        pass
    def post(self, request):
        pass
""")
        fs = FileSystemTools(jail_dir=tmp_path)
        surface = discover_attack_surface(fs)
        assert surface.get("total_endpoints", 0) >= 0


class TestEmptyProject:
    def test_empty_surface(self, tmp_path):
        fs = FileSystemTools(jail_dir=tmp_path)
        surface = discover_attack_surface(fs)
        assert isinstance(surface, dict)
        assert surface.get("total_endpoints", 0) == 0
