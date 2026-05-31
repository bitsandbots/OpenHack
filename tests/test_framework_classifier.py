import json
from pathlib import Path
from tests.conftest import write_file, write_json

from openhack.tools.filesystem import FileSystemTools
from openhack.framework_classifier import classify_frameworks


class TestNextjsDetection:
    def test_detects_nextjs(self, tmp_path):
        write_json(tmp_path, "package.json", {
            "dependencies": {"next": "14.0.0", "react": "18.0.0"}
        })
        fs = FileSystemTools(jail_dir=tmp_path)
        result = classify_frameworks(fs)
        assert len(result) == 1
        assert "nextjs" in result[0]["frameworks"]
        assert result[0]["language"] == "javascript"


class TestExpressDetection:
    def test_detects_express(self, tmp_path):
        write_json(tmp_path, "package.json", {
            "dependencies": {"express": "4.18.0"}
        })
        fs = FileSystemTools(jail_dir=tmp_path)
        result = classify_frameworks(fs)
        assert any("express" in c["frameworks"] for c in result)


class TestFlaskDetection:
    def test_detects_flask(self, tmp_path):
        write_file(tmp_path, "requirements.txt", "flask==3.0.0\nSQLAlchemy==2.0.0\n")
        fs = FileSystemTools(jail_dir=tmp_path)
        result = classify_frameworks(fs)
        assert len(result) >= 1
        assert any("flask" in c["frameworks"] for c in result)
        assert any(c["language"] == "python" for c in result)


class TestDjangoDetection:
    def test_detects_django(self, tmp_path):
        write_file(tmp_path, "requirements.txt", "Django==5.0\ndjango-rest-framework==3.14\n")
        fs = FileSystemTools(jail_dir=tmp_path)
        result = classify_frameworks(fs)
        assert any("django" in c["frameworks"] for c in result)


class TestRailsDetection:
    def test_detects_rails(self, tmp_path):
        write_file(tmp_path, "Gemfile", 'source "https://rubygems.org"\ngem "rails", "~> 7.1"\n')
        fs = FileSystemTools(jail_dir=tmp_path)
        result = classify_frameworks(fs)
        assert any("rails" in c["frameworks"] for c in result)
        assert any(c["language"] == "ruby" for c in result)


class TestLaravelDetection:
    def test_detects_laravel(self, tmp_path):
        write_json(tmp_path, "composer.json", {
            "require": {"laravel/framework": "^10.0"}
        })
        fs = FileSystemTools(jail_dir=tmp_path)
        result = classify_frameworks(fs)
        assert any("laravel" in c["frameworks"] for c in result)
        assert any(c["language"] == "php" for c in result)


class TestMultipleFrameworks:
    def test_detects_multiple_roots(self, tmp_path):
        write_json(tmp_path, "frontend/package.json", {
            "dependencies": {"next": "14.0.0"}
        })
        write_file(tmp_path, "backend/requirements.txt", "fastapi==0.100.0\n")
        fs = FileSystemTools(jail_dir=tmp_path)
        result = classify_frameworks(fs)
        assert len(result) >= 2


class TestNoFramework:
    def test_empty_directory(self, tmp_path):
        fs = FileSystemTools(jail_dir=tmp_path)
        result = classify_frameworks(fs)
        assert result == []
