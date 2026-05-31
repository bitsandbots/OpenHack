import json
from pathlib import Path
from unittest.mock import patch

from openhack.scan_session import ScanSession


class TestScanSessionCRUD:
    def test_save_and_load(self, tmp_path):
        with patch("openhack.scan_session.SESSIONS_DIR", tmp_path):
            session = ScanSession("test123", "/tmp/myapp")
            session.classifications = [{"root": ".", "language": "python", "frameworks": ["flask"]}]
            session.entry_points = [
                {"path": "/login", "method": "POST", "file": "app.py", "status": "unscanned"},
                {"path": "/users", "method": "GET", "file": "app.py", "status": "unscanned"},
            ]
            session.save()

            loaded = ScanSession.load("test123")
            assert loaded is not None
            assert loaded.session_id == "test123"
            assert loaded.target_dir == "/tmp/myapp"
            assert len(loaded.entry_points) == 2

    def test_load_nonexistent(self, tmp_path):
        with patch("openhack.scan_session.SESSIONS_DIR", tmp_path):
            assert ScanSession.load("nope") is None

    def test_list_sessions(self, tmp_path):
        with patch("openhack.scan_session.SESSIONS_DIR", tmp_path):
            s1 = ScanSession("aaa", "/tmp/app1")
            s1.save()
            s2 = ScanSession("bbb", "/tmp/app2")
            s2.save()

            sessions = ScanSession.list_sessions()
            assert len(sessions) == 2


class TestScanSessionState:
    def test_mark_scanned(self, tmp_path):
        with patch("openhack.scan_session.SESSIONS_DIR", tmp_path):
            session = ScanSession("s1", "/app")
            session.entry_points = [
                {"path": "/a", "file": "a.py", "status": "unscanned"},
                {"path": "/b", "file": "b.py", "status": "unscanned"},
            ]
            session.mark_scanned("a.py")
            assert session.scanned_count == 1
            assert session.unscanned_count == 1

    def test_coverage_pct(self, tmp_path):
        with patch("openhack.scan_session.SESSIONS_DIR", tmp_path):
            session = ScanSession("s2", "/app")
            session.entry_points = [
                {"path": "/a", "file": "a.py", "status": "unscanned"},
                {"path": "/b", "file": "b.py", "status": "unscanned"},
                {"path": "/c", "file": "c.py", "status": "unscanned"},
                {"path": "/d", "file": "d.py", "status": "unscanned"},
            ]
            session.mark_scanned("a.py")
            session.mark_scanned("b.py")
            assert session.coverage_pct == 50.0

    def test_mark_finding(self, tmp_path):
        with patch("openhack.scan_session.SESSIONS_DIR", tmp_path):
            session = ScanSession("s3", "/app")
            session.entry_points = [
                {"path": "/a", "file": "a.py", "status": "unscanned"},
            ]
            session.mark_finding("a.py")
            assert session.entry_points[0]["status"] == "finding_found"

    def test_zone_coverage(self, tmp_path):
        with patch("openhack.scan_session.SESSIONS_DIR", tmp_path):
            session = ScanSession("s4", "/app")
            session.mark_zone_complete("auth", ["auth.py", "login.py"], 2)
            assert "auth" in session.get_completed_zones()
            assert session.zone_coverage["auth"]["findings_count"] == 2
