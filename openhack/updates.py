"""
Startup update check + announcements fetcher.

Calls GET /updates on the inference worker. Never blocks the TUI or
raises to the user on failure — network errors are silently swallowed.
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx

from openhack import __version__
from openhack.config import CONFIG_DIR

logger = logging.getLogger(__name__)

_DISMISSED_FILE = CONFIG_DIR / "dismissed_announcements.json"
_LAST_CHECK_FILE = CONFIG_DIR / ".last_update_check"
_RECHECK_INTERVAL = 3600  # 1 hour


@dataclass
class LatestRelease:
    version: str
    published_at: str = ""
    download_url: str = ""
    release_notes: str = ""


@dataclass
class Announcement:
    id: str
    level: str  # "info" | "warning" | "critical"
    title: str
    body: str = ""
    placement: list[str] = field(default_factory=list)
    published_at: str = ""
    expires_at: Optional[str] = None


@dataclass
class UpdateInfo:
    latest: Optional[LatestRelease] = None
    announcements: list[Announcement] = field(default_factory=list)
    has_update: bool = False


def _get_updates_url() -> str:
    if os.environ.get("OPENHACK_DEV", "0") == "1":
        return "http://localhost:8787/updates"
    return "https://api.openhack.com/updates"


def _semver_gt(a: str, b: str) -> bool:
    """Return True if version `a` is strictly greater than `b` (semver major.minor.patch)."""
    def _parse(v: str) -> tuple[int, ...]:
        v = v.lstrip("v")
        parts = v.split("-")[0].split("+")[0]  # strip pre-release/build
        return tuple(int(x) for x in parts.split(".") if x.isdigit())
    try:
        return _parse(a) > _parse(b)
    except (ValueError, TypeError):
        return False


def _is_expired(expires_at: Optional[str]) -> bool:
    if not expires_at:
        return False
    try:
        exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        return datetime.now(timezone.utc) > exp
    except (ValueError, TypeError):
        return False


def _load_dismissed() -> set[str]:
    try:
        data = json.loads(_DISMISSED_FILE.read_text())
        return set(data) if isinstance(data, list) else set()
    except Exception:
        return set()


def save_dismissed(ann_id: str) -> None:
    """Persist an announcement ID as dismissed so it won't re-appear."""
    dismissed = _load_dismissed()
    dismissed.add(ann_id)
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        _DISMISSED_FILE.write_text(json.dumps(sorted(dismissed)))
    except Exception:
        pass


def _should_check() -> bool:
    """Don't re-check if we already checked within this hour."""
    try:
        ts = float(_LAST_CHECK_FILE.read_text().strip())
        return (time.time() - ts) > _RECHECK_INTERVAL
    except Exception:
        return True


def _mark_checked() -> None:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        _LAST_CHECK_FILE.write_text(str(time.time()))
    except Exception:
        pass


async def fetch_updates(force: bool = False) -> Optional[UpdateInfo]:
    """Fetch update info from /updates. Returns None on any failure."""
    if not force and not _should_check():
        return None

    url = _get_updates_url()
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url, params={"current": __version__})
            if resp.status_code != 200:
                return None
            data = resp.json()
    except Exception:
        return None

    _mark_checked()

    info = UpdateInfo()

    # Parse latest release
    latest_raw = data.get("latest")
    if latest_raw and isinstance(latest_raw, dict):
        info.latest = LatestRelease(
            version=latest_raw.get("version", ""),
            published_at=latest_raw.get("publishedAt", ""),
            download_url=latest_raw.get("downloadUrl", ""),
            release_notes=latest_raw.get("releaseNotes", ""),
        )
        if info.latest.version and _semver_gt(info.latest.version, __version__):
            info.has_update = True

    # Parse announcements
    dismissed = _load_dismissed()
    for ann_raw in data.get("announcements") or []:
        if not isinstance(ann_raw, dict):
            continue
        ann_id = ann_raw.get("id", "")
        if ann_id in dismissed:
            continue
        if _is_expired(ann_raw.get("expiresAt")):
            continue
        info.announcements.append(Announcement(
            id=ann_id,
            level=ann_raw.get("level", "info"),
            title=ann_raw.get("title", ""),
            body=ann_raw.get("body", ""),
            placement=ann_raw.get("placement") or [],
            published_at=ann_raw.get("publishedAt", ""),
            expires_at=ann_raw.get("expiresAt"),
        ))

    return info
