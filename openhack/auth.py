"""
OpenHack device-code login flow.

Talks to the web app's CLI auth endpoints:
  POST /api/cli/auth          — start session, returns device_code + user_code
  POST /api/cli/auth/poll     — poll for approval, returns token on success
"""

import asyncio
import webbrowser
from dataclasses import dataclass
from typing import Optional

import aiohttp

from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import HTML


POLL_INTERVAL_SECONDS = 2
MAX_POLL_SECONDS = 600


class DeviceLoginError(Exception):
    pass


class DeviceLoginExpired(DeviceLoginError):
    pass


class DeviceLoginCancelled(DeviceLoginError):
    pass


@dataclass
class DeviceCodeStart:
    device_code: str
    user_code: str
    verification_url: str
    expires_in: int


@dataclass
class LoginResult:
    token: str
    org_id: Optional[str] = None
    org_slug: Optional[str] = None
    org_name: Optional[str] = None
    user_email: Optional[str] = None
    user_first_name: Optional[str] = None
    user_last_name: Optional[str] = None


def _html(text: str) -> None:
    print_formatted_text(HTML(text))


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


async def _start_device_flow(session: aiohttp.ClientSession, app_url: str) -> DeviceCodeStart:
    url = f"{app_url.rstrip('/')}/api/cli/auth"
    try:
        async with session.post(url) as resp:
            if resp.status != 200:
                body = await resp.text()
                raise DeviceLoginError(f"Failed to start login (HTTP {resp.status}): {body[:200]}")
            data = await resp.json()
    except aiohttp.ClientConnectorError as exc:
        raise DeviceLoginError(
            f"Could not reach OpenHack at {app_url}. Is the app running?"
        ) from exc
    except aiohttp.ClientError as exc:
        raise DeviceLoginError(f"Network error talking to {app_url}: {exc}") from exc
    return DeviceCodeStart(
        device_code=data["device_code"],
        user_code=data["user_code"],
        verification_url=data["verification_url"],
        expires_in=int(data.get("expires_in", 900)),
    )


async def _poll_once(session: aiohttp.ClientSession, app_url: str, device_code: str) -> tuple[str, Optional[dict]]:
    """Returns (status, payload). status ∈ {pending, approved, expired}.

    payload (on approved) is the full poll response: {token, org: {id, slug, name}}.
    """
    url = f"{app_url.rstrip('/')}/api/cli/auth/poll"
    try:
        async with session.post(url, json={"device_code": device_code}) as resp:
            if resp.status == 410:
                return ("expired", None)
            if resp.status != 200:
                body = await resp.text()
                raise DeviceLoginError(f"Poll failed (HTTP {resp.status}): {body[:200]}")
            data = await resp.json()
    except aiohttp.ClientError:
        # Transient network blip — surface as pending so polling continues.
        return ("pending", None)

    status = data.get("status", "")
    if status == "approved":
        return ("approved", data)
    if status == "pending":
        return ("pending", None)
    return (status or "unknown", None)


async def device_login(app_url: str) -> LoginResult:
    """Run the device-code login flow. Returns token + org context.

    Raises DeviceLoginError on failure, DeviceLoginCancelled on user interrupt.
    """
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        start = await _start_device_flow(session, app_url)

        _html("")
        _html(f'  <b><ansicyan>Login with OpenHack</ansicyan></b>')
        _html("")
        _html(f'  Your verification code: <b><ansiyellow>{_esc(start.user_code)}</ansiyellow></b>')
        _html("")
        _html(f'  <ansigray>Opening browser at:</ansigray>')
        _html(f'  <ansigray>{_esc(start.verification_url)}</ansigray>')
        _html("")

        try:
            webbrowser.open(start.verification_url)
        except Exception:
            pass

        _html(f'  <ansigray>Waiting for approval... (Ctrl+C to cancel)</ansigray>')
        _html("")

        elapsed = 0
        try:
            while elapsed < MAX_POLL_SECONDS:
                await asyncio.sleep(POLL_INTERVAL_SECONDS)
                elapsed += POLL_INTERVAL_SECONDS

                status, payload = await _poll_once(session, app_url, start.device_code)

                if status == "approved":
                    if not payload or not payload.get("token"):
                        raise DeviceLoginError("Approval succeeded but no token was returned.")
                    org = payload.get("org") or {}
                    user = payload.get("user") or {}
                    result = LoginResult(
                        token=payload["token"],
                        org_id=org.get("id"),
                        org_slug=org.get("slug"),
                        org_name=org.get("name"),
                        user_email=user.get("email"),
                        user_first_name=user.get("firstName"),
                        user_last_name=user.get("lastName"),
                    )
                    org_name = result.org_name or "(no org)"
                    _html(f'  <b><ansigreen>✓</ansigreen></b> Logged in to <b>{_esc(org_name)}</b>.')
                    _html("")
                    return result

                if status == "expired":
                    raise DeviceLoginExpired(
                        "Login code expired before approval. Please run setup again."
                    )

                # status == "pending" — keep polling
        except asyncio.CancelledError:
            raise DeviceLoginCancelled("Login cancelled.")
        except KeyboardInterrupt:
            raise DeviceLoginCancelled("Login cancelled.")

    raise DeviceLoginExpired("Login timed out waiting for approval.")
