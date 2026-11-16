# SPDX-License-Identifier: GPL-3.0-or-later
"""Alerts by email (smtplib) and webhook (urllib), rate limited per event (design 8.6)."""

from __future__ import annotations

import asyncio
import email.utils
import json
import logging
import re
import smtplib
import socket
import urllib.error
import urllib.request
from collections.abc import Callable
from email.message import EmailMessage
from urllib.parse import urlsplit

log = logging.getLogger(__name__)

_EVENT_BAD = re.compile(r"[^A-Za-z0-9._-]")
_WEBHOOK_TIMEOUT_S = 10
_SMTP_TIMEOUT_S = 10


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def _send_email(host: str, port: int, msg: EmailMessage) -> None:
    with smtplib.SMTP(host, port, timeout=_SMTP_TIMEOUT_S) as smtp:
        smtp.send_message(msg)


def _post_webhook(url: str, body: bytes, timeout: float) -> None:
    request = urllib.request.Request(
        url, data=body, method="POST", headers={"Content-Type": "application/json"})
    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(request, timeout=timeout):
        pass


def event_name(event: str) -> str:
    """The event as used in subjects, payloads and rate limits: [A-Za-z0-9._-], 64 chars."""
    return _EVENT_BAD.sub("_", event)[:64] or "event"


def _safe_url(url: str) -> str:
    """Only scheme://host[:port] of the URL, for logging (paths can carry secrets)."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or "?"
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return f"{urlsplit(url).scheme}://<invalid url>"
    return f"{parts.scheme}://{host}{port}"


class Alerter:
    """Sends an alert on each configured channel, at most once per event per interval."""

    def __init__(
        self,
        *,
        email: str,
        webhook: str,
        smtp_server: str,
        min_interval_s: int,
        clock: Callable[[], float],
        instance: str,
        sender: str | None = None,
        send_email: Callable[[str, int, EmailMessage], None] = _send_email,
        post_webhook: Callable[[str, bytes, float], None] = _post_webhook,
    ) -> None:
        self._email = email
        self._webhook = webhook.strip()
        self._smtp_server = smtp_server
        self._min_interval = min_interval_s
        self._clock = clock
        self._instance = instance
        self.sender = sender or f"assp-ng@{socket.getfqdn()}"
        self._send_email = send_email
        self._post_webhook = post_webhook
        self._last: dict[str, float] = {}
        self._scheme_logged = False

    async def notify(self, event: str, message: str) -> bool:
        """Deliver the alert; ``True`` if at least one channel delivered. Never raises."""
        name = event_name(event)
        now = self._clock()
        last = self._last.get(name)
        if last is not None and now - last < self._min_interval:
            return False
        self._last[name] = now  # attempts count, so a failed delivery uses up the slot
        results: list[bool] = []
        if self._email:
            results.append(await self._deliver("email", self._email_job, name, message))
        if self._webhook:
            results.append(await self._deliver("webhook", self._webhook_job, name, message, now))
        return any(results)

    async def _deliver(self, channel: str, job: Callable[..., None], *args: object) -> bool:
        try:
            await asyncio.to_thread(job, *args)
        except _Refused:
            return False
        except Exception as exc:
            log.warning("alert delivery by %s failed: %s: %s", channel, type(exc).__name__,
                        _reason(exc))
            return False
        return True

    def _email_job(self, name: str, message: str) -> None:
        host, _, port = self._smtp_server.rpartition(":")
        msg = EmailMessage()
        msg["From"] = self.sender
        msg["To"] = self._email
        msg["Subject"] = f"[ASSP-NG {self._instance}] {name}"
        msg["Date"] = email.utils.formatdate(localtime=True)
        msg["Message-ID"] = email.utils.make_msgid(domain=self.sender.rpartition("@")[2] or None)
        msg.set_content(message)
        self._send_email(host, int(port), msg)

    def _webhook_job(self, name: str, message: str, ts: float) -> None:
        if urlsplit(self._webhook).scheme.lower() not in ("http", "https"):
            if not self._scheme_logged:
                self._scheme_logged = True
                log.warning("alert webhook refused: unsupported URL scheme (http and https only)")
            raise _Refused
        body = json.dumps({"instance": self._instance, "event": name, "message": message,
                           "ts": ts}).encode("utf-8")
        try:
            self._post_webhook(self._webhook, body, _WEBHOOK_TIMEOUT_S)
        except Exception as exc:
            raise _WebhookError(f"{_safe_url(self._webhook)} {type(exc).__name__}") from None


class _Refused(Exception):
    pass


class _WebhookError(Exception):
    pass


def _reason(exc: Exception) -> str:
    return str(exc)[:100]
