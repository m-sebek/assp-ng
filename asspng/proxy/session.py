# SPDX-License-Identifier: GPL-3.0-or-later
"""One client connection: setup (spec 4.2), command handling (4.3) and errors (4.10).

A ``Session`` runs the CONNECT checks, on a ``submissions`` listener performs the TLS
handshake (only now, so the limits also bound the pending handshakes: ruling R59), connects
to the backend MTA (PTR lookup in parallel, then XCLIENT), sends ASSP-NG's own banner and
handles client commands strictly one at a time. Commands go through one verb -> handler
table (``_command_handlers``). A verb without a handler is answered with 502 and never
forwarded, so a client cannot control the MTA.
STARTTLS, AUTH, MAIL and RCPT are handled in ``session_envelope``, DATA in ``session_data``.

Logging: every client line passes ``redact_auth`` before it reaches the debug tap, and an
over-long line or a line without a known verb (it may be an AUTH payload) is only reported
by its length. Besides the dialogue the tap gets the session's events (spec 8.11): the state
mode at connect and on each change, the check decisions (``CHK``, from the engine), the PTR
lookup (``DNS``), a ``connect`` line once the PTR name is known (``ptr=-`` when the session
ended before the lookup) and a ``TLS`` line after each handshake. Replies relayed from the
MTA lose their control characters before they reach the client. Each message gets its own
maillog record; one session record is written at the end only if there was none.

Shutdown: the application calls ``notify_shutdown()`` and then cancels the task. A session that
was waiting for a client command answers 421 first; any other one closes without a word, so a
reply or a message in progress is never cut into. The session's maillog result is "shutdown".
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import time
from collections.abc import Awaitable, Callable
from functools import partial

from asspng.checks.base import (
    CheckContext,
    Phase,
    SessionInfo,
    TransactionInfo,
    spared_from_ip_score,
)
from asspng.checks.engine import R_REJECT, Outcome
from asspng.config.model import ListenerKind
from asspng.config.policy import Policy
from asspng.log.debug import DNS, SES, STATE, SessionTap
from asspng.net.dns import PtrResult
from asspng.net.ipnet import network_key, parse_ip
from asspng.proxy import session_data as data
from asspng.proxy import session_envelope as envelope
from asspng.proxy.auth import redact_auth
from asspng.proxy.backend import Backend, BackendClosed, BackendError, XclientUnsupported
from asspng.proxy.session_deps import SessionDeps as SessionDeps  # re-exported
from asspng.proxy.session_util import (
    config_int,
    config_seconds,
    config_text,
    is_known_command,
    sanitized,
    session_record,
    tls_version,
    wire_lines,
)
from asspng.proxy.xclient import format_xclient
from asspng.smtp.commands import Command, CommandSyntaxError, parse_command
from asspng.smtp.ehlo import filter_ehlo
from asspng.smtp.lines import ConnectionClosed, LineTooLong, read_line
from asspng.smtp.replies import (
    R_BACKEND_DOWN,
    R_BACKEND_LOST,
    R_BAD_ARG,
    R_BYE,
    R_HELP,
    R_IDLE,
    R_INTERNAL,
    R_LINE_TOO_LONG,
    R_NOT_IMPL,
    R_SYNTAX,
    R_TEMPFAIL,
    R_TEMPFAIL_CMD,
    R_TOO_MANY_ERRORS,
    R_VRFY,
    ReadTimeout,
    Reply,
)
from asspng.state.controller import StateMode

_log = logging.getLogger(__name__)

MAX_LINE = 2048
_CLOSE_TIMEOUT_S = 5.0
_SHUTDOWN_REPLY_TIMEOUT_S = 1.0
_PTR_UNKNOWN = PtrResult(None, True)

Handler = Callable[[Command], Awaitable[None]]


class _ClientGone(Exception):
    """Writing to the client failed: its connection is gone."""


class Session:
    """One SMTP client connection: create it per accepted connection and await ``run()``.

    ``peer`` is the client address and port as reported by the socket.
    """

    def __init__(
        self,
        deps: SessionDeps,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peer: tuple[str, int],
    ) -> None:
        self._deps = deps
        self._reader = reader
        self._writer = writer
        self._peer_port = peer[1]
        self.id = secrets.token_hex(4)
        client_ip = parse_ip(peer[0])
        self._info = SessionInfo(
            session_id=self.id,
            client_ip=client_ip,
            net_key=network_key(client_ip, self._int("network.ipv4_prefix"),
                                self._int("network.ipv6_prefix")),
            listener=deps.listener,
            tls_version=tls_version(writer),
            auth_user=None,
            helo=None,
            trusted=client_ip in deps.config.trusted,
            exempt=client_ip in deps.config.exempt,
            messages=0,
            protocol_errors=0,
            invalid_recipients=0,
        )
        self._tap = SessionTap(self.id, deps.debug_rules, deps.debug_log,
                               self._int("debug.ring_lines"))
        self._default_policy = deps.policies.default_policy()
        self._sender_policy: Policy | None = None
        self._handlers = self._command_handlers()
        self._started = deps.clock()
        self._backend: Backend | None = None
        self._ptr: PtrResult | None = None
        self._txn: TransactionInfo | None = None
        self._txn_count = 0  # transactions opened in this session
        # Set once a per-message maillog record was written: no session record then.
        self._txn_logged = False
        # True while the client sends AUTH responses: every client line is redacted.
        self._in_auth_exchange = False
        # Set when the AUTH phase (the network's failure limit) refused with 454: another
        # AUTH closes the session. A per-user block never sets it.
        self._auth_tempfailed = False
        self._slot_held = False
        self._unwatch_state: Callable[[], None] | None = None
        # True on an implicit-TLS listener until the handshake: the client cannot read SMTP.
        self._tls_pending = deps.listener.kind is ListenerKind.SUBMISSIONS
        self._closing = False
        self._client_gone = False
        self._helo_rejected = False
        self._result: str | None = None
        self._last_mta = "-"
        self._shutting_down = False
        self.idle = False  # True while the session waits for the client's next command

    def notify_shutdown(self) -> None:
        """The service stops: a cancellation that follows ends the session as "shutdown"."""
        self._shutting_down = True

    # --- lifecycle ------------------------------------------------------------------------

    async def run(self) -> None:
        """Serve the connection until it ends. Never raises, except ``CancelledError``.

        Cleanup (connection slot, backend, session maillog record, client connection) always
        runs; a cancellation is re-raised after it.
        """
        try:
            await self._serve()
        except _ClientGone:
            self._end("disconnected")
        except Exception as exc:
            await self._internal_error(exc)
        except asyncio.CancelledError:
            await self._shutdown_notice()
            raise
        finally:
            await self._cleanup()

    async def _serve(self) -> None:
        # Debug ip: rules target one client network at /32 or /64 (spec 8.11), whatever
        # prefix keys the state (5.3).
        self._tap.on_connect(network_key(self._info.client_ip), self._deps.listener.name)
        state = self._deps.state
        self._unwatch_state = state.watch(self._on_state_change)
        self._tap.line(STATE, f"mode={state.mode.name}")
        if not (await self._admit() and await self._start_implicit_tls()):
            self._tap_connect()  # no PTR lookup for a refused client
            return
        if await self._connect_backend():
            await self._reply(self._banner())
            await self._command_loop()

    async def _admit(self) -> bool:
        """Refusals before the backend is contacted; acquires the connection slot."""
        deps = self._deps
        if deps.state.mode is StateMode.TEMPFAIL or deps.memory_over_limit():
            _log.info("s=%s refused: state unavailable or memory over its limit", self.id)
            await self._finish("tempfailed", R_TEMPFAIL)
            return False
        if deps.connections.total >= self._int("limits.instance.concurrent"):
            _log.warning("s=%s refused: instance connection limit reached", self.id)
            await self._finish("tempfailed", R_BACKEND_DOWN)
            return False
        # Acquired before the CONNECT checks: the per-network count includes this session.
        deps.connections.acquire(self._info.net_key)
        self._slot_held = True
        decision = await deps.engine.run_phase(Phase.CONNECT, self._check_context())
        if decision.outcome is not Outcome.CONTINUE:
            _log.info("s=%s rejected at connect", self.id)
            await self._finish("rejected", decision.reply or R_REJECT)
            return False
        return True

    async def _start_implicit_tls(self) -> bool:
        """The TLS handshake of a ``submissions`` listener, bounded by
        ``timeouts.tls_handshake``. The listener read nothing so far (see ``listener``)."""
        if not self._tls_pending:
            return True
        context = self._deps.tls.front_context()
        if context is None:  # the listener refuses to start without; a reload keeps one
            _log.error("s=%s no TLS certificate for the submissions listener", self.id)
            self._end("tempfailed")
            return False
        try:
            await self._writer.start_tls(
                context, ssl_handshake_timeout=self._seconds("timeouts.tls_handshake"))
        except OSError as exc:  # SSLError, a handshake timeout or a reset
            _log.info("s=%s TLS handshake failed: %s", self.id, type(exc).__name__)
            self._client_lost()
            return False
        self._tls_pending = False
        self._info.tls_version = tls_version(self._writer)
        self._tap_tls()
        return True

    async def _connect_backend(self) -> bool:
        """PTR lookup and backend connect in parallel, then XCLIENT (fail closed)."""
        deps = self._deps
        backend = deps.backend_factory(deps.listener)
        self._backend = backend
        ptr, banner = await asyncio.gather(
            self._lookup_ptr(), backend.connect(), return_exceptions=True)
        self._ptr = ptr if isinstance(ptr, PtrResult) else _PTR_UNKNOWN
        self._tap_connect()
        if isinstance(banner, BackendError):
            await self._backend_down(f"{type(banner).__name__}: {banner}")
            return False
        if isinstance(banner, BaseException):
            raise banner
        self._note_mta(banner)
        if banner.code != 220:
            await self._backend_down(f"banner {banner.code}")
            return False
        if deps.listener.xclient and not await self._send_xclient(backend, self._ptr):
            return False
        deps.health.backend_result(deps.listener.name, True)
        return True

    async def _lookup_ptr(self) -> PtrResult:
        ip = self._info.client_ip
        started = time.perf_counter()
        try:
            async with asyncio.timeout(self._seconds("timeouts.ptr")):
                result = await self._deps.resolver.lookup(ip)
        except Exception as exc:  # a missing name is never fatal
            _log.debug("s=%s PTR lookup failed: %s", self.id, type(exc).__name__)
            self._tap.line(DNS, f"PTR {ip} failed: {type(exc).__name__} "
                                f"ms={(time.perf_counter() - started) * 1000:.1f}")
            return _PTR_UNKNOWN
        self._tap.line(DNS, f"PTR {ip} name={result.xclient_value} "
                            f"ms={(time.perf_counter() - started) * 1000:.1f}")
        return result

    async def _send_xclient(self, backend: Backend, ptr: PtrResult) -> bool:
        """Without XCLIENT the MTA would see the proxy's address, so failures refuse."""
        hostname = self._text("hostname")
        ip, name = self._info.client_ip, ptr.xclient_value
        self._tap.line("P>M", f"EHLO {hostname}")
        self._tap.line("P>M", format_xclient(ip, self._peer_port, name).decode().rstrip())
        try:
            greeting = await backend.xclient(ip, self._peer_port, name, hostname)
        except XclientUnsupported:
            await self._backend_down("XCLIENT is not advertised", logging.ERROR)
            return False
        except BackendError as exc:
            await self._backend_down(f"XCLIENT failed: {type(exc).__name__}: {exc}",
                                     logging.ERROR)
            return False
        self._note_mta(greeting)
        return True

    async def _backend_down(self, reason: str, level: int = logging.WARNING) -> None:
        listener = self._deps.listener.name
        failures = self._deps.health.backend_result(listener, False)
        _log.log(level, "s=%s backend of listener %s unavailable: %s (%d consecutive failures)",
                 self.id, listener, reason, failures)
        await self._finish("tempfailed", R_BACKEND_DOWN)

    # --- debug tap events -----------------------------------------------------------------

    def _tap_connect(self) -> None:
        ptr = "-" if self._ptr is None else self._ptr.xclient_value
        self._tap.line(SES, f"connect ip={self._info.client_ip} port={self._peer_port} "
                            f"ptr={ptr} listener={self._deps.listener.name}")

    def _tap_tls(self) -> None:
        """After a TLS handshake (implicit or STARTTLS)."""
        cipher = self._writer.get_extra_info("cipher")  # (name, protocol, bits) or None
        self._tap.line(SES, f"TLS {self._info.tls_version} "
                            f"cipher={cipher[0] if cipher else '-'}")

    def _on_state_change(self, old: StateMode, new: StateMode, reason: str) -> None:
        self._tap.line(STATE, f"mode={new.name} (was {old.name}): {reason}")

    def _banner(self) -> Reply:
        text = self._text("banner.text")
        return Reply.of(220, f"{self._text('hostname')} ESMTP" + (f" {text}" if text else ""))

    # --- command loop ---------------------------------------------------------------------

    def _command_handlers(self) -> dict[str, Handler]:
        """Verb -> handler. A verb missing here is answered with 502 and never forwarded."""
        return {
            "EHLO": self._on_helo,
            "HELO": self._on_helo,
            "NOOP": self._on_noop,
            "RSET": self._on_rset,
            "QUIT": self._on_quit,
            "VRFY": self._on_vrfy,
            "EXPN": self._on_vrfy,
            "HELP": self._on_help,
            "STARTTLS": partial(envelope.on_starttls, self),
            "AUTH": partial(envelope.on_auth, self),
            "MAIL": partial(envelope.on_mail, self),
            "RCPT": partial(envelope.on_rcpt, self),
            "DATA": partial(data.on_data, self),
        }

    async def _command_loop(self) -> None:
        while not self._closing:
            line = await self._read_command(idle=True)
            if line is not None:
                await self._dispatch(line)

    async def _read_command(
        self, on_too_long: Callable[[], Awaitable[None]] | None = None, *, idle: bool = False
    ) -> bytes | None:
        """Read one client line (a command or an AUTH response); None when there is no line
        to handle. ``on_too_long`` runs before an over-long line is answered. ``idle`` marks
        the read of a command, during which a shutdown answers 421."""
        try:
            line = await self._read_line(idle)
        except ReadTimeout:
            await self._finish("timeout", R_IDLE)
            return None
        except LineTooLong as exc:
            self._tap.line("C>P", f"<line too long: {exc.length} bytes>")
            if on_too_long is not None:
                await on_too_long()
            await self._protocol_error(R_LINE_TOO_LONG)
            return None
        except (ConnectionClosed, OSError):
            self._end("disconnected")
            return None
        self._tap.line("C>P", self._client_line_text(line))
        return line

    async def _read_line(self, idle: bool) -> bytes:
        """``read_line`` with ``idle`` set while it waits; a cancellation leaves it set."""
        self.idle = idle
        try:
            line = await read_line(self._reader, MAX_LINE, self._seconds("timeouts.command"))
        except Exception:
            self.idle = False
            raise
        self.idle = False
        return line

    def _client_line_text(self, line: bytes) -> str:
        """Log-safe text of a line read by ``_read_command``."""
        if not self._in_auth_exchange and not is_known_command(line, self._handlers):
            return f"<unknown command: {len(line)} bytes>"
        return self._redacted(line)

    async def _dispatch(self, line: bytes) -> None:
        try:
            command = parse_command(line)
        except CommandSyntaxError:
            await self._protocol_error(R_SYNTAX)
            return
        handler = self._handlers.get(command.verb)
        if handler is None:
            await self._protocol_error(R_NOT_IMPL)
            return
        try:
            await handler(command)
        except BackendError as exc:
            await self._backend_lost(exc)

    async def _protocol_error(self, reply: Reply | None) -> None:
        """Answer an error (None: one without a reply of its own); at the limit close the
        session and score the client network."""
        info = self._info
        info.protocol_errors += 1
        if info.protocol_errors < self._int("limits.session.protocol_errors"):
            if reply is not None:
                await self._reply(reply)
            return
        _log.info("s=%s closed after %d protocol errors", self.id, info.protocol_errors)
        await self._penalize(self._int("abuse.protocol_error_ip_score"),
                             "too many protocol errors")
        await self._finish("rejected", R_TOO_MANY_ERRORS)

    async def _refused_by_state(self, verb: str) -> bool:
        """Spec 6.2: while the state is in TEMPFAIL, MAIL, RCPT and DATA get 451 4.3.0 and
        nothing is forwarded. Returns whether the command was refused."""
        if self._deps.state.mode is not StateMode.TEMPFAIL:
            return False
        _log.info("s=%s %s refused: state unavailable", self.id, verb)
        await self._reply(R_TEMPFAIL_CMD)
        return True

    async def _penalize(self, points: int, reason: str) -> None:
        """Add IP score, sparing the clients the check engine spares too."""
        info = self._info
        if spared_from_ip_score(info):
            return
        try:
            await self._deps.penalty_box.add_score(info.net_key, points, reason)
        except Exception as exc:  # e.g. the state store refuses (TEMPFAIL)
            _log.warning("s=%s cannot add IP score: %s", self.id, type(exc).__name__)

    async def _backend_lost(self, exc: BackendError) -> None:
        _log.warning("s=%s lost the backend connection: %s: %s",
                     self.id, type(exc).__name__, exc)
        self._deps.health.record("backend_lost")
        await self._finish("tempfailed", R_BACKEND_LOST)

    # --- commands -------------------------------------------------------------------------

    async def _on_helo(self, command: Command) -> None:
        if not command.arg:
            await self._protocol_error(R_BAD_ARG)
            return
        self._info.helo = command.arg
        decision = await self._deps.engine.run_phase(Phase.HELO, self._check_context())
        if decision.outcome is not Outcome.CONTINUE:
            # Not forwarded; the client may try again (unless the reply is a 421).
            self._helo_rejected = True
            await self._refuse(decision.reply or R_REJECT)
            return
        self._helo_rejected = False
        mta = await self._forward(f"{command.verb} {command.arg}".encode())
        if mta.is_positive:
            self._reset_transaction()  # EHLO and HELO imply RSET (RFC 5321 4.1.4)
        hostname = self._text("hostname")
        if command.verb == "HELO":
            await self._reply(Reply.of(250, hostname) if mta.is_positive else mta)
            return
        await self._reply(filter_ehlo(
            mta,
            hostname=hostname,
            offer_starttls=self._offer_starttls(),
            auth_allowed=self._auth_allowed(),
            max_size=self._int("max_message_size"),
        ))

    def _offer_starttls(self) -> bool:
        """STARTTLS is advertised only when it is handled, configured and not yet active."""
        return ("STARTTLS" in self._handlers and self._info.tls_version is None
                and self._deps.tls.front_context() is not None)

    def _auth_allowed(self) -> bool:
        """AUTH is advertised only when it is handled, allowed and TLS is active."""
        return ("AUTH" in self._handlers and self._deps.listener.auth
                and self._info.tls_version is not None)

    async def _on_noop(self, command: Command) -> None:
        await self._reply(await self._forward(b"NOOP"))

    async def _on_rset(self, command: Command) -> None:
        mta = await self._forward(b"RSET")
        if mta.is_positive:
            self._reset_transaction()
        await self._reply(mta)

    async def _on_quit(self, command: Command) -> None:
        self._end("quit")
        try:
            await self._forward(b"QUIT")
        except BackendError as exc:  # the client is leaving anyway
            _log.debug("s=%s QUIT to the backend failed: %s", self.id, type(exc).__name__)
        await self._reply(R_BYE)

    async def _on_vrfy(self, command: Command) -> None:
        await self._reply(R_VRFY)

    async def _on_help(self, command: Command) -> None:
        await self._reply(R_HELP)

    def _reset_transaction(self) -> None:
        self._txn = None

    # --- I/O helpers ----------------------------------------------------------------------

    async def _forward(self, line: bytes) -> Reply:
        """Send one command line to the MTA and return its reply; raises ``BackendError``."""
        backend = self._backend
        if backend is None:
            raise BackendClosed("no backend connection")
        self._tap.line("P>M", self._redacted(line))
        reply = await backend.command(line, self._seconds("timeouts.backend_command"))
        self._note_mta(reply)
        return reply

    def _note_mta(self, reply: Reply) -> None:
        for line in wire_lines(reply):
            self._tap.line("M>P", line)
        self._last_mta = f"{reply.code} {reply.lines[-1]}" if reply.lines else str(reply.code)

    async def _reply(self, reply: Reply, timeout_s: float | None = None) -> None:
        """Send a reply to the client; control characters in its text become spaces.
        The client gets ``timeout_s`` (default ``timeouts.command``) to take it."""
        clean = sanitized(reply)
        if self._tls_pending:  # refused before the implicit-TLS handshake: close silently
            self._tap.line("P>C", f"<not sent before the TLS handshake: {clean.code}>")
            return
        for line in wire_lines(clean):
            self._tap.line("P>C", line)
        if self._client_gone:
            raise _ClientGone("client connection lost")
        if timeout_s is None:
            timeout_s = self._seconds("timeouts.command")
        try:
            self._writer.write(clean.encode())
            async with asyncio.timeout(timeout_s):
                await self._writer.drain()
        except (OSError, TimeoutError) as exc:
            self._client_gone = True
            raise _ClientGone("client connection lost") from exc

    async def _refuse(self, reply: Reply) -> None:
        """Send a refusal (a check decision's reply); a 421 also ends the session, since
        421 means the server closes the connection (RFC 5321 3.8, ruling R63)."""
        if reply.code == 421:
            _log.info("s=%s closed after a 421 refusal", self.id)
            await self._finish("rejected", reply)
        else:
            await self._reply(reply)

    async def _finish(self, result: str, reply: Reply) -> None:
        """End the session with ``result`` after a last reply."""
        self._end(result)
        await self._reply(reply)

    def _end(self, result: str) -> None:
        """Stop the command loop; the first result set is the session's result."""
        if self._result is None:
            self._result = result
        self._closing = True

    def _client_lost(self) -> None:
        """The client connection is unusable: end the session; cleanup aborts it."""
        self._client_gone = True
        self._end("disconnected")

    def _redacted(self, line: bytes) -> str:
        """Log-safe text of a client line (or of a line built from one)."""
        return redact_auth(line, self._in_auth_exchange).decode("utf-8", "replace")

    def _check_context(self, txn: TransactionInfo | None = None) -> CheckContext:
        """The checks' view; ``txn`` replaces the current transaction (MAIL's candidate)."""
        deps = self._deps
        return CheckContext(
            session=self._info,
            txn=self._txn if txn is None else txn,
            config=deps.config,
            default_policy=self._default_policy,
            sender_policy=self._sender_policy,
            state=deps.state,
            clock=deps.clock,
            connections=deps.connections,
            tap=self._tap.line,
        )

    def _int(self, key: str) -> int:
        return config_int(self._deps.config, key)

    def _seconds(self, key: str) -> float:
        return config_seconds(self._deps.config, key)

    def _text(self, key: str) -> str:
        return config_text(self._deps.config, key)

    # --- errors and cleanup ---------------------------------------------------------------

    async def _internal_error(self, exc: Exception) -> None:
        """Only this session ends: log, count and answer 421 if the client is still there."""
        self._result = "error"
        self._closing = True
        _log.error("s=%s unhandled error, closing the session", self.id, exc_info=exc)
        try:
            self._deps.health.record("session_error")
        except Exception as health_exc:
            _log.warning("s=%s cannot count the error: %s", self.id,
                         type(health_exc).__name__)
        if not self._client_gone:
            with contextlib.suppress(Exception):
                await self._reply(R_INTERNAL)

    async def _shutdown_notice(self) -> None:
        """After a cancellation by the shutdown: answer 421 if the client was between
        commands (best effort, bounded), never in the middle of a reply or of DATA."""
        if not self._shutting_down:
            return
        self._end("shutdown")
        if self.idle and not self._client_gone:
            self.idle = False
            with contextlib.suppress(Exception):
                await self._reply(R_TEMPFAIL, _SHUTDOWN_REPLY_TIMEOUT_S)

    async def _cleanup(self) -> None:
        """Release the slot, write the session record and close both connections.

        Never raises an ``Exception``. If a cancellation interrupts the closing, the client
        connection is aborted before the cancellation propagates.
        """
        if self._unwatch_state is not None:
            self._unwatch_state()
            self._unwatch_state = None
        if self._slot_held:
            self._slot_held = False
            self._deps.connections.release(self._info.net_key)
        if not self._txn_logged:
            self._write_session_record()
        closed = False
        try:
            await self._close_backend()
            if self._client_gone:
                self._abort_client()  # a failed TLS handshake never finishes a close
            else:
                await self._close_client()
            closed = True
        finally:
            if not closed:
                self._abort_client()

    def _write_session_record(self) -> None:
        try:
            self._deps.maillog(session_record(
                self._info, self._ptr, instance=self._text("instance"),
                result=self._final_result(), mta=self._last_mta, started=self._started,
                now=self._deps.clock()))
        except Exception as exc:
            _log.warning("s=%s cannot write the session record: %s", self.id,
                         type(exc).__name__)

    def _final_result(self) -> str:
        result = self._result or "disconnected"
        if self._helo_rejected and result in ("quit", "disconnected"):
            return "rejected"  # the session ended on a HELO rejection
        return result

    async def _close_backend(self) -> None:
        backend, self._backend = self._backend, None
        if backend is None:
            return
        try:
            await backend.close()
        except Exception as exc:
            _log.warning("s=%s closing the backend failed: %s", self.id, type(exc).__name__)

    async def _close_client(self) -> None:
        try:
            self._writer.close()
            async with asyncio.timeout(_CLOSE_TIMEOUT_S):
                await self._writer.wait_closed()
        except Exception:  # timed out, or the connection was reset
            self._abort_client()

    def _abort_client(self) -> None:
        with contextlib.suppress(Exception):
            self._writer.transport.abort()
