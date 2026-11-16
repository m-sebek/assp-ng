# SPDX-License-Identifier: GPL-3.0-or-later
"""Envelope commands of a session: STARTTLS and AUTH (spec 4.3, 4.5), MAIL and RCPT with the
relay decision (4.6) and policy grouping (4.11).

The handlers are module functions taking the ``Session``; ``Session._command_handlers``
registers them. They are part of the session: they read and change its package-private
attributes (``_info``, ``_txn``, ``_deps``, ``_tap``, ``_reader``, ``_writer``...) and use its
helpers (``_reply``, ``_forward``, ``_protocol_error``...), so only the session's command
loop may call them.

Protocol errors (spec 4.3) are wrong sequence (503), bad arguments (501), syntax (500),
commands that are not offered (502) and relay attempts. Policy refusals (530, 538, 552,
454, 451, 452) are not counted.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import TYPE_CHECKING

from asspng.checks.base import Phase, SessionInfo, TransactionInfo
from asspng.checks.engine import R_REJECT, Outcome
from asspng.config.model import ListenerKind
from asspng.config.policy import Policy
from asspng.proxy.auth import AuthExchange, AuthSyntaxError
from asspng.proxy.session_util import tls_version
from asspng.smtp.address import Address
from asspng.smtp.commands import (
    Command,
    CommandArgumentError,
    CommandSyntaxError,
    parse_mail_from,
    parse_rcpt_to,
)
from asspng.smtp.replies import (
    R_AUTH_REQUIRED,
    R_AUTH_TEMPFAIL,
    R_BAD_ARG,
    R_BAD_SEQUENCE,
    R_DOMAINS_UNAVAILABLE,
    R_ENCRYPTION_REQUIRED,
    R_NOT_IMPL,
    R_POLICY_SPLIT,
    R_RELAY_DENIED,
    R_SIZE,
    R_SYNTAX,
    R_TLS_ACTIVE,
    R_TLS_READY,
    R_TLS_UNAVAILABLE,
    R_TOO_MANY_ERRORS,
    R_TOO_MANY_RCPT,
    Reply,
)

if TYPE_CHECKING:
    from asspng.proxy.session import Session

_log = logging.getLogger(__name__)

_BLANKS = re.compile(r"[ \t]+")
_CONTROL = re.compile(rb"[\x00-\x1f\x7f]")
_SUBMISSION_KINDS = frozenset({ListenerKind.SUBMISSION, ListenerKind.SUBMISSIONS})
# Parameters forwarded to the MTA; any other one is refused with 501. MAIL's AUTH= is
# dropped instead: clients such as Outlook send it, and the MTA must not trust it.
_MAIL_PARAMS = frozenset({"SIZE", "BODY", "SMTPUTF8", "RET", "ENVID"})
_MAIL_DROPPED = frozenset({"AUTH"})
_RCPT_PARAMS = frozenset({"NOTIFY", "ORCPT"})
_FLAG_PARAMS = frozenset({"SMTPUTF8"})  # the only allowed parameter without a value
_INVALID_RCPT_CODES = frozenset({550, 551, 553})


def _accepted(reply: Reply) -> bool:
    return 200 <= reply.code < 300


# --- STARTTLS ------------------------------------------------------------------------------


def _discard_buffered(reader: asyncio.StreamReader) -> int:
    """Drop the bytes already buffered in ``reader``; return how many there were.

    ``StreamWriter.start_tls`` keeps the reader's buffer, so plaintext a client pipelined
    after STARTTLS would be read as if it had arrived over TLS (command injection, the
    CVE-2011-0411 class). After AUTH, pipelined bytes may be credentials meant for an
    exchange that never started or already ended. asyncio has no public way to empty the
    buffer, so this uses the CPython-internal ``StreamReader._buffer`` (a bytearray). If it
    ever disappears the lookup raises and the session ends with an internal error: it fails
    closed.
    """
    buffer: bytearray = getattr(reader, "_buffer")
    count = len(buffer)
    buffer.clear()
    return count


async def on_starttls(session: Session, command: Command) -> None:
    """Upgrade the client connection (RFC 3207); HELO and the transaction are reset."""
    info = session._info
    if command.arg:
        await session._protocol_error(R_BAD_ARG)
        return
    if info.tls_version is not None:  # after STARTTLS, or on an implicit-TLS listener
        await session._protocol_error(R_TLS_ACTIVE)
        return
    context = session._deps.tls.front_context()
    if context is None:
        await session._reply(R_TLS_UNAVAILABLE)
        return
    if session._txn is not None:
        await session._protocol_error(R_BAD_SEQUENCE)
        return
    timeout = session._seconds("timeouts.tls_handshake")
    await session._reply(R_TLS_READY)
    # No await between the drain above and start_tls: every byte read so far is plaintext.
    discarded = _discard_buffered(session._reader)
    if discarded:
        _log.warning("s=%s discarded %d bytes sent after STARTTLS", session.id, discarded)
        info.protocol_errors += 1
    try:
        await session._writer.start_tls(context, ssl_handshake_timeout=timeout)
    except OSError as exc:  # SSLError, a handshake timeout or a reset
        _log.info("s=%s TLS handshake failed: %s", session.id, type(exc).__name__)
        session._client_lost()
        return
    info.tls_version = tls_version(session._writer)
    session._tap_tls()
    info.helo = None
    session._helo_rejected = False
    session._reset_transaction()


# --- AUTH ----------------------------------------------------------------------------------


async def on_auth(session: Session, command: Command) -> None:
    """Relay an AUTH exchange to the MTA, which verifies the credentials (spec 4.5).

    Whatever the outcome, bytes the client pipelined after it are dropped unread and never
    logged: AUTH is the last command of a pipelined group (RFC 4954), PIPELINING is not
    offered, and such bytes may be credentials.
    """
    try:
        await _authenticate(session, command)
    finally:
        discarded = _discard_buffered(session._reader)
        if discarded:
            _log.warning("s=%s discarded %d bytes sent after an authentication command",
                         session.id, discarded)


async def _authenticate(session: Session, command: Command) -> None:
    deps, info = session._deps, session._info
    if not deps.listener.auth:
        await session._protocol_error(R_NOT_IMPL)
        return
    if info.tls_version is None:
        await session._reply(R_ENCRYPTION_REQUIRED)
        return
    if session._auth_tempfailed:
        await _auth_after_tempfail(session)
        return
    if info.auth_user is not None or session._txn is not None:
        await session._protocol_error(R_BAD_SEQUENCE)
        return
    started = _start_exchange(command.arg)
    if started is None:
        await session._protocol_error(R_BAD_ARG)
        return
    exchange, line = started
    decision = await deps.engine.run_phase(Phase.AUTH, session._check_context())
    if decision.outcome is not Outcome.CONTINUE:
        reply = decision.reply or R_AUTH_TEMPFAIL
        if reply == R_AUTH_TEMPFAIL:  # this network is over its failure limit
            session._auth_tempfailed = True  # the next AUTH closes the session
        await session._refuse(reply)
        return
    if exchange.username is not None and await _user_blocked(session, exchange.username):
        await session._reply(R_AUTH_TEMPFAIL)  # nothing was forwarded
        return
    await _relay_exchange(session, exchange, line)


def _start_exchange(arg: str) -> tuple[AuthExchange, bytes] | None:
    """The exchange and the AUTH line to forward; None for a bad mechanism or response."""
    words = _BLANKS.split(arg) if arg else []
    if len(words) not in (1, 2):
        return None
    try:
        exchange = AuthExchange(words[0], words[1] if len(words) == 2 else None)
    except AuthSyntaxError:
        return None
    return exchange, " ".join(["AUTH", words[0].upper(), *words[1:]]).encode()


async def _relay_exchange(session: Session, exchange: AuthExchange, line: bytes) -> None:
    """Relay the exchange line by line until the MTA's final reply."""
    reply = await session._forward(line)
    try:
        while reply.code == 334:
            # Set from the MTA's 334, before the response is read: it is never tapped,
            # logged or forwarded in clear.
            session._in_auth_exchange = True
            await session._reply(reply)
            response = await session._read_command(lambda: _cancel_exchange(session))
            if response is None:  # timeout, disconnect or an over-long line (answered)
                return
            next_reply = await _client_response(session, exchange, response)
            if next_reply is None:
                return
            reply = next_reply
    finally:
        session._in_auth_exchange = False
    await _auth_result(session, exchange, reply)


async def _client_response(
    session: Session, exchange: AuthExchange, response: bytes
) -> Reply | None:
    """Track and forward one client response; None when the exchange ended locally."""
    if _CONTROL.search(response):  # the MTA must never get a CR or another control byte
        await _cancel_exchange(session)
        await session._protocol_error(R_BAD_ARG)
        return None
    username_known = exchange.username is not None
    try:
        exchange.on_client_line(response.decode("ascii", "replace"))
    except AuthSyntaxError:
        await _cancel_exchange(session)
        await session._protocol_error(R_BAD_ARG)
        return None
    username = exchange.username
    if not username_known and username is not None and await _user_blocked(session, username):
        await _cancel_exchange(session)  # the response with the username is not forwarded
        await session._reply(R_AUTH_TEMPFAIL)
        return None
    return await session._forward(response)


async def _cancel_exchange(session: Session) -> None:
    """Cancel the exchange open at the MTA; its reply is not relayed."""
    await session._forward(b"*")


async def _auth_result(session: Session, exchange: AuthExchange, reply: Reply) -> None:
    """235 authenticates the session; 5xx counts as a failure unless the client cancelled."""
    if reply.code == 235:
        session._info.auth_user = exchange.username
        session._sender_policy = session._deps.policies.for_sender(exchange.username or "")
    elif reply.is_permanent and not exchange.cancelled:
        _log.info("s=%s authentication failed with %d", session.id, reply.code)
        await _record_failure(session, exchange.username)
    await session._reply(reply)


async def _auth_after_tempfail(session: Session) -> None:
    _log.info("s=%s closed: authentication retried after a temporary failure", session.id)
    await session._penalize(session._int("abuse.auth_failure_ip_score"),
                            "authentication retried after a temporary failure")
    await session._finish("rejected", R_TOO_MANY_ERRORS)


async def _user_blocked(session: Session, username: str) -> bool:
    """Whether the user is over its failure limit. A blocked user gets 454 but is never
    escalated to 421: whoever locked the account elsewhere must not get this network
    scored."""
    deps = session._deps
    limit = session._int("limits.auth.failures_per_user")
    try:
        return await deps.auth_limits.user_blocked(deps.state, username, limit)
    except Exception as exc:  # the state store refuses: fail closed
        _log.warning("s=%s cannot read the authentication failures: %s",
                     session.id, type(exc).__name__)
        return True


async def _record_failure(session: Session, username: str | None) -> None:
    deps = session._deps
    window_s = session._int("limits.auth.window")
    try:
        await deps.auth_limits.record_failure(deps.state, session._info.net_key, username,
                                              window_s)
    except Exception as exc:
        _log.warning("s=%s cannot count the authentication failure: %s",
                     session.id, type(exc).__name__)


# --- MAIL ----------------------------------------------------------------------------------


async def on_mail(session: Session, command: Command) -> None:
    """Start a transaction: a new ``TransactionInfo`` once the MTA accepts the sender."""
    deps, info = session._deps, session._info
    if await session._refused_by_state("MAIL"):
        return
    if info.helo is None or session._helo_rejected or session._txn is not None:
        await session._protocol_error(R_BAD_SEQUENCE)
        return
    if deps.listener.kind in _SUBMISSION_KINDS and info.auth_user is None:
        await session._reply(R_AUTH_REQUIRED)
        return
    try:
        mail = parse_mail_from(command.arg)
    except CommandArgumentError:
        await session._protocol_error(R_BAD_ARG)
        return
    except CommandSyntaxError:
        await session._protocol_error(R_SYNTAX)
        return
    params = _forwarded_params(mail.params, _MAIL_PARAMS, _MAIL_DROPPED)
    if params is None:
        await session._protocol_error(R_BAD_ARG)
        return
    size = params.get("SIZE")
    if size is not None and int(size) > session._int("max_message_size"):
        await session._reply(R_SIZE)
        return
    sender = _path_text(mail.path)
    session._tap.on_envelope(sender, [], info.auth_user)
    txn = _new_transaction(session._txn_count + 1, mail.path, info)
    decision = await deps.engine.run_phase(Phase.MAIL, session._check_context(txn))
    if decision.outcome is not Outcome.CONTINUE:
        await session._refuse(decision.reply or R_REJECT)
        return
    mta = await session._forward(_envelope_line("MAIL FROM:", sender, params))
    if _accepted(mta):
        session._txn_count += 1
        session._txn = txn
    await session._reply(mta)


def _new_transaction(number: int, sender: Address | None, info: SessionInfo
                     ) -> TransactionInfo:
    """A transaction that starts from the session's pre-MAIL check results (R62)."""
    return TransactionInfo(number=number, mail_from=sender, recipients=[], current_rcpt=None,
                           policy=None, score=info.score, reasons=list(info.reasons),
                           would_reject=list(info.would_reject), warn=False, message=None)


def _path_text(path: Address | None) -> str:
    """The address as the client sent it (without a source route); ``""`` for ``<>``."""
    return "" if path is None else str(path)


def _forwarded_params(
    params: dict[str, str | None],
    allowed: frozenset[str],
    dropped: frozenset[str] = frozenset(),
) -> dict[str, str | None] | None:
    """The parameters to forward, in the client's order; None if one is refused."""
    kept: dict[str, str | None] = {}
    for key, value in params.items():
        if key in dropped:
            continue
        if key not in allowed or (value is None) != (key in _FLAG_PARAMS):
            return None
        kept[key] = value
    size = kept.get("SIZE")
    if size is not None and not (size.isascii() and size.isdigit()):
        return None
    return kept


def _envelope_line(prefix: str, path: str, params: dict[str, str | None]) -> bytes:
    """MAIL or RCPT rebuilt from the parsed command, so nothing else reaches the MTA."""
    words = [f"{prefix}<{path}>"]
    words += [key if value is None else f"{key}={value}" for key, value in params.items()]
    return " ".join(words).encode()


# --- RCPT ----------------------------------------------------------------------------------


async def on_rcpt(session: Session, command: Command) -> None:
    """Relay decision, recipient limit and policy grouping, then the RCPT checks."""
    if await session._refused_by_state("RCPT"):
        return
    txn = session._txn
    if txn is None:
        await session._protocol_error(R_BAD_SEQUENCE)
        return
    try:
        rcpt = parse_rcpt_to(command.arg)
    except CommandArgumentError:
        await session._protocol_error(R_BAD_ARG)
        return
    except CommandSyntaxError:
        await session._protocol_error(R_SYNTAX)
        return
    params = _forwarded_params(rcpt.params, _RCPT_PARAMS)
    if params is None:
        await session._protocol_error(R_BAD_ARG)
        return
    if not await _relay_allowed(session, rcpt.path):
        return
    if len(txn.recipients) >= session._int("limits.message.recipients"):
        await session._reply(R_TOO_MANY_RCPT)
        return
    policy = session._deps.policies.for_recipient(rcpt.path)
    if txn.policy is not None and txn.policy.fingerprint != policy.fingerprint:
        # RFC 5321: the client sends this recipient again in a new transaction.
        await session._reply(R_POLICY_SPLIT)
        return
    await _check_and_forward(session, txn, rcpt.path, policy, params)


def _routing_syntax(rcpt: Address) -> bool:
    """Whether the local part routes onwards: ``%`` or ``!``, or a quoted ``@``, ``%`` or
    ``!``. An MTA may deliver ``a%remote@local`` to ``a@remote`` (ruling R61)."""
    local = rcpt.local
    if local.startswith('"'):
        return any(c in local[1:-1] for c in "@%!")
    return "%" in local or "!" in local


async def _relay_allowed(session: Session, rcpt: Address) -> bool:
    """Authenticated or trusted clients, then local domains (and a bare postmaster). For
    everybody else, routing syntax in the local part is a relay attempt (ruling R61)."""
    info = session._info
    if info.auth_user is not None or info.trusted:
        return True
    domains = session._deps.domains()
    routed = _routing_syntax(rcpt)
    if not routed and domains.is_local(rcpt.domain):
        return True
    if not routed and not domains.available:
        await session._reply(R_DOMAINS_UNAVAILABLE)
        return False
    _log.info("s=%s relay denied", session.id)
    await session._penalize(session._int("abuse.relay_denied_ip_score"), "relay attempt")
    await session._protocol_error(R_RELAY_DENIED)
    return False


async def _check_and_forward(
    session: Session, txn: TransactionInfo, rcpt: Address, policy: Policy,
    params: dict[str, str | None],
) -> None:
    """RCPT checks, forwarding and the MTA's verdict.

    The checks already see the recipient's policy. It stays the transaction's policy only
    when the recipient is accepted: rejected recipients do not count (spec 4.11).
    """
    previous = txn.policy
    txn.policy, txn.current_rcpt = previous or policy, rcpt
    decision = await session._deps.engine.run_phase(Phase.RCPT, session._check_context())
    txn.current_rcpt = None
    if decision.outcome is not Outcome.CONTINUE:
        txn.policy = previous
        await session._refuse(decision.reply or R_REJECT)
        return
    mta = await session._forward(_envelope_line("RCPT TO:", str(rcpt), params))
    if not _accepted(mta):
        txn.policy = previous
        if mta.code in _INVALID_RCPT_CODES:
            await _invalid_recipient(session, mta)
        else:
            await session._reply(mta)
        return
    txn.recipients.append(rcpt)
    session._tap.on_envelope(_path_text(txn.mail_from), [str(r) for r in txn.recipients],
                             session._info.auth_user)
    await session._reply(mta)


async def _invalid_recipient(session: Session, mta: Reply) -> None:
    """Relay the MTA's rejection; at the limit close the session and score the network."""
    info = session._info
    info.invalid_recipients += 1
    if info.invalid_recipients < session._int("limits.session.invalid_recipients"):
        await session._reply(mta)
        return
    _log.info("s=%s closed after %d invalid recipients", session.id, info.invalid_recipients)
    await session._penalize(session._int("abuse.invalid_recipient_ip_score"),
                            "too many invalid recipients")
    await session._finish("rejected", R_TOO_MANY_ERRORS)
