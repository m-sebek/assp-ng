# SPDX-License-Identifier: GPL-3.0-or-later
"""Apply a plan to Postfix, verify it, and roll back on any failure (spec 8.10, R52/R53/R56).

Rollback follows how far apply got:

- before the Postfix restart: only ``master.cf`` is restored, nothing is restarted;
- after the Postfix restart but before ASSP-NG was restarted: restore, ``postfix check``,
  restart Postfix; ASSP-NG is left alone;
- after ASSP-NG was restarted: stop ASSP-NG first (the restored Postfix listens on 25/587/465
  again), restore, check, restart Postfix. ASSP-NG is never started again. If the backup
  already had no public listener (the host was integrated before) ASSP-NG is left running.

Every restart of Postfix is followed by a check that the unit is active, and a rollback probes
each restored public port.
"""
from __future__ import annotations

import datetime as dt
import filecmp
import os
import re
import shutil
import smtplib
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from asspng.postfix.inspect import (POSTFIX_UNIT, PostfixError, PostfixRefused, PostfixState, Run,
                                    is_public_listener, parse_master, read_master, run_checked,
                                    service_host, service_port)
from asspng.postfix.plan import Plan

SERVICE = "assp-ng-proxy"
ISPCONFIG_MESSAGE = (
    "this is an ISPConfig host (/usr/local/ispconfig exists): ISPConfig regenerates the "
    "Postfix configuration during updates and would overwrite the changes, so assp-ng does "
    "not edit master.cf here. Integration through ISPConfig's custom templates is not "
    "available yet; configure Postfix by hand (see the documentation)")
NOTE_STOPPED = (f"ASSP-NG ({SERVICE}) was stopped and is not started again, because the "
                "restored Postfix listens on 25/587/465; once the problem is fixed run "
                f"'systemctl start {SERVICE}' after moving Postfix off the public ports")
NOTE_LEFT_RUNNING = (f"ASSP-NG ({SERVICE}) was left running: the restored configuration has "
                     "no public Postfix listener, so there is no port conflict")
NOTE_UNTOUCHED = f"ASSP-NG ({SERVICE}) was not touched by this run"
NOTE_MASTER_ONLY = "Postfix was not restarted; only master.cf was restored"
Backend = tuple[str, int, bool]
_STOPPED = frozenset({"inactive", "failed", "not loaded"})
_VERIFY_RETRY_S = 10.0
_VERIFY_TIMEOUT_S = 5.0


@dataclass(frozen=True)
class Target:
    """An SMTP endpoint to probe; ``tls`` means implicit TLS (smtps)."""

    host: str
    port: int
    tls: bool


Probe = Callable[[Sequence[Target]], bool]


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _install(data: bytes, dest: Path, mode: int) -> None:
    """Durably and atomically replace ``dest``, keeping the owner of an existing file."""
    tmp = dest.with_name(dest.name + ".assp-ng-tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        try:
            old = dest.lstat()
            os.chown(tmp, old.st_uid, old.st_gid)
        except (FileNotFoundError, PermissionError):
            pass
        _fsync_dir(dest.parent)
        os.replace(tmp, dest)
        _fsync_dir(dest.parent)
    finally:
        tmp.unlink(missing_ok=True)


def _refuse_dir(path: Path, st: os.stat_result, owners: frozenset[int], *, leaf: bool
                ) -> None:
    """Raise unless ``st`` (an lstat or fstat of ``path``) is a safe directory."""
    if stat.S_ISLNK(st.st_mode):
        raise PostfixError(f"refusing {path}: it is a symlink")
    if not stat.S_ISDIR(st.st_mode):
        raise PostfixError(f"refusing {path}: it is not a directory")
    if st.st_uid not in owners:
        raise PostfixError(f"refusing {path}: it is owned by uid {st.st_uid}, not by root")
    sticky = bool(st.st_mode & stat.S_ISVTX) and not leaf
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and not sticky:
        raise PostfixError(f"refusing {path}: it is writable by group or others")


def _open_trusted_dir(path: Path, *, create: bool, euid: int | None) -> int:
    """``check_trusted_dir``, then an fd of the directory, opened without following a
    symlink; with ``create`` a missing directory is made (0700)."""
    path = Path(os.path.abspath(path))
    owners = frozenset({0, os.geteuid() if euid is None else euid})
    for parent in reversed(path.parents):  # "/" first
        try:
            st = os.lstat(parent)
        except OSError as exc:
            raise PostfixError(f"refusing {path}: cannot inspect {parent} "
                               f"({exc.strerror or type(exc).__name__})") from None
        _refuse_dir(parent, st, owners, leaf=False)
    if create:
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise PostfixError(f"cannot create {path}: {exc.strerror}") from None
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise PostfixError(f"{path} does not exist") from None
    _refuse_dir(path, st, owners, leaf=True)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:  # replaced by a symlink since the lstat (ELOOP)
        raise PostfixError(f"refusing {path}: {exc.strerror or type(exc).__name__}") from None
    try:
        _refuse_dir(path, os.fstat(fd), owners, leaf=True)
    except BaseException:
        os.close(fd)
        raise
    return fd


def check_trusted_dir(path: Path, *, euid: int | None = None) -> None:
    """Refuse a directory that anybody but root could control (ruling R58).

    Root restores the Postfix configuration from backups, so every path component from ``/``
    must be a real directory (a symlink is refused, never followed), owned by root (or by the
    effective user ``euid``, for tests) and not writable by group or others. A
    world-writable parent with the sticky bit (``/tmp``) is accepted: nobody else can
    replace the entries in it. Raises ``PostfixError``.
    """
    os.close(_open_trusted_dir(path, create=False, euid=euid))


def _chmod_dir(path: Path, mode: int) -> None:
    """chmod a directory without ever following a symlink."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def _backup(etc: Path, backup_root: Path, now: Callable[[], dt.datetime]) -> Path:
    fd = _open_trusted_dir(backup_root, create=True, euid=None)
    try:
        os.fchmod(fd, 0o700)
    finally:
        os.close(fd)
    stamp = now().astimezone(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    dest = backup_root / f"postfix-{stamp}"
    try:
        os.mkdir(dest, 0o700)  # exclusive: an existing backup is never reused or removed
    except FileExistsError:
        raise PostfixError(f"backup directory {dest} exists already; nothing was changed") \
            from None
    except OSError as exc:
        raise PostfixError(f"cannot create {dest}: {exc.strerror}") from None
    try:
        shutil.copytree(etc, dest, symlinks=True, dirs_exist_ok=True)
        _chmod_dir(dest, 0o700)
    except (OSError, shutil.Error) as exc:
        shutil.rmtree(dest, ignore_errors=True)  # only the directory created just above
        raise PostfixError(f"cannot back up {etc} to {dest}: "
                           f"{getattr(exc, 'strerror', None) or type(exc).__name__}") from None
    return dest


def _restore(backup: Path, etc: Path) -> None:
    """Copy back every backed-up file that differs; files that are equal are left alone."""
    for root, dirs, files in os.walk(backup):
        rel = Path(root).relative_to(backup)
        (etc / rel).mkdir(exist_ok=True)
        for name in [*dirs, *files]:
            src, dest = Path(root) / name, etc / rel / name
            if src.is_symlink():
                target = os.readlink(src)
                if dest.is_symlink() and os.readlink(dest) == target:
                    continue
                tmp = dest.with_name(dest.name + ".assp-ng-tmp")
                tmp.unlink(missing_ok=True)
                os.symlink(target, tmp)
                os.replace(tmp, dest)
            elif src.is_file():
                if (dest.is_file() and not dest.is_symlink()
                        and filecmp.cmp(src, dest, shallow=False)):
                    continue
                _install(src.read_bytes(), dest, stat.S_IMODE(src.stat().st_mode))


def _status(run: Run, unit: str) -> str:
    """``systemctl is-active`` state; a non-zero exit is normal for an inactive unit."""
    try:
        done = run(["systemctl", "is-active", unit], capture_output=True, text=True,
                   timeout=60, check=False)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return (done.stdout or "").strip() or "unknown"


def _require_postfix_active(run: Run) -> None:
    state = _status(run, POSTFIX_UNIT)
    if state != "active":
        raise PostfixError(f"Postfix ({POSTFIX_UNIT}) is not active after the restart "
                           f"(state: {state})")


def _stop_assp(run: Run) -> None:
    """Stop ASSP-NG; a failing stop is fine when the unit is not running anyway."""
    try:
        run_checked(run, ["systemctl", "stop", SERVICE])
    except PostfixError as exc:
        state = _status(run, SERVICE)
        if state not in _STOPPED:
            raise PostfixError(f"{exc}; {SERVICE} is still {state}, so nothing was changed") \
                from None


def _public_targets(master_text: str) -> list[Target]:
    return [Target(service_host(s), port, port == 465) for s in parse_master(master_text)
            if is_public_listener(s) and (port := service_port(s)) is not None]


def _default_probe(targets: Sequence[Target]) -> bool:
    return make_verifier(targets, [])()


def _rollback(backup: Path, run: Run, etc: Path, probe: Probe | None, *,
              stop: bool | None) -> str:
    """Restore ``backup`` and restart Postfix; ``stop`` None means "if it has public ports"."""
    if not (backup / "master.cf").is_file():
        raise PostfixError(f"{backup} is not a Postfix backup (no master.cf)")
    check_trusted_dir(backup)
    targets = _public_targets(read_master(backup / "master.cf"))
    stopping = bool(targets) if stop is None else stop and bool(targets)
    if stopping:
        _stop_assp(run)
    try:
        _restore(backup, etc)
    except OSError as exc:
        raise PostfixError(f"cannot restore {backup} into {etc}: "
                           f"{exc.strerror or type(exc).__name__}") from None
    run_checked(run, ["postfix", "check"])
    run_checked(run, ["systemctl", "restart", "postfix"])
    try:
        _require_postfix_active(run)
        if targets and not (probe or _default_probe)(targets):
            raise PostfixError("Postfix does not answer on "
                               + ", ".join(str(t.port) for t in targets))
    except PostfixError as exc:
        raise PostfixError(f"{exc}; the configuration was restored from {backup}") from None
    if stopping:
        return NOTE_STOPPED
    if targets:
        return NOTE_UNTOUCHED
    # No public Postfix listener: ASSP-NG must be the one serving 25/587/465. Its restart may
    # have killed the old proxy, so confirm it before saying it runs.
    state = _status(run, SERVICE)
    if state != "active":
        raise PostfixError(f"nothing serves the public ports: {SERVICE} is {state} and the "
                           f"restored Postfix has no public listener; the configuration was "
                           f"restored from {backup}")
    return NOTE_LEFT_RUNNING


def rollback(backup_dir: Path, run: Run = subprocess.run, *, etc: Path = Path("/etc/postfix"),
             probe: Probe | None = None) -> str:
    """Stop ASSP-NG (if the backup has public listeners), restore, check, restart Postfix.

    Returns a note telling what happened to ASSP-NG; it is never started again here.
    """
    return _rollback(backup_dir, run, etc, probe, stop=None)


# --- the postconf guard ------------------------------------------------------------------

_PARAM_LINE = re.compile(r"([^/\s]+)/([^/\s]+)/[^\s=]+ =(?: |$)")


def _key(line: str) -> tuple[str, str]:
    # postconf -P prints "name/type/param = value", and "name/type/param = " (trailing space)
    # for an empty value, so the line must not be stripped before matching.
    match = _PARAM_LINE.match(line)
    if match:
        return match.group(1), match.group(2)
    fields = line.split()  # postconf -M: name type private unpriv chroot wakeup maxproc cmd
    return (fields[0], fields[1]) if len(fields) > 1 else ("", "")


def _postconf_lines(run: Run, directory: Path) -> set[str]:
    lines: set[str] = set()
    for mode in ("-M", "-P"):
        out = run_checked(run, ["postconf", "-c", str(directory), mode]).stdout
        lines.update(line.rstrip("\r\n") for line in out.split("\n") if line.strip())
    return lines


def check_plan(plan: Plan, run: Run, etc: Path) -> None:
    """Refuse unless ``postconf`` reads the planned master.cf as intended.

    ``postfix check`` does not catch a continuation line that folded into the wrong service,
    so compare ``postconf -M`` and ``-P`` of the current and the planned configuration: they
    may differ only in the disabled and the added services.
    """
    allowed = {*plan.disabled, *plan.added}
    current = _postconf_lines(run, etc)
    with tempfile.TemporaryDirectory(prefix="assp-ng-plan-") as tmp:
        directory = Path(tmp)
        try:
            shutil.copy(etc / "main.cf", directory / "main.cf")
        except OSError as exc:
            raise PostfixError(f"cannot read {etc / 'main.cf'}: {exc.strerror}") from None
        (directory / "master.cf").write_bytes(
            plan.master_text_new.encode("utf-8", errors="surrogateescape"))
        planned = _postconf_lines(run, directory)
    unexpected = sorted(line for line in current ^ planned if _key(line) not in allowed)
    keys = {_key(line) for line in planned}
    if (unexpected or any(k not in keys for k in plan.added)
            or any(k in keys for k in plan.disabled)):
        raise PostfixRefused(
            "postconf reads the planned master.cf differently from the plan"
            + (": " + "; ".join(unexpected[:4]) if unexpected else "")
            + "; nothing was changed")


# --- apply -------------------------------------------------------------------------------

def _require_unit_loaded(run: Run) -> None:
    state = run_checked(run, ["systemctl", "show", "-p", "LoadState", "--value",
                              SERVICE]).stdout.strip()
    if state != "loaded":
        raise PostfixRefused(f"the {SERVICE} unit is not installed (LoadState={state}); "
                             "install it before running apply")


def apply_plan(plan: Plan, state: PostfixState, *, backup_root: Path,
               run: Run = subprocess.run, verify: Callable[[], bool],
               etc: Path = Path("/etc/postfix"), now: Callable[[], dt.datetime] = _utcnow,
               probe: Probe | None = None) -> Path:
    """Apply ``plan``; return the backup directory. Any failure rolls back and raises."""
    if state.ispconfig:
        raise RuntimeError(ISPCONFIG_MESSAGE)
    if plan.master_text_new == state.master_text:
        raise PostfixError("nothing to apply: the plan is empty")
    _require_unit_loaded(run)
    check_plan(plan, run, etc)
    backup = _backup(etc, backup_root, now)
    master = etc / "master.cf"
    stage = 0  # 0 nothing restarted, 1 Postfix restart attempted, 2 ASSP-NG restart attempted
    try:
        _install(plan.master_text_new.encode("utf-8", errors="surrogateescape"), master,
                 stat.S_IMODE(master.stat().st_mode))
        run_checked(run, ["postfix", "check"])
        stage = 1
        run_checked(run, ["systemctl", "restart", "postfix"])
        _require_postfix_active(run)
        stage = 2
        run_checked(run, ["systemctl", "restart", SERVICE])
        try:
            ok = verify()
        except Exception as exc:
            raise PostfixError(f"verification failed ({type(exc).__name__})") from None
        if not ok:
            raise PostfixError("verification failed")
    except (Exception, KeyboardInterrupt) as exc:
        reason = str(exc) if isinstance(exc, Exception) else "interrupted"
        try:
            if stage == 0:
                _restore(backup, etc)
                note = NOTE_MASTER_ONLY
            else:
                note = _rollback(backup, run, etc, probe, stop=False if stage == 1 else None)
        except Exception as inner:
            raise PostfixError(f"{reason}; the automatic rollback failed too: {inner}; "
                               f"restore {backup} into {etc} by hand") from None
        if not isinstance(exc, Exception):
            raise
        raise PostfixError(f"{reason}; configuration rolled back from {backup}. {note}") \
            from None
    return backup


# --- default verification ----------------------------------------------------------------

def open_smtp(host: str, port: int, tls: bool, timeout: float) -> smtplib.SMTP:
    """Connect (the constructor reads the 220 banner and raises on anything else)."""
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # a liveness probe, not authentication
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return smtplib.SMTP_SSL(host, port, local_hostname="assp-ng-verify", timeout=timeout,
                                context=ctx)
    return smtplib.SMTP(host, port, local_hostname="assp-ng-verify", timeout=timeout)


def _probe(connect: Callable[[str, int, bool, float], smtplib.SMTP], host: str, port: int,
           tls: bool, xclient: bool, timeout: float) -> str | None:
    where = f"{host}:{port}"
    try:
        smtp = connect(host, port, tls, timeout)
    except (OSError, smtplib.SMTPException) as exc:
        return f"{where}: {type(exc).__name__}"
    try:
        code, _ = smtp.ehlo("assp-ng-verify")
        if code != 250:
            return f"{where}: EHLO answered {code}"
        if xclient and not smtp.has_extn("xclient"):
            return f"{where}: XCLIENT not advertised"
        return None
    except (OSError, smtplib.SMTPException) as exc:
        return f"{where}: {type(exc).__name__}"
    finally:
        try:
            smtp.quit()
        except (OSError, smtplib.SMTPException):
            smtp.close()


def make_verifier(targets: Sequence[Target], backends: Sequence[Backend], *,
                  connect: Callable[[str, int, bool, float], smtplib.SMTP] = open_smtp,
                  sleep: Callable[[float], None] = time.sleep,
                  monotonic: Callable[[], float] = time.monotonic,
                  report: Callable[[str], None] | None = None,
                  retry_s: float = _VERIFY_RETRY_S, timeout: float = _VERIFY_TIMEOUT_S
                  ) -> Callable[[], bool]:
    """EHLO through every listener and directly to every backend (XCLIENT offered).

    Retries for about ``retry_s`` seconds while ASSP-NG starts.
    """
    def say(text: str) -> None:
        (report or (lambda t: print(t, file=sys.stderr)))(text)

    def verify() -> bool:
        deadline = monotonic() + retry_s
        while True:
            error: str | None = None
            for t in targets:
                error = error or _probe(connect, t.host, t.port, t.tls, False, timeout)
            for host, port, _auth in backends:
                error = error or _probe(connect, host.strip("[]"), port, False, True, timeout)
            if error is None:
                return True
            if monotonic() >= deadline:
                say(f"verify: {error}")
                return False
            sleep(1.0)

    return verify
