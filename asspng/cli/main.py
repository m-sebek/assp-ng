# SPDX-License-Identifier: GPL-3.0-or-later
"""Entry point of the ``assp-ng`` command."""
from __future__ import annotations

import argparse
import sys

from asspng.cli import config_cmd, ops_cmd, postfix_cmd
from asspng.cli.config_cmd import DEFAULT_DIR, CliError, Deps


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="assp-ng", description="ASSP-NG administration")
    parser.add_argument("--config-dir", default=str(DEFAULT_DIR), metavar="PATH",
                        help=f"configuration directory (default: {DEFAULT_DIR})")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    config_cmd.add_parser(sub)
    ops_cmd.add_parser(sub)
    postfix_cmd.add_parser(sub)
    return parser


def main(argv: list[str] | None = None, *, deps: Deps | None = None) -> int:
    """Run the CLI: 0 success, 1 operational failure, 2 usage or validation error."""
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:  # argparse: 0 for --help, 2 for usage errors
        return exc.code if isinstance(exc.code, int) else 2
    try:
        return int(args.func(args, deps if deps is not None else Deps()))
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.code
    except OSError as exc:
        where = f" ({exc.filename})" if exc.filename else ""
        print(f"error: {exc.strerror or type(exc).__name__}{where}", file=sys.stderr)
        return 1
    except Exception as exc:  # never a traceback: it could quote a URL
        print(f"error: unexpected {type(exc).__name__}", file=sys.stderr)
        return 1
