# ASSP-NG

ASSP-NG is a GPL-licensed SMTP anti-spam proxy written in Python, the successor
of ASSP v1. It sits in front of a mail server, runs a configurable set of checks
on each incoming message and accepts, rejects or defers it.

The design is described in
[docs/superpowers/specs/2026-11-12-core-proxy-design.md](docs/superpowers/specs/2026-11-12-core-proxy-design.md).
Development setup is in [docs/development.md](docs/development.md).

Licensed under the GPL-3.0-or-later, see [LICENSE](LICENSE).
