# SPDX-License-Identifier: GPL-3.0-or-later
"""``python3 -m asspng.proxy --config /etc/assp-ng/assp-ng.toml``: the proxy service, as run by
the systemd unit ``assp-ng-proxy.service``."""

from asspng.service.app import main

if __name__ == "__main__":
    raise SystemExit(main())
