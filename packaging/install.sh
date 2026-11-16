#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# ASSP-NG installer for Debian 13 (design spec 8.9). Run as root from a checkout of the
# repository: sudo ./packaging/install.sh
#
# Idempotent: it can be run again to update the code, units and wrapper. It never overwrites an
# existing configuration file, never touches Postfix and never creates database users.
set -euo pipefail

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "install.sh: must run as root" >&2
    exit 1
fi

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPT=/opt/assp-ng
ETC=/etc/assp-ng
WRAPPER=/usr/local/bin/assp-ng
SYSTEMD=/etc/systemd/system
HOOK_DIR=/etc/letsencrypt/renewal-hooks/deploy

if [ ! -d "$SRC/asspng" ] || [ ! -d "$SRC/packaging" ]; then
    echo "install.sh: $SRC is not an ASSP-NG checkout" >&2
    exit 1
fi

echo "==> Installing Debian packages"
apt-get install -y python3 python3-dnspython python3-redis python3-pymysql \
    python3-sqlalchemy python3-alembic python3-systemd python3-cryptography python3-tomlkit

echo "==> Creating the assp-ng system user and group"
if ! getent group assp-ng > /dev/null; then
    addgroup --system assp-ng
fi
if ! id -u assp-ng > /dev/null 2>&1; then
    adduser --system --ingroup assp-ng --home /var/lib/assp-ng --no-create-home \
        --shell /usr/sbin/nologin assp-ng
fi

echo "==> Creating $ETC"
install -d -m 0750 -o root -g assp-ng "$ETC" "$ETC/domain.d" "$ETC/user.d" "$ETC/tls"

echo "==> Copying the code to $OPT"
install -d -m 0755 -o root -g root "$OPT"
STAGE="$OPT/asspng.new"
OLD="$OPT/asspng.old"
# A run interrupted between the two renames below leaves only the .old tree: put it back.
if [ ! -e "$OPT/asspng" ] && [ -d "$OLD" ]; then
    mv "$OLD" "$OPT/asspng"
fi
# Stage the new tree next to the live one and swap it in with renames, so a failed extraction
# leaves the running code untouched.
trap 'rm -rf "$STAGE"' EXIT
rm -rf "$STAGE" "$OLD"
tar -C "$SRC" --exclude=__pycache__ -cf - asspng \
    | tar -C "$OPT" --no-same-owner --transform 's,^asspng,asspng.new,' -xf -
if [ ! -f "$STAGE/__init__.py" ]; then
    echo "install.sh: extracting the code to $STAGE failed" >&2
    exit 1
fi
chown -R root:root "$STAGE"
chmod -R u=rwX,go=rX "$STAGE"
if [ -e "$OPT/asspng" ]; then
    mv "$OPT/asspng" "$OLD"
fi
mv "$STAGE" "$OPT/asspng"
rm -rf "$OLD"

echo "==> Installing the assp-ng command, systemd units, logrotate and certbot hook"
install -m 0755 -o root -g root "$SRC/packaging/bin/assp-ng" "$WRAPPER"
install -m 0644 -o root -g root "$SRC/packaging/systemd/assp-ng-proxy.service" \
    "$SYSTEMD/assp-ng-proxy.service"
install -m 0644 -o root -g root "$SRC/packaging/systemd/assp-ng-notify@.service" \
    "$SYSTEMD/assp-ng-notify@.service"
install -m 0644 -o root -g root "$SRC/packaging/logrotate/assp-ng" /etc/logrotate.d/assp-ng
install -d -m 0755 -o root -g root "$HOOK_DIR"
install -m 0755 -o root -g root "$SRC/packaging/certbot/assp-ng-deploy-hook" \
    "$HOOK_DIR/assp-ng"
systemctl daemon-reload

echo "==> Configuration files"
if [ ! -e "$ETC/assp-ng.toml" ]; then
    install -m 0640 -o root -g assp-ng "$SRC/packaging/config/assp-ng.toml.example" \
        "$ETC/assp-ng.toml"
    echo "    created $ETC/assp-ng.toml from the example: edit it before starting the service"
else
    echo "    kept the existing $ETC/assp-ng.toml"
fi
if [ ! -e "$ETC/default.toml" ]; then
    "$WRAPPER" config init
    chown root:assp-ng "$ETC/default.toml"
    chmod 0640 "$ETC/default.toml"
    echo "    created $ETC/default.toml"
else
    echo "    kept the existing $ETC/default.toml"
fi

cat <<'NEXT'

ASSP-NG is installed but not started. Next steps (docs/installation.md has the details):

1. Create the database and its user in MariaDB. Choose a password, put it in
   /etc/assp-ng/assp-ng.toml (database.url), and run as the MariaDB root user:

     CREATE DATABASE asspng CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
     CREATE USER 'asspng'@'localhost' IDENTIFIED BY 'PASSWORD';
     GRANT ALL PRIVILEGES ON asspng.* TO 'asspng'@'localhost';
     FLUSH PRIVILEGES;

2. Edit /etc/assp-ng/assp-ng.toml, then validate it and create the tables:

     assp-ng config check
     assp-ng db upgrade

3. Review what the Postfix assistant would change. Nothing is changed by these two commands:

     assp-ng postfix check
     assp-ng postfix plan

4. Install the TLS certificate (the certbot deploy hook is already in place), then run
   'assp-ng postfix apply'. It restarts Postfix and starts ASSP-NG. To start it at boot:

     systemctl enable assp-ng-proxy
NEXT
