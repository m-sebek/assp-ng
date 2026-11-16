# Test server acceptance checklist

Manual acceptance of ASSP-NG on the test server (design spec 10.2 layer 6 and 10.4). Work through
the sections in order and write down the date, the result and any log excerpt for each item.

## Prerequisites

- [ ] A clean Debian 13 installation, installed by following [installation.md](installation.md)
      step by step, with no undocumented manual fix. Note every deviation.
- [ ] The three release-blocking items in installation.md are confirmed and written down: the
      `postfix@-` unit, real `postconf -M`/`postconf -P` captures and, on an ISPConfig host, the
      template mechanism.
- [ ] A real Postfix with XCLIENT enabled for `127.0.0.1` on the internal `smtpd` services on
      `127.0.0.1:10125` and `127.0.0.1:10587`.
- [ ] A Let's Encrypt certificate installed through the certbot deploy hook, and a renewal test
      (`certbot renew --dry-run`) that reloads ASSP-NG.
- [ ] `assp-ng config check` and `assp-ng status` are clean.

## Test mode first

New domains start in test mode (`testmode = true`), where rejections are only logged.

- [ ] Domain added with `assp-ng domain add` and `testmode = true` set for it.
- [ ] `maillog.log` shows `result=` values for real mail, and nothing is rejected.
- [ ] After the review period, test mode is switched off for the domain.

## swaks scenarios

Run against the public address of the test server.

- [ ] Plain delivery to a local mailbox on port 25 is accepted, and the backend receives the real
      client address through XCLIENT.
- [ ] Relay to a foreign domain without AUTH is refused.
- [ ] STARTTLS on port 25 works with the Let's Encrypt certificate, and SNI selects the right one.
- [ ] AUTH on port 587 without TLS is refused, and AUTH with STARTTLS succeeds.
- [ ] Wrong AUTH credentials are refused, and the password does not appear in any log.
- [ ] A message over the size limit gets `552`.
- [ ] The rate limits reject or defer at the configured thresholds.
- [ ] Repeated bad behaviour puts the client into the penalty box (`assp-ng pb list`), and
      `assp-ng pb remove` releases it.
- [ ] Stopping Redis switches ASSP-NG to the degraded mode, mail keeps flowing, and it recovers
      when Redis is back. Stopping Postfix gives `421` on new sessions.
- [ ] `assp-ng debug on` works while Redis is down, and the debug log has no AUTH payload.

## Real clients on 587 and 465

- [ ] Thunderbird: account setup, sending and receiving on 587 with STARTTLS.
- [ ] Outlook: sending on 587 with STARTTLS, and on 465 with implicit TLS if that listener is
      enabled.
- [ ] A mobile mail client (Android and iOS): sending on 587 or 465.

## Operations

- [ ] `systemctl reload assp-ng-proxy` applies a valid change and keeps the old configuration
      after an invalid one.
- [ ] `systemctl kill -s KILL assp-ng-proxy` is followed by an automatic restart, and an alert
      mail arrives for a failed start.
- [ ] A logrotate run (`logrotate -f /etc/logrotate.d/assp-ng`) rotates the logs and the new
      files are written by the running service.
- [ ] `assp-ng postfix rollback` restores the previous Postfix setup, and `apply` works again.

## Definition of done (spec 10.4)

- [ ] All automated tests pass in CI.
- [ ] On the test server, mail for 1 or 2 domains flows in production mode for **14 days** with
      no lost mail and no restart caused by a crash.
- [ ] Memory and throughput are measured and documented in `docs/`.
- [ ] Installation following the documentation works on a clean Debian 13.
