# ASSP-NG — Decisions for later subprojects

| | |
|---|---|
| Status | Collected decisions, input for the design of subprojects 2–6 |
| Date | 2026-11-14 (updated 2026-11-16: backscatter protection 5.2, Bayes implementation and improvements 6.1) |
| Related | [Subproject 1: Core SMTP Proxy — Design](2026-11-12-core-proxy-design.md) |

This document records decisions made while designing subproject 1 that belong to later
subprojects, so they are not lost. Each subproject's own design document will refine them.

---

## 1. Lists (subproject 2)

### 1.1 Storage and sharing

All lists live in MySQL and are shared by every instance that uses the same database.

```
list_entry(id, list, pattern, scope, expires_at NULL, source, created_by,
           hits, last_hit, created_at, updated_at)
  list     allow | deny | noprocessing | red | bulkblock
  pattern  someone@example.com | @example.com | @.example.com (domain and its subdomains)
  scope    server | domain:<local domain> | user:<local mailbox>
  source   auto | manual | import | web | learn
```

- MySQL stays out of the mail hot path. Every instance keeps an in-memory index of all entries
  (about 15 MB per 100 000 entries). It is updated by Redis events and, as a safety net, by an
  incremental refresh by `updated_at` every minute.
- Auto-whitelist updates (expiry extensions on every outbound message) are batched and written in
  the background. They never delay delivery. During a MySQL outage they wait in a bounded
  in-memory queue.
- Patterns are compared in lowercase IDNA form.

### 1.2 CLI

The same grammar is used for every list:

```
assp-ng whitelist add someone@example.com                         # server scope
assp-ng whitelist add someone@example.com domain:example.sk
assp-ng whitelist add @example.com user:jano@example.sk --expires 90d
assp-ng whitelist del | list | show ...
assp-ng blacklist ... | assp-ng noprocessing ... | assp-ng redlist ...
```

Manual entries are permanent unless `--expires` is given. Every change is audit-logged. An import
from ASSP v1 lists follows later.

### 1.3 Scope precedence

Mailbox > domain > server, the same order as layered configuration. A manual mailbox-level allow
entry can override a server-level deny entry. The auto-whitelist never creates such an override.

### 1.4 IP lists

Three IP lists follow the same principles: MySQL storage shared between instances, an in-memory
index with Redis events, the same CLI grammar, scopes, optional expiry, audit log.

| List | Effect |
|---|---|
| `whitelistip` | Same effect as an address whitelist hit (section 2): skips greylisting, DNSBL and Bayes, gets a score bonus, and the network **never receives penalty-box points**. Security checks (antivirus, attachments, URL) always run. |
| `blacklistip` | `554 5.7.1`. Server scope rejects at connect, domain/mailbox scope at `RCPT TO` for that recipient. A permanent rejection, because it is a deliberate admin decision (the automatic penalty box uses temporary `421`). |
| `nodelayip` | Exempt from greylisting only (v1 `noDelay`). Meant for the sending pools of large providers (Microsoft, Google, Seznam…), which retry from different IPs and would otherwise be delayed for hours. Greylisting itself works normally for everyone else. |

```
assp-ng whitelistip add 203.0.113.0/24 --note "partner company"
assp-ng whitelistip add 198.51.100.7 domain:firma.sk
assp-ng blacklistip add 2001:db8:bad::/48 --expires 30d
assp-ng nodelayip add 40.92.0.0/15 --note "Microsoft outbound"
assp-ng whitelistip|blacklistip|nodelayip del | list | show ...
```

- Single addresses and CIDR ranges, IPv4 and IPv6. A range with host bits set (for example
  `203.0.113.5/24`) is rejected, so a typo cannot silently become a whole-network entry.
- **Overlapping ranges: the most specific prefix wins**, as in routing. A `/24` blacklist with a
  manual `/32` whitelist exception therefore works. As with addresses, adding a `blacklistip`
  entry removes the `whitelistip` entries inside its range, so an exception must be added
  afterwards.
- **None of these lists grants relaying.** Relay permission stays exclusively in
  `trusted-networks.txt` (root-owned file), and `exempt-networks.txt` (exemption from connection
  limits) stays separate. A database list, which the web interface will manage, must never be able
  to turn the server into an open relay.
- **Optional later:** the worker keeps `nodelayip` entries for configured provider domains up to
  date from their SPF records (`source = auto`), because the providers' ranges change. ASSP v1's
  `files/nodelay.txt` (72 entries from the 2000s) is outdated and is not imported by default.

---

## 2. Auto-whitelist (subproject 2)

- **Enabled by default.** It is the "web of trust" core of ASSP v1.
- **When an address is added:** an authenticated user (or a trusted network) sends a message to an
  **external** recipient and the MTA accepts it with `250`. The envelope recipient (`RCPT TO`) is
  added.
  - Local addresses are never added (v1 rule; spammers forge them).
  - Nothing is added from bounces (null sender), from messages with more than 50 recipients, from
    messages ASSP-NG considers suspicious, or later from accounts locked for suspected credential
    theft (subproject 4).
  - Nothing is added while a deny entry covering that address is active.
- **Expiry:** 365 days after the last outbound message to the address. Every further outbound
  message extends it. Inbound mail does **not** extend it, unlike v1: a hijacked correspondent
  account must not keep itself whitelisted.
- **Scope:** recipient-level setting `whitelist.auto_scope = "user" | "domain" | "server"`, default
  `"user"`. On a hosting server a correspondent of one customer must not gain trust with all
  customers. A company can set `"domain"` in its `domain.d/` file.
- **Effect: a bonus, not a bypass.** A whitelisted sender skips greylisting, DNSBL and Bayes and
  gets a score bonus. Antivirus, attachment, URL and (later) AI phishing checks always run.
  Conversation hijacking sends from genuinely whitelisted addresses.
- **Anti-spoofing:** the whitelist applies only if the matched identity is not failing
  authentication (section 4). An identity of a domain that publishes neither SPF nor DKIM gets
  the bonus only, not the skips.
- **Several recipients:** the whitelist applies only if it covers **all** recipients of the
  transaction. Recipients are not split for this, to avoid needless deferrals.

---

## 3. Blacklist (subproject 2)

- Same storage, CLI and scopes as the whitelist. Expiry is optional; without it the entry is
  permanent.
- **Adding a deny entry removes matching allow entries** at the same and narrower scopes. A
  server entry removes every whitelist entry for the address. A domain entry removes those of the
  domain and its mailboxes. Removals are audit-logged.
- **While a deny entry is active, the auto-whitelist does not add the address**, even if a local
  user writes to it (for example to unsubscribe).
- **After expiry or removal the address is "new":** removed whitelist entries are not restored.
  The address returns to the whitelist only through normal auto-whitelisting or manually.
- **Effect:** the envelope sender is checked at `RCPT TO`, where `554 5.7.1` rejects only the
  affected recipient. The others in the same transaction are unaffected. Header identities are
  checked in the HEADER phase (section 4). Mode (block or score) is a normal check setting.

---

## 4. Sender identities for list matching (subproject 2)

Newsletters and mailing lists use envelope senders that differ from the visible `From:`. Examples
are VERP bounce addresses such as `bounce-12345-jano=firma.sk@mail.esp.com`, list bounce addresses
such as `list-bounces@lists.org`, and SRS or BATV rewritten addresses. ASSP-NG therefore matches
lists against several **identities**, each authenticated separately:

| Identity | Taken from | Authenticated by |
|---|---|---|
| envelope sender | `MAIL FROM`, normalised (BATV `prvs=` tag removed, SRS decoded) | SPF pass for that domain, or DKIM pass with that domain |
| author | header `From:` | DMARC pass (SPF or DKIM aligned with the `From:` domain) |
| mailing list | `List-Post: <mailto:…>` address (and `List-Id`) | SPF or DKIM pass for the list's domain |

- `Reply-To:`, `Sender:` and `Errors-To:` are **not** identities. Anyone can write them, and ASSP v1's
  "greedy" whitelist matching on them was easy to abuse.
- **Whitelist hit:**
  - an identity that is on the list and authenticated (pass) gets the full whitelist effect;
  - an identity whose domain publishes no SPF or DKIM ("none") gets the bonus only;
  - an identity whose authentication fails is ignored.
- **Auto-whitelist entries** are envelope recipients of outbound mail (section 2). A correspondent's
  reply normally matches through the envelope sender or the `From:` header. A reply from a
  mailing list matches through `List-Post` when the user previously wrote to the list address.
- **Newsletters** are usually never written to, so they are not auto-whitelisted. A manual entry
  (`assp-ng whitelist add news@company.com` or `@company.com`) matches through the `From:` header
  and needs DMARC pass for the full effect.
- **Timing:** the envelope sender is known at `MAIL FROM`, the header identities only after
  `DATA`. A whitelist match through `From:` or `List-Post` therefore cannot skip checks that run
  before `DATA` (greylisting). It can skip DNSBL scoring and Bayes, and it gives the bonus.
- **Blacklist:** the envelope sender is matched at `RCPT TO` with no authentication requirement
  (blocking a forged address does no harm). The `From:` header is matched in the HEADER phase. It
  rejects the message only if the entry covers all recipients of the transaction; otherwise it
  adds score.
- **Consequence:** SPF, DKIM and DMARC verification moves into subproject 2. Subproject 6 keeps
  ARC.

---

## 5. Reply tracking and backscatter protection (subproject 2)

### 5.1 Reply tracking

- The Message-IDs of accepted outbound messages are stored in Redis for 90 days, together with
  the local envelope sender and the recipients (about 100 bytes per message). "Outbound" means
  messages relayed to at least one non-local recipient, from an authenticated user or a trusted
  network. This is the same set that gets the token in 5.2.
- An inbound message whose `In-Reply-To`/`References` contains a stored Message-ID, and whose
  sender matches a stored recipient, gets a **bonus** (the same effect class as the whitelist). It
  never bypasses security checks.
- The `Message-ID` of outgoing mail is never modified (unlike ASSP v1's MSGID signing):
  - the copy in the user's Sent folder keeps the same ID, so threads stay intact;
  - inbound `References` never need rewriting. Rewriting them would break the original sender's
    DKIM signature, for example after a Sieve redirect to another provider.

  The only addition to outgoing mail is the token header in 5.2. ASSP-NG adds it before Postfix,
  so OpenDKIM signs it like any other header.

### 5.2 Backscatter protection

**Problem.** Spammers forge a local address as the envelope sender, so non-delivery reports
(bounces) and auto-replies for mail we never sent reach that user.

**Approach.** A stateless HMAC token in a header of every outbound message. A bounce for real
mail carries the original headers, and with them the token. Auto-replies usually carry only
`In-Reply-To`, so they are checked against the Message-ID store from 5.1.

Alternatives considered and rejected:

- **Token inside the `Message-ID` (ASSP v1 MSGID signing).** It breaks the Sent-folder copy and
  needs inbound rewriting (see 5.1). v1 also let a valid tag skip all checks, and anyone who
  received our mail could reuse it.
- **BATV (`prvs=` in the envelope sender).** It changes the sender address, which breaks mailing
  list subscriptions and sender callouts.
- **Message-ID store only.** Without Redis nothing could be verified. It also only covers the
  stored history.

**Token**

- ASSP-NG adds `X-ASSP-NG-Thread-Token` to every outbound message (as defined in 5.1). The message
  goes to the MTA once for all recipients, so there is one token per message. The core already
  strips any incoming `X-ASSP-NG-*` field, so a client cannot supply its own token.
- Format: `v1.<key id>.<day>.<mac>`.
  - `<day>` is the number of days since 1970-01-01 UTC.
  - `<mac>` is the base32 encoding, without padding, of the first 16 bytes of
    HMAC-SHA256(key, lower-cased envelope sender + "|" + day).
  - The token is bound to the envelope sender because the bounce returns to exactly that
    address, so the verifier knows it without any lookup.
- Valid for 14 days, since some servers retry delivery for 5 to 7 days. A token dated more than
  one day in the future is invalid. The MAC is compared in constant time.
- Keys:
  - stored in a key file in `/etc/assp-ng/` (mode 0640, root:assp-ng), created by
    `assp-ng config init`;
  - the file holds several keys with ids: the newest one signs, all of them verify;
  - rotation adds a new key and keeps the old one for at least 14 days;
  - instances that share mail need the same file;
  - reloaded on SIGHUP;
  - the same keys also sign the `X-ASSP-NG-Bulk` identity (8.2).
- **A token can be reused.** Anyone who received mail from a user sees that user's token. Reusing
  it only lets a forged bounce to that one user pass this check for 14 days. All other checks
  still run, and nothing is bypassed.

**Verification (BODY phase)**

- **Bounces**:
  - What counts as a bounce: a message with a null envelope sender (`MAIL FROM:<>`).
  - Where the token is searched:
    1. the `message/rfc822-headers` or `message/rfc822` part of a DSN;
    2. otherwise the first 64 kB of the text parts, for an inline quoted header line, because
       some servers quote headers as plain text.
  - Result:
    - A valid token for the bounce's recipient passes.
    - If original headers are present but there is no valid token for that recipient, the
      configured mode applies.
    - If the bounce has no original headers, it cannot be judged and only gets the score, even
      in `reject` mode.
- **Auto-replies**:
  - What counts as an auto-reply: `Auto-Submitted: auto-replied` (RFC 3834) and the common legacy
    markers. Subproject 2 picks the exact list.
  - Result:
    - It passes when `In-Reply-To`/`References` contains a stored Message-ID whose stored sender
      is the recipient of the auto-reply.
    - If the auto-reply has references but none of them match, the configured mode applies.
    - If it has no references, it only gets the score.
    - If Redis is unavailable, the result is neutral.
- A pass is not a bonus. It only means this check does not count.

**Settings** (recipient level: default, domain, mailbox)

- `backscatter.mode = off | score | reject` (default `score`):
  - `score` adds `backscatter.score`;
  - `reject` answers `550 5.7.1` at the end of DATA. Rejecting during the SMTP session creates no
    new backscatter.
- `backscatter.score`: its default is set with the other scores in subproject 2.
- Recipients with different modes are split by the existing policy grouping (`452 4.5.3`), so a
  rejection never affects another user's copy.
- **Grace period:** until 14 days after tokens were first enabled, `reject` acts as `score`. This
  covers bounces for mail sent before tokens existed. The date tokens were first enabled is
  recorded in `/var/lib/assp-ng`.
- **Known limit:** mail that leaves the server without passing ASSP-NG gets no token. Examples are
  web applications that send through `sendmail` straight to Postfix, and Sieve forwards. Their
  bounces count as missing a token. This is why the default is `score`, and why a domain that
  sends that way should not use `reject`. The documentation says so.
- The maillog records the outcome as `backscatter=valid|missing|no-headers`.

---

## 6. Bayes and message collections (subproject 3)

- **Hybrid model:**
  1. **Collections** of samples (equivalent of v1 `spam/`, `notspam/`, `errors/`) are stored in
     MySQL: the first 32 kB of each message, compressed (about 5–8 kB per sample). They are shared
     between instances and backed up with the database. CLI: `assp-ng corpus list | show | move |
     delete`; later the web interface.
  2. **Incremental learning:** a new sample updates token counts immediately, and the change
     reaches all instances within a minute.
  3. **Nightly rebuild** (worker) from the whole collection, as in v1. It removes drift, applies
     corrections, and allows algorithm changes without losing data.
  4. **Ageing:** a cap per class (for example 15 000 samples) drops the oldest samples first,
     instead of v1's random overwriting.
  5. **Corrections** (admin, later users via the web) take precedence like v1 `errors/`: they are
     never aged out and take effect immediately.
- **Automatic sample sources:**
  - ham: outbound mail of local users (v1 behaviour; teaches the users' language), and inbound mail
    from whitelisted senders that passed every check;
  - spam: messages rejected by **other** high-confidence checks (high score, URIBL, antivirus) and
    mail to spam-trap addresses (v1 "spam buckets");
  - **never** Bayes's own decisions, to avoid a feedback loop;
  - rejections before `DATA` have no content and produce no sample.
- **One server-wide database**, shared between instances. Per-domain or per-mailbox Bayes may come
  later if needed. The v1 algorithm is kept (word pairs, 40 most significant tokens, threshold
  0.6). Any change is measured first.
- **Own implementation** in pure Python using only the standard library (`email`, `re`, `zlib`,
  `hashlib`). No external library is used:
  - `spambayes` is no longer in Debian (it was Python 2 only);
  - `python3-simplebayes` is unmaintained upstream, has no word pairs and stores a pickle file;
  - `python3-sklearn` costs about 140 MB with numpy and scipy, plus RAM in every process that
    loads it. Its model is an in-memory array that cannot be shared as per-token increments, and
    it would change the algorithm. The tokenizer, the hard part, would have to be written anyway.

  A single tokenizer is shared by learning and scoring. The worker learns, and the proxy only
  scores from token counts held in memory.
- **Privacy:** samples hold personal data. Maximum age defaults to 180 days, access is admin only,
  `bayes.collect = false` disables collection per domain or mailbox, and redlisted addresses are
  never collected.
- **Open:** a quarantine of **whole** blocked messages with release (v1 block reports and resend)
  is a separate feature, to be decided in subproject 3 or 5.

### 6.1 Improvements (decided 2026-11-16)

1. **Measurement first.**
   - The worker runs a nightly cross-validation on the sample collection in MySQL. It reports:
     - the false-positive rate (ham classified as spam);
     - the false-negative rate (spam that passes).
   - The report is available through `assp-ng bayes report`. An alert is sent when the
     false-positive rate rises.
   - **Shadow mode:** an alternative variant of the algorithm can run next to the active one. It
     only records its verdict in the maillog (`bayes_shadow=`) and has no effect.
   - This is how every change to the tokenizer or the algorithm is judged before it is enabled.
2. **Learning from mail clients (IMAPSieve).** This works like the existing `sa-learn` setup:
   - Moving a message into the Junk folder teaches it as spam. Moving it out of Junk teaches it
     as ham.
   - Dovecot's `imapsieve` with `vnd.dovecot.pipe` calls `assp-ng learn spam|ham [--user
     <mailbox>]`, which reads the message from stdin (or a file argument). The documentation
     ships a ready Dovecot example.
   - `assp-ng learn` hands the message to the running service over a dedicated learn socket
     (`/run/assp-ng/learn.sock`). That socket only accepts learn requests and has a size limit.
     The mail user (for example `vmail`) gets access through a separate group, never the
     database credentials.
   - Learning is **server-wide**, into the one shared database (see above). `--user` is used for
     the rate limit, auditing and deduplication, not for a per-user Bayes.
   - Samples are deduplicated by a hash of their content:
     - the same spam reported by ten users is one sample;
     - when the same user moves a message back, the class of the existing sample changes;
     - when different users teach the same content as spam and as ham, the sample is marked
       **disputed**. It is left out of learning until the admin decides, and `assp-ng corpus`
       lists disputed samples.
   - Samples from folder moves are ordinary samples: they age out. Corrections with precedence
     stay as in item 5 of the hybrid model. There is a per-user rate limit.
   - **Marketing mail is handled by `bulkblock`, not by Bayes.** Users often move newsletters
     into Junk because they no longer want them, while other users still do. Teaching such mail
     as spam server-wide would make Bayes block the newsletter for everyone.

     When a message carries a validly signed `X-ASSP-NG-Bulk` header with an identity (8.2):
     - `learn spam` adds a `bulkblock` entry for that identity, scoped to the user
       (`user:<mailbox>`, source `learn`). See 8.3.
     - `learn ham` removes an entry that `learn` created for that identity and user.
     - In both cases the message never becomes a Bayes sample.

     When there is no such header, no identity, or the signature is invalid, the message is an
     ordinary spam or ham sample. A newsletter whose sender is not authenticated is spam that
     only pretends to be marketing.
3. **Better tokenizer:**
   - full MIME and charset decoding;
   - HTML is turned into text, plus tokens for its structure (for example HTML-only mail, hidden
     text);
   - URL domains become separate tokens;
   - header tokens carry a prefix (`subject:…`, `from-domain:…`);
   - Unicode is normalised: NFKC, zero-width characters removed, look-alike characters mapped to
     Latin;
   - Slovak words also produce a token without diacritics, because spammers mix both forms.
4. **Candidate in shadow mode only:** Robinson's smoothing of rare tokens with Fisher
   (chi-square) combining, as used by SpamBayes and SpamAssassin. It adds an "unsure" band that
   gets a partial score, instead of the near-0-or-1 result of the v1 combining. It is enabled
   only if measurement (point 1) shows an improvement.

---

## 7. TNEF (`winmail.dat`) decoding (subproject 3)

See subproject 1 design, section 11. The decoder is pure Python, strictly limited and
fuzz-tested. It never touches signed or encrypted messages. The attachment and antivirus checks
share it. Whether DKIM-signed inbound messages are converted is decided in the subproject 3
design (forwarding to external providers may then fail DMARC).

---

## 8. Marketing mail ("graymail") (subprojects 3 and 5)

Marketing campaigns and newsletters are often not spam in the technical sense, yet they flood
mailboxes, for example after a one-time e-shop purchase, or from senders that ignore
unsubscribe requests.

### 8.1 Classification (subproject 3)

A HEADER-phase classifier marks a message as `bulk`, with a confidence value and its reasons.

- **Signals:**
  - `List-Unsubscribe` (RFC 2369) and one-click `List-Unsubscribe-Post` (RFC 8058); since 2024
    Gmail and Yahoo require them from bulk senders;
  - `Precedence: bulk`, `Feedback-ID`, campaign headers;
  - a DKIM `d=` domain of a known email service provider (Mailchimp, SendGrid, Brevo, Klaviyo,
    Ecomail, SmartEmailing, …), kept in an updatable data file;
  - VERP-style envelope senders.
- **Transactional mail must not be hit** (order confirmations, invoices, password resets).
  Precision beats recall: when unsure, the message is not marked `bulk`.
- **Discussion lists are not marketing.** Messages with `List-Post` are treated as mailing-list
  traffic (section 4), not as bulk.
- The maillog records `bulk=yes` with the reasons.

### 8.2 Default action: tag only

- Header field `X-ASSP-NG-Bulk: yes (<reasons>); id=<address>; sig=v1.<key id>.<mac>`. No score
  and no rejection by default.
  - `id` is the author address (`From:`), present only when DMARC passed.
  - `sig` is an HMAC-SHA256 over `"bulk|" + id`, with the keys from 5.2 (same encoding).
  - Without an authenticated identity the header is just `yes (<reasons>)`.
  - Why the signature: the core strips incoming `X-ASSP-NG-*` fields, but mail delivered locally
    without passing ASSP-NG (for example a web application using `sendmail`) could carry a forged
    header. Without the signature, such a header could make a user block any sender (6.1, point 2).
- The documentation provides a Dovecot global Sieve example that files such mail into a
  "Newsletters" folder (like Gmail's Promotions tab), so nothing is lost and the inbox stays
  clean.
- Recipient-level settings (default, domain, mailbox): `bulk.mode = off | tag | score` (default
  `tag`), `bulk.score` (default 0), `bulk.subject_tag` (default empty).

### 8.3 `bulkblock` list

- A list type with the same storage, CLI, scopes and optional expiry as the other lists:

  ```
  assp-ng bulkblock add @aggressive-shop.example user:jano@firma.sk
  assp-ng bulkblock del | list | show ...
  ```
- **Effect:** when a message is classified `bulk` **and** a sender identity (section 4) matches
  the entry **and** that identity is authenticated (pass), the recipient refuses it with
  `550 5.7.1 Recipient refuses marketing from this sender`. Non-bulk mail from the same sender
  (the next order confirmation) still passes.
- **Rejected, not silently discarded:** email service providers suppress an address after a hard
  bounce to protect their reputation, so the rejection effectively unsubscribes the user. Silent
  discarding would let the sender continue forever. Rejecting during SMTP also follows the ASSP
  principle (no backscatter), and sending marketing after an unsubscribe is unlawful in the EU
  anyway.
- The decision is made in the HEADER phase. It rejects when the entry covers all recipients of the
  transaction (marketing mail is normally sent one recipient per message). Otherwise it only tags.
- Hits are counted per entry, so the admin sees how often each sender tries.
- **Entries from folder moves** (6.1, point 2). When a user moves a marketing message into Junk,
  `assp-ng learn spam` adds a `bulkblock` entry for that user. The entry holds:
  - the signed author identity from the `X-ASSP-NG-Bulk` header (8.2), as an exact address;
  - scope `user:<mailbox>`;
  - source `learn`.

  The envelope sender is never used. ESPs send from VERP addresses (`bounce-123@mail.esp.com`),
  and blocking such a domain would block every customer of the ESP. Moving the message back out
  of Junk removes the entry.
- **The user documentation says plainly** that moving a newsletter into Junk unsubscribes from
  it. The next message gets the 550, and the ESP then usually suppresses the address. Removing
  our entry does not undo that suppression; the user has to subscribe again on the sender's
  website.

### 8.4 One-click unsubscribe and enforcement (subproject 5)

- An **"Unsubscribe"** action in the web interface performs the RFC 8058 one-click unsubscribe
  (HTTP POST) on the user's behalf.
- **Restrictions**, because the server would act on links taken from untrusted mail:
  - only on the user's explicit request;
  - only if the message carries a passing DKIM signature that covers `List-Unsubscribe` and
    `List-Unsubscribe-Post` (as RFC 8058 requires);
  - HTTPS only, and only to public addresses: the resolved IP is checked, private, loopback and
    link-local ranges are refused, also after redirects (SSRF protection);
  - short timeouts;
  - never for mail classified as spam, which would only confirm the address to a spammer.
- ASSP-NG records the unsubscribe date per recipient and sender identity. If bulk mail from that
  sender still arrives after a grace period (default 10 days), a `bulkblock` entry is created
  automatically (`source = auto`) and the user is informed.

---

## 9. Outbound protection (subproject 4)

- Per-user rate limits (already in subproject 1) extended by anomaly detection:
  - login from a new country or network, one account from many IPs;
  - volume jump against the user's baseline;
  - many first-time recipients, `MAIL FROM` differing from the authenticated account.
- **Automatic lock:** above thresholds, sending for the account is suspended (`421`), the admin is
  alerted, and the admin unlocks it (later in the web interface).
- Outbound content checks (antivirus, URL, Bayes, later AI) with their own thresholds.

---

## 10. Other items

- **Web interface (subproject 5):** shows configuration read-only and manages data (domains,
  lists, penalty box, corpus, reporting and learning). Editing configuration from the web, if ever
  needed, would go through a separate privileged helper. Self-service for end users is decided
  there.
- **AI phishing check (subproject 6):** BODY-phase check with a strict timeout and a "tag only"
  mode. Sending message content to a remote model has GDPR implications.
- **ISPConfig:** optional source of local domains (subproject 6) and of DKIM keys for OpenDKIM
  (Postfix assistant, with subproject 2).
- **Postfix assistant:** filters are disabled only when the installed ASSP-NG replaces them.
  rspamd and postgrey go with subproject 2, amavis and clamav-milter with subproject 3.
