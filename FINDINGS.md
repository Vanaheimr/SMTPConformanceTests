# Findings

Every finding below is pinned by at least one test that asserts what the RFC
says. Those tests carry `[Category("KnownIssue")]` and a `Finding` property with
the ID, so the merge gate stays green while they stay red. When a fix lands,
the test turns green, the nightly reports it as "now passing", and the tag
comes off.

Measured against **Hermod `8af03484`** (Styx `fc2aeddb`), 2026-10-03.
Line numbers refer to that revision, under `libs/Hermod/Hermod/SMTP/`.

```powershell
dotnet test SMTPConformanceTests.slnx --filter "TestCategory=KnownIssue"
```

| ID | Severity | Area | Summary | Tests |
|---|---|---|---|---|
| [S-1](#s-1) | **critical** | server | SMTP smuggling: bare LF / bare CR end a line, so `<LF>.<LF>` ends DATA | 8 |
| [S-2](#s-2) | **high** | server | A rejected BDAT does not consume its chunk — the chunk is executed as commands | 2 |
| [C-1](#c-1) | **high** | client | STARTTLS refused with 454 → the client sends the message in cleartext | 1 |
| [S-11](#s-11) | medium | server | SMTPUTF8 envelope addresses are decoded as Latin-1 (`jÃ¶ran@…`) | 2 |
| [S-14](#s-14) | medium | server | REQUIRETLS and DSN parameters are lost on the way into the relay queue | 2 |
| [S-5](#s-5) | medium | server | AUTH failures carry the reply code twice (`535 535 5.7.8 …`) | 2 |
| [S-6](#s-6) | medium | server | Unknown or malformed MAIL/RCPT parameters are silently accepted | 6 |
| [C-4](#c-4) | medium | client | 8-bit content is sent to a server without 8BITMIME | 2 |
| [C-2](#c-2) | medium | client | No fallback to HELO when EHLO is refused | 2 |
| [S-3](#s-3) | low | server | DATA after BDAT in the same transaction is accepted | 1 |
| [S-4](#s-4) | low | server | Replies without RFC 2034 enhanced status codes | 5 |
| [S-7](#s-7) | low | server | `SIZE=` above the limit is not refused at MAIL | 1 |
| [S-8](#s-8) | low | server | HELO/EHLO without argument, DATA/STARTTLS with one: accepted | 4 |
| [S-9](#s-9) | low | server | A second MAIL inside a transaction silently restarts it | 1 |
| [S-10](#s-10) | low | server | `RCPT TO:<Postmaster>` is refused as a relay attempt | 1 |
| [S-12](#s-12) | low | server | Non-ASCII addresses accepted without the SMTPUTF8 parameter | 2 |
| [S-13](#s-13) | low | server | With `RequireStartTls`, only MAIL is gated; AUTH, VRFY, RSET are not | 3 |
| [S-15](#s-15) | low | server | AUTH is accepted during a mail transaction | 1 |
| [S-16](#s-16) | low | server | Undecodable base64 in AUTH is 535, not 501 5.5.2 | 1 |
| [S-17](#s-17) | low | server | RSET discards the authentication | 1 |
| [C-3](#c-3) | low | client | EHLO keywords are matched case-sensitively | 1 |
| [C-5](#c-5) | low | client | A bare LF in the body goes out as a bare LF | 1 |
| [C-6](#c-6) | low | client | Default EHLO argument is the bare host name, not an FQDN | 1 |
| [C-7](#c-7) | low | client | Declared `SIZE=` is two octets short | 1 |

52 tests in all. Besides these, [observations](#observations-without-a-test-yet)
from reading the code that are not pinned by a test yet.

---

## Server

### S-1
**SMTP smuggling: bare LF and bare CR are accepted as line terminators.**

RFC 5321 §2.3.8: *"Conforming implementations MUST NOT recognize or generate any
other character or character sequence as a line terminator."*

`SMTPSession.ReadLineAsync` (`SMTPSession.cs:1156`) is `StreamReader.ReadLineAsync`,
which ends a line at CR, LF or CRLF alike. `HandleDataAsync` (`:647`) therefore
ends the message at `<LF>.<LF>`, `<CR>.<CR>` and four other mixed forms, and
reads what follows as commands. All six variants deliver a second, smuggled
message with an arbitrary `MAIL FROM` (CVE-2023-51764/-51765/-51766 class, SEC
Consult 2023). An outbound MTA that forwards bare LFs as data — Postfix before
its smuggling fix did — lets any of its authenticated users inject mail into
Hermod "from" any address that MTA is authorised for under SPF.

Fix: read lines byte-wise, terminate on CRLF only; reject (or at least never
treat as terminator) a bare CR or LF, as Postfix (`smtpd_forbid_bare_newline`)
and Exim now do.

Tests: `LineTerminatorTests` — six `Smuggling: …` cases, `A_bare_LF_does_not_terminate_a_command`,
`A_bare_CR_does_not_terminate_a_command`.

Fix proposed in [Vanaheimr/Hermod#95](https://github.com/Vanaheimr/Hermod/pull/95), together with S-2.

### S-2
**A rejected BDAT does not consume its chunk.**

RFC 3030 §2: *"If a failure occurs after a BDAT command is received, the
receiver-SMTP MUST accept and discard the associated message data before
sending the appropriate 5XX or 4XX code."*

`HandleBdatAsync` (`SMTPSession.cs:714`, `:737`) returns 503 (no recipient) or
552 (too large) *before* reading the announced octets. The chunk is then parsed
as commands: `BDAT 12 LAST` + `NOOP\r\nNOOP\r\n` yields `503, 250, 250`. With
pipelining that is command injection by anyone who can make a BDAT fail.

Tests: `ChunkingTests.A_rejected_bdat_still_consumes_its_chunk`,
`ChunkingTests.An_oversized_bdat_still_consumes_its_chunk`.

Fix proposed in [Vanaheimr/Hermod#95](https://github.com/Vanaheimr/Hermod/pull/95).

### S-3
**DATA after BDAT in the same transaction is accepted.** RFC 3030 §2: *"If a DATA
statement is issued after a BDAT for the current transaction, a 503 'Bad sequence
of commands' MUST be issued."* `HandleDataAsync` (`:616`) does not look at
`_inBdatSequence`. Test: `ChunkingTests.Data_after_bdat_in_the_same_transaction_is_503`.

### S-4
**Replies without enhanced status codes.** RFC 2034 §4: once
`ENHANCEDSTATUSCODES` is advertised, *"the text part of all 2xx, 4xx, and 5xx SMTP
responses other than the initial greeting and any response to HELO or EHLO are
prefaced with a status code"*. Missing on `250 OK` (NOOP `:241`, RSET `:1123`),
`252 Cannot verify user` (`:249`), `500 Unrecognized command` (`:254`), `221 … closing
connection` (`:1144`), and on the 503s "Say HELO first" (`:310`, `:487`), "TLS already
active", "Already authenticated". Tests: `EnhancedStatusCodeTests` — five cases.

### S-5
**AUTH failures carry the reply code twice.** The auth handlers return
`ErrorCode: "535 5.7.8 …"` (`PlainAuthHandler.cs:54`, `LoginAuthHandler.cs:75`,
`ScramSha256AuthHandler.cs:56`, …, `SmtpAuthManager.cs` for `504 5.5.4`), and
`SMTPSession.HandleAuthResultAsync` (`:386`) / `HandleAuthAsync` (`:347`) prepend the
code again: `535 535 5.7.8 Authentication failed`, `504 504 5.5.4 Unrecognized
authentication type`. The reply is still parseable, but the enhanced code is no
longer where RFC 2034 puts it, so clients report "no enhanced code".
Tests: `AuthTests.Wrong_password_is_535`, `EnhancedStatusCodeTests` "unknown AUTH mechanism (504)".

### S-6
**Unknown or malformed MAIL/RCPT parameters are silently accepted.** RFC 5321
§4.1.1.11: *"If the server SMTP does not recognize or cannot implement one or more
of the parameters associated with a particular MAIL FROM or RCPT TO command, it
will return code 555."* `HandleMailFromAsync` (`:497`) and `HandleRcptToAsync`
(`:548`) pick out the parameters they know and ignore the rest, including
malformed values of known ones: `X-NO-SUCH-PARAM=1`, `BODY=9BITMIME` (RFC 6152 §2),
`SIZE=huge` (RFC 1870 §3), `RET=BODY` (RFC 3461 §4.3), and `NOTIFY=NEVER,SUCCESS`
(RFC 3461 §4.1: *"the NEVER keyword MUST appear by itself"*). Tests: six, in
`CommandSyntaxTests`, `InternationalizationTests`, `SizeExtensionTests`, `DsnParameterTests`.

### S-7
**`SIZE=` above the limit is not refused at MAIL.** RFC 1870 §6.1: *"If the
indicated size is larger than the server's fixed maximum message size, the server
responds with code 552."* The declared size is never read; the message is
transferred in full and only then refused. Test: `SizeExtensionTests.A_declared_size_above_the_limit_is_rejected_at_mail_with_552`.

### S-8
**Argument syntax is not checked.** `EHLO` and `HELO` without a domain are
answered 250 (RFC 5321 §4.1.1.1 grammar → 501; `:260`, `:268`). `DATA please`
starts a DATA phase (§4.1.1.4: `data = "DATA" CRLF`). `STARTTLS now` starts TLS
(RFC 3207 §4: *"501 Syntax error (no parameters allowed)"*). Tests: four.

### S-9
**A second MAIL inside a transaction restarts it.** RFC 5321 §3.3 forbids the
client to send it; §4.3.2 lists 503 as the server's answer. `HandleMailFromAsync`
(`:526`) clears the recipients and answers 250. Test:
`TransactionStateTests.A_second_mail_inside_a_transaction_is_503`.

### S-10
**`RCPT TO:<Postmaster>` is refused.** RFC 5321 §4.5.1: *"the special case of
'RCPT TO:<Postmaster>' (with no domain specification), MUST be supported."*
`ExtractDomain` (`:1103`) yields `""`, which is not a local domain, so the
recipient is treated as relay and refused with 550. Test:
`RelayAndPostmasterTests.Postmaster_without_a_domain_is_accepted`.

### S-11
**SMTPUTF8 envelope addresses are decoded as Latin-1.** The session reader is
Latin-1 (`:52`), deliberately, so that DATA/BDAT octets survive — and the message
body is re-decoded as UTF-8 (`:698`). The envelope is not: `jöran@bücher.example`
reaches storage, the relay queue and the `Received:` header as
`jÃ¶ran@bÃ¼cher.example`. RFC 6531 §3.3 makes the addresses UTF-8. Reproduced with
CPython's `smtplib` as well. Tests: `InternationalizationTests.Utf8_addresses_with_the_smtputf8_parameter_are_accepted`,
`PythonSmtplibTests.Smtplib_smtputf8_delivery`.

### S-12
**Non-ASCII addresses are accepted without the SMTPUTF8 parameter.** RFC 6531 §3.5:
550 for MAIL, 553 for RCPT. Tests: two in `InternationalizationTests`.

### S-13
**`RequireStartTls` gates only MAIL.** RFC 3207 §4: the server *"SHOULD return the
reply code: 530 Must issue a STARTTLS command first to every command other than
NOOP, EHLO, STARTTLS, or QUIT."* AUTH (SCRAM is offered in cleartext), VRFY and
RSET are answered normally. Tests: three cases in `RequireStartTlsTests`.

### S-14
**REQUIRETLS and DSN parameters are dropped when a message is queued for relay.**
`ProcessReceivedMessageAsync` (`:967`) builds the `QueuedMail` with `Priority` but
without `RequireTls`, `EnvId`, `Ret` or `Notify`, although the session parsed all
of them. RFC 8689 §5 requires the REQUIRETLS tag to travel with the message
(the README claims it is "propagated to enforced outbound delivery"); RFC 3461
§5.2.1: ENVID, RET and NOTIFY *"MUST also appear"* on the relayed MAIL/RCPT.
Note that `QueuedMail.Notify` is per message, while NOTIFY and ORCPT are per
recipient. Tests: `StartTlsTests.Requiretls_is_carried_onto_the_relay_queue`,
`AuthTests.Dsn_parameters_are_carried_onto_the_relay_queue`.

### S-15
**AUTH is accepted during a mail transaction.** RFC 4954 §4: *"An AUTH command
issued during a mail transaction MUST be rejected with a 503 reply."* Test:
`AuthTests.Auth_during_a_transaction_is_503`.

### S-16
**Undecodable base64 in an AUTH response is 535.** RFC 4954 §4: *"If the server
cannot [BASE64] decode any client response, it MUST reject the AUTH command with
a 501 reply (and an enhanced status code of 5.5.2)."* Test:
`AuthTests.An_undecodable_response_is_501_5_5_2`.

### S-17
**RSET discards the authentication** (`HandleRsetAsync`, `:1122`,
`_authManager.Reset()`). No RFC sentence says RSET keeps it — but RFC 5321
§4.1.1.5 scopes RSET to the transaction, and RFC 4954 §4 says that after a
successful AUTH *"no more AUTH commands may be issued in the same session"*. A
client that RSETs (most do, between messages) is left unauthenticated with no
legitimate way back; its next relay RCPT gets 550. Postfix, Exim and Dovecot
keep the authentication. Test: `AuthTests.Rset_keeps_the_authentication`.

---

## Submission client (`SMTPSubmissionClient`)

### C-1
**A refused STARTTLS silently downgrades to cleartext.** With `UseTLS = STARTTLS`,
a `454` (or any non-220) reply to STARTTLS (`SMTPSubmissionClient.cs:792`) has no
else branch: the client sends EHLO again and carries on in cleartext. With
credentials it stops one step later — AUTH is never sent without TLS, so the
result is `InvalidLogin`; **without credentials the whole message goes out in
the clear.** An on-path attacker only has to rewrite one reply. RFC 3207 §6
names exactly this attack; a client configured to require TLS must stop. (The
"STARTTLS not advertised" path does throw; only the refused path leaks.) Test:
`SubmissionClientTests.A_refused_starttls_does_not_downgrade`.

Fix proposed in [Vanaheimr/Hermod#96](https://github.com/Vanaheimr/Hermod/pull/96):
all three failure paths end with a new `MailSentStatus.TLSUnavailable`, no retry.

### C-2
**No HELO fallback.** RFC 5321 §3.2: a client must be able to accept 500/501/502/550
to EHLO, and should then fall back to HELO. Any non-250 EHLO reply throws
(`:769`). Also seen against Postfix `smtp-sink -e`. Tests:
`SubmissionClientTests.Ehlo_refused_falls_back_to_helo`, `SmtpSinkTests.Helo_fallback_against_a_non_esmtp_server`.

### C-3
**EHLO keywords are compared case-sensitively** (`== "STARTTLS"`, `== "8BITMIME"`,
… `:787`, `:833`ff). RFC 5321 §2.4 makes them case-insensitive; a server
advertising `starttls` gets "TLS is not supported". Test:
`SubmissionClientTests.Ehlo_keywords_are_case_insensitive`.

### C-4
**8-bit content to a server without 8BITMIME.** RFC 5321 §2.4: *"An SMTP client
that has not successfully negotiated an appropriate extension ... MUST NOT
transmit messages with information in the high-order bit of octets."* A
`text/plain; charset=utf-8` body goes out as raw UTF-8 regardless. Also seen
against `smtp-sink -8`. Tests: `SubmissionClientTests.No_8bit_data_without_8bitmime`,
`SmtpSinkTests.No_8bit_octets_without_8bitmime`.

### C-5
**A bare LF in the body is sent as a bare LF** (`SendDataAsync`, `:424`, writes
each serialized line verbatim). RFC 5321 §2.3.8. Against a server with S-1's
behaviour this is exactly a smuggling primitive. Test:
`SubmissionClientTests.A_bare_LF_in_the_body_is_not_sent_bare`.

### C-6
**The default EHLO argument is `Dns.GetHostName()`** (`:173`) — `octal` on the
test machine. RFC 5321 §4.1.4: a primary host name (FQDN) or an address literal.
Test: `SubmissionClientTests.Default_ehlo_argument_is_a_domain_or_address_literal`.

### C-7
**The declared `SIZE=` is two octets short** (`:996`, `String.Join("\r\n", lines)`
omits the final CRLF). RFC 1870 §5 counts all CRLFs. Harmless except at the exact
limit. Test: `SubmissionClientTests.Declared_size_covers_the_message`.

---

## Observations without a test yet

- **`VerifySpf` / `VerifyDkim` / `VerifyDmarc` have no effect.** `SMTPServerConfig`
  carries them and `Start()` logs them, but `ProcessReceivedMessageAsync` (`:813`)
  calls `DNSVerifier.VerifyAsync` unconditionally for every unauthenticated
  sender. (The fixture therefore needs a stub DNS client even for plain tests.)
- **The server always binds `IPAddress.Any`, IPv4 only** (`SMTPServer.cs`), with no
  option for loopback, a specific address or IPv6, and no way to learn the bound
  port — which is why the fixture has to pick free ports itself.
- **Unbounded line reads.** The command-line limit (`MaxCommandLineLength`) is
  checked *after* `StreamReader.ReadLineAsync` has buffered the whole line; a peer
  that never sends LF grows the buffer until the session timeout.
- **Session timeout closes without a 421** (RFC 5321 §4.5.3.2 / §3.8).
- **Client: one refused RCPT aborts the whole transaction** without RSET or QUIT,
  and after any exception the connection stays open until `Dispose()`.
- **Client reply reader** decodes each TCP read as UTF-8 on its own (a multi-byte
  character split across segments is corrupted) and keeps no surplus bytes
  between replies.
- **Client never uses PIPELINING or CHUNKING** even when advertised — not a
  conformance issue, but a latency one.
