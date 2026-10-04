# Findings

Every finding below is pinned by at least one test that asserts what the RFC
says. Those tests carry `[Category("KnownIssue")]` and a `Finding` property with
the ID, so the merge gate stays green while they stay red. When a fix lands,
the test turns green, the nightly reports it as "now passing", and the tag
comes off — the `Finding` property stays, so the test still says which finding
it guards.

First measured against **Hermod `8af03484`** (Styx `fc2aeddb`), 2026-10-03; line
numbers refer to that revision, under `libs/Hermod/Hermod/SMTP/`. Pinned to
**Hermod `d2d608d2`** (Styx `c530de16`), which closes every one of them. The
second round (S-18 and on, C-8 and on) comes from the observations the first one
left without a test; its line numbers refer to `96a8048d`.

```powershell
dotnet test SMTPConformanceTests.slnx --filter "TestCategory=KnownIssue"
```

### Open

None. A new finding gets a test tagged `KnownIssue` and a row here.

### Closed

| ID | Severity | Area | Summary | Tests | Fixed in |
|---|---|---|---|---|---|
| [S-1](#s-1) | **critical** | server | SMTP smuggling: bare LF / bare CR end a line, so `<LF>.<LF>` ends DATA | 8 | [Vanaheimr/Hermod#95](https://github.com/Vanaheimr/Hermod/pull/95) |
| [S-2](#s-2) | **high** | server | A rejected BDAT does not consume its chunk — the chunk is executed as commands | 2 | [Vanaheimr/Hermod#95](https://github.com/Vanaheimr/Hermod/pull/95) |
| [C-1](#c-1) | **high** | client | STARTTLS refused with 454 → the client continues in cleartext | 1 | [Vanaheimr/Hermod#96](https://github.com/Vanaheimr/Hermod/pull/96) |
| [S-11](#s-11) | medium | server | SMTPUTF8 envelope addresses were decoded as Latin-1 (`jÃ¶ran@…`) | 2 | [Vanaheimr/Hermod#99](https://github.com/Vanaheimr/Hermod/pull/99) |
| [S-14](#s-14) | medium | server | REQUIRETLS and DSN parameters were lost on the way into the relay queue | 2 | [Vanaheimr/Hermod#100](https://github.com/Vanaheimr/Hermod/pull/100) |
| [S-5](#s-5) | medium | server | AUTH failures carried the reply code twice (`535 535 5.7.8 …`) | 2 | [Vanaheimr/Hermod#98](https://github.com/Vanaheimr/Hermod/pull/98) |
| [S-6](#s-6) | medium | server | Unknown or malformed MAIL/RCPT parameters were silently accepted | 6 | [Vanaheimr/Hermod#101](https://github.com/Vanaheimr/Hermod/pull/101) |
| [C-4](#c-4) | medium | client | 8-bit content was sent to a server without 8BITMIME | 2 | [Vanaheimr/Hermod#103](https://github.com/Vanaheimr/Hermod/pull/103) |
| [C-2](#c-2) | medium | client | No fallback to HELO when EHLO was refused | 2 | [Vanaheimr/Hermod#102](https://github.com/Vanaheimr/Hermod/pull/102) |
| [S-3](#s-3) | low | server | DATA after BDAT in the same transaction was accepted | 1 | [Vanaheimr/Hermod#111](https://github.com/Vanaheimr/Hermod/pull/111) |
| [S-7](#s-7) | low | server | `SIZE=` above the limit was not refused at MAIL | 1 | [Vanaheimr/Hermod#109](https://github.com/Vanaheimr/Hermod/pull/109) |
| [S-16](#s-16) | low | server | Undecodable base64 in AUTH was 535, not 501 5.5.2 | 1 | [Vanaheimr/Hermod#110](https://github.com/Vanaheimr/Hermod/pull/110) |
| [S-17](#s-17) | low | server | RSET discarded the authentication | 1 | [Vanaheimr/Hermod#105](https://github.com/Vanaheimr/Hermod/pull/105) |
| [S-4](#s-4) | low | server | Replies without RFC 2034 enhanced status codes | 5 | [Vanaheimr/Hermod#113](https://github.com/Vanaheimr/Hermod/pull/113) |
| [S-8](#s-8) | low | server | HELO/EHLO without argument, DATA/STARTTLS with one: accepted | 4 | [Vanaheimr/Hermod#114](https://github.com/Vanaheimr/Hermod/pull/114) |
| [S-9](#s-9) | low | server | A second MAIL inside a transaction silently restarted it | 1 | [Vanaheimr/Hermod#115](https://github.com/Vanaheimr/Hermod/pull/115) |
| [S-10](#s-10) | low | server | `RCPT TO:<Postmaster>` was refused as a relay attempt | 1 | [Vanaheimr/Hermod#116](https://github.com/Vanaheimr/Hermod/pull/116) |
| [S-15](#s-15) | low | server | AUTH was accepted during a mail transaction | 1 | [Vanaheimr/Hermod#117](https://github.com/Vanaheimr/Hermod/pull/117) |
| [C-5](#c-5) | low | client | A bare LF in the body went out as a bare LF | 1 | [Vanaheimr/Hermod#120](https://github.com/Vanaheimr/Hermod/pull/120) |
| [C-3](#c-3) | low | client | EHLO keywords were matched case-sensitively | 1 | [Vanaheimr/Hermod#118](https://github.com/Vanaheimr/Hermod/pull/118) |
| [C-6](#c-6) | low | client | Default EHLO argument was the bare host name, not an FQDN | 1 | [Vanaheimr/Hermod#119](https://github.com/Vanaheimr/Hermod/pull/119) |
| [C-7](#c-7) | low | client | Declared `SIZE=` was two octets short | 1 | [Vanaheimr/Hermod#120](https://github.com/Vanaheimr/Hermod/pull/120) |
| [S-12](#s-12) | low | server | Non-ASCII addresses were accepted without the SMTPUTF8 parameter | 2 | [Vanaheimr/Hermod#122](https://github.com/Vanaheimr/Hermod/pull/122) |
| [S-13](#s-13) | low | server | With `RequireStartTls`, only MAIL was gated; AUTH, VRFY, RSET were not | 3 | [Vanaheimr/Hermod#123](https://github.com/Vanaheimr/Hermod/pull/123) |
| [C-8](#c-8) | medium | client | A failed attempt ended without QUIT, the connection left open | 7 | [Vanaheimr/Hermod#126](https://github.com/Vanaheimr/Hermod/pull/126) |
| [C-9](#c-9) | low | client | Each TCP read was decoded as UTF-8 on its own; surplus bytes were dropped | 1 | [Vanaheimr/Hermod#127](https://github.com/Vanaheimr/Hermod/pull/127) |
| [S-18](#s-18) | low | server | Listened on IPv4 `Any` only, no address choice, bound ports unknown | 2 | [Vanaheimr/Hermod#125](https://github.com/Vanaheimr/Hermod/pull/125) |
| [S-19](#s-19) | low | server | An idle session was closed without saying why (no 421) | 1 | [Vanaheimr/Hermod#124](https://github.com/Vanaheimr/Hermod/pull/124) |
| [C-10](#c-10) | low | client | PIPELINING and CHUNKING were never used | 2 | [Vanaheimr/Hermod#127](https://github.com/Vanaheimr/Hermod/pull/127) |

The 65 tests for these are part of the merge gate now; the observations the first
round noted without a test are [accounted for](#observations-without-a-test-yet).

---

## Server

### S-1
**Closed** in [Vanaheimr/Hermod#95](https://github.com/Vanaheimr/Hermod/pull/95) (`edcb81f3`).
**SMTP smuggling: bare LF and bare CR were accepted as line terminators.**

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

Fixed: `SMTPLineReader` ends lines at CR LF only. A bare CR/LF in a command
is `500 5.5.2`; in content it rejects the message with `550 5.5.2` after the end
of data, or is normalized to CR LF with `SMTPServerConfig.RejectBareLineEndings = false`.

### S-2
**Closed** in [Vanaheimr/Hermod#95](https://github.com/Vanaheimr/Hermod/pull/95) (`edcb81f3`).
**A rejected BDAT did not consume its chunk.**

RFC 3030 §2: *"If a failure occurs after a BDAT command is received, the
receiver-SMTP MUST accept and discard the associated message data before
sending the appropriate 5XX or 4XX code."*

`HandleBdatAsync` (`SMTPSession.cs:714`, `:737`) returns 503 (no recipient) or
552 (too large) *before* reading the announced octets. The chunk is then parsed
as commands: `BDAT 12 LAST` + `NOOP\r\nNOOP\r\n` yields `503, 250, 250`. With
pipelining that is command injection by anyone who can make a BDAT fail.

Tests: `ChunkingTests.A_rejected_bdat_still_consumes_its_chunk`,
`ChunkingTests.An_oversized_bdat_still_consumes_its_chunk`.

Fixed: every refusal with a known chunk size reads and discards the chunk first.

### S-3
**Closed** in [Vanaheimr/Hermod#111](https://github.com/Vanaheimr/Hermod/pull/111) (`26e540bb`).
**DATA after BDAT in the same transaction was accepted.** RFC 3030 §2: *"If a DATA
statement is issued after a BDAT for the current transaction, a 503 'Bad sequence
of commands' MUST be issued."* `HandleDataAsync` (`:616`) does not look at
`_inBdatSequence`. Test: `ChunkingTests.Data_after_bdat_in_the_same_transaction_is_503`.

Checking the fix showed what the old behaviour did with the message: DATA took
a body of its own, that body alone was delivered, and the BDAT chunks already
received were dropped with the transaction. Fixed: DATA is 503 while a BDAT
sequence is open; the chunks stay, and BDAT … LAST still completes.

### S-4
**Closed** in [Vanaheimr/Hermod#113](https://github.com/Vanaheimr/Hermod/pull/113) (`7988e6c6`).
**Replies without enhanced status codes.** RFC 2034 §4: once
`ENHANCEDSTATUSCODES` is advertised, *"the text part of all 2xx, 4xx, and 5xx SMTP
responses other than the initial greeting and any response to HELO or EHLO are
prefaced with a status code"*. Missing on `250 OK` (NOOP `:241`, RSET `:1123`),
`252 Cannot verify user` (`:249`), `500 Unrecognized command` (`:254`), `221 … closing
connection` (`:1144`), and on the 503s "Say HELO first" (`:310`, `:487`), "TLS already
active", "Already authenticated". Tests: `EnhancedStatusCodeTests` — five cases.

Fixing it turned up four more: the 220 to STARTTLS, the 454 without a
certificate, the 501 to AUTH without a mechanism and the 501 to a cancelled AUTH.
All 13 carry a code now (2.0.0, 5.5.1, 5.5.4, 4.7.0, 5.7.0 by RFC 3463 class);
`EnhancedStatusCodeTests` gained the two AUTH cases that need no TLS.

### S-5
**Closed** in [Vanaheimr/Hermod#98](https://github.com/Vanaheimr/Hermod/pull/98) (`0887e06e`).
**AUTH failures carried the reply code twice.** The auth handlers return
`ErrorCode: "535 5.7.8 …"` (`PlainAuthHandler.cs:54`, `LoginAuthHandler.cs:75`,
`ScramSha256AuthHandler.cs:56`, …, `SmtpAuthManager.cs` for `504 5.5.4`), and
`SMTPSession.HandleAuthResultAsync` (`:386`) / `HandleAuthAsync` (`:347`) prepend the
code again: `535 535 5.7.8 Authentication failed`, `504 504 5.5.4 Unrecognized
authentication type`. The reply is still parseable, but the enhanced code is no
longer where RFC 2034 puts it, so clients report "no enhanced code".
Tests: `AuthTests.Wrong_password_is_535`, `EnhancedStatusCodeTests` "unknown AUTH mechanism (504)".

Fixed: the session takes the reply code from the handler's text when it begins
with one (`SendAuthRefusalAsync`), so `503 5.5.1 AUTH not started` is a 503 now as well.

### S-6
**Closed** in [Vanaheimr/Hermod#101](https://github.com/Vanaheimr/Hermod/pull/101) (`a08ac031`).
**Unknown or malformed MAIL/RCPT parameters were silently accepted.** RFC 5321
§4.1.1.11: *"If the server SMTP does not recognize or cannot implement one or more
of the parameters associated with a particular MAIL FROM or RCPT TO command, it
will return code 555."* `HandleMailFromAsync` (`:497`) and `HandleRcptToAsync`
(`:548`) pick out the parameters they know and ignore the rest, including
malformed values of known ones: `X-NO-SUCH-PARAM=1`, `BODY=9BITMIME` (RFC 6152 §2),
`SIZE=huge` (RFC 1870 §3), `RET=BODY` (RFC 3461 §4.3), and `NOTIFY=NEVER,SUCCESS`
(RFC 3461 §4.1: *"the NEVER keyword MUST appear by itself"*). Tests: six, in
`CommandSyntaxTests`, `InternationalizationTests`, `SizeExtensionTests`, `DsnParameterTests`.

Fixed: `ESMTPParameters` checks every MAIL/RCPT parameter against what is
advertised — unknown ones, and any after HELO, are 555; invalid values 501. A
parameter repeated with the same value is tolerated, because CPython's smtplib
sends `SMTPUTF8 SMTPUTF8`; the interop lane caught that before the fix went in.

### S-7
**Closed** in [Vanaheimr/Hermod#109](https://github.com/Vanaheimr/Hermod/pull/109) (`cec28b42`).
**`SIZE=` above the limit was not refused at MAIL.** RFC 1870 §6.1: *"If the
indicated size is larger than the server's fixed maximum message size, the server
responds with code 552."* The declared size is never read; the message is
transferred in full and only then refused. Test: `SizeExtensionTests.A_declared_size_above_the_limit_is_rejected_at_mail_with_552`.

Fixed: the declared size is compared at MAIL; a 20-digit value beyond UInt64
counts as larger than any limit.

### S-8
**Closed** in [Vanaheimr/Hermod#114](https://github.com/Vanaheimr/Hermod/pull/114) (`a4e083d3`).
**Argument syntax was not checked.** `EHLO` and `HELO` without a domain are
answered 250 (RFC 5321 §4.1.1.1 grammar → 501; `:260`, `:268`). `DATA please`
starts a DATA phase (§4.1.1.4: `data = "DATA" CRLF`). `STARTTLS now` starts TLS
(RFC 3207 §4: *"501 Syntax error (no parameters allowed)"*). Tests: four.

Fixed in one place next to the command parser: a command that breaks its
argument rule is 501 and not executed. `RSET now` had the same gap (§4.1.1.5) and
is covered too, with a fifth test, `CommandSyntaxTests.Rset_with_an_argument_is_rejected_with_501`.
QUIT with an argument (§4.1.1.10 allows none) still ends the session, as in Postfix: refusing it
would only keep a connection open that both sides are done with.

### S-9
**Closed** in [Vanaheimr/Hermod#115](https://github.com/Vanaheimr/Hermod/pull/115) (`c8684647`).
**A second MAIL inside a transaction restarted it.** RFC 5321 §4.1.4 forbids the
client to send it; §4.3.2 lists 503 as the server's answer. `HandleMailFromAsync`
(`:526`) clears the recipients and answers 250. Test:
`TransactionStateTests.A_second_mail_inside_a_transaction_is_503`.

Fixed: `503 5.5.1 Nested MAIL command`, as in Postfix; the open transaction keeps
its sender and recipients. Hermod's own clients send one message per session.

### S-10
**Closed** in [Vanaheimr/Hermod#116](https://github.com/Vanaheimr/Hermod/pull/116) (`7301f097`).
**`RCPT TO:<Postmaster>` was refused.** RFC 5321 §4.5.1: *"the special case of
'RCPT TO:<Postmaster>' (with no domain specification), MUST be supported."*
`ExtractDomain` (`:1103`) yields `""`, which is not a local domain, so the
recipient is treated as relay and refused with 550. Test:
`RelayAndPostmasterTests.Postmaster_without_a_domain_is_accepted`.

Fixed: domainless `Postmaster`, in any case, is `postmaster@<Hostname>` and
delivered locally whatever the relay rules; with the domain filled in, the MDN
generator, which parses each recipient as an address, sees an ordinary one.

### S-11
**Closed** in [Vanaheimr/Hermod#99](https://github.com/Vanaheimr/Hermod/pull/99) (`e835211c`).
**SMTPUTF8 envelope addresses were decoded as Latin-1.** The session reader is
Latin-1 (`:52`), deliberately, so that DATA/BDAT octets survive — and the message
body is re-decoded as UTF-8 (`:698`). The envelope is not: `jöran@bücher.example`
reaches storage, the relay queue and the `Received:` header as
`jÃ¶ran@bÃ¼cher.example`. RFC 6531 §3.3 makes the addresses UTF-8. Reproduced with
CPython's `smtplib` as well. Tests: `InternationalizationTests.Utf8_addresses_with_the_smtputf8_parameter_are_accepted`,
`PythonSmtplibTests.Smtplib_smtputf8_delivery`.

Fixed: every command line is decoded as UTF-8 before it is parsed; octets that are
not UTF-8 make it an invalid command (`500 5.5.2`). S-12 is untouched.

### S-12
**Closed** in [Vanaheimr/Hermod#122](https://github.com/Vanaheimr/Hermod/pull/122) (`5fc362d8`).
**Non-ASCII addresses were accepted without the SMTPUTF8 parameter.** RFC 6531 §3.5:
550 for MAIL, 553 for RCPT. Tests: two in `InternationalizationTests`.

Fixed: `550 5.6.7` / `553 5.6.7` (RFC 6533: "Non-ASCII addresses not permitted for
that sender/recipient"); the parameter counts per transaction. Clients with such
addresses send it already - smtplib on its own, Hermod's submission client too.

### S-13
**Closed** in [Vanaheimr/Hermod#123](https://github.com/Vanaheimr/Hermod/pull/123) (`96a8048d`).
**`RequireStartTls` gated only MAIL.** RFC 3207 §4: the server *"SHOULD return the
reply code: 530 Must issue a STARTTLS command first to every command other than
NOOP, EHLO, STARTTLS, or QUIT."* AUTH (SCRAM is offered in cleartext), VRFY and
RSET are answered normally. Tests: three cases in `RequireStartTlsTests`.

Fixed as RFC 3207 has it - HELO and unknown commands are 530 too - and EHLO no
longer advertises AUTH before TLS when TLS is required, like Postfix's
`smtpd_tls_auth_only`.

### S-14
**Closed** in [Vanaheimr/Hermod#100](https://github.com/Vanaheimr/Hermod/pull/100) (`0044ecf7`).
**REQUIRETLS and DSN parameters were dropped when a message was queued for relay.**
`ProcessReceivedMessageAsync` (`:967`) builds the `QueuedMail` with `Priority` but
without `RequireTls`, `EnvId`, `Ret` or `Notify`, although the session parsed all
of them. RFC 8689 §5 requires the REQUIRETLS tag to travel with the message
(the README claims it is "propagated to enforced outbound delivery"); RFC 3461
§5.2.1: ENVID, RET and NOTIFY *"MUST also appear"* on the relayed MAIL/RCPT.
Note that `QueuedMail.Notify` is per message, while NOTIFY and ORCPT are per
recipient. Tests: `StartTlsTests.Requiretls_is_carried_onto_the_relay_queue`,
`AuthTests.Dsn_parameters_are_carried_onto_the_relay_queue`.

Fixed: the queue entry keeps `RequireTls`, `EnvId`, `Ret` and, new,
`RecipientDsns` — NOTIFY and ORCPT per recipient — and `SMTPOutboundClient` writes
each relayed RCPT with its own NOTIFY (`NEVER` included) and its received ORCPT.
The relay client had also been rewriting every ORCPT from the recipient address and
applying one NOTIFY to all recipients; that is fixed with it. Still open: an absent
RET is relayed as `RET=FULL` (RFC 3461 leaves the absent case to the server).

### S-15
**Closed** in [Vanaheimr/Hermod#117](https://github.com/Vanaheimr/Hermod/pull/117) (`1b9a9a95`).
**AUTH was accepted during a mail transaction.** RFC 4954 §4: *"An AUTH command
issued during a mail transaction MUST be rejected with a 503 reply."* Test:
`AuthTests.Auth_during_a_transaction_is_503`.

It mattered beyond the reply code: completed, the AUTH let the later RCPTs run
under another identity than the MAIL, so a recipient just refused as relay would
be accepted into the same transaction. Fixed: 503 and no exchange started.

### S-16
**Closed** in [Vanaheimr/Hermod#110](https://github.com/Vanaheimr/Hermod/pull/110) (`15ac9f6c`).
**Undecodable base64 in an AUTH response was 535.** RFC 4954 §4: *"If the server
cannot [BASE64] decode any client response, it MUST reject the AUTH command with
a 501 reply (and an enhanced status code of 5.5.2)."* Test:
`AuthTests.An_undecodable_response_is_501_5_5_2`.

Fixed in all four handlers (PLAIN, LOGIN, SCRAM-SHA-256, EXTERNAL — the last had
ignored decode errors). Only the client response itself counts: a malformed
proof inside a well-encoded SCRAM message stays 535, and RFC 4954 §4's `=` is the
empty response, so `AUTH EXTERNAL =` keeps working.

### S-17
**Closed** in [Vanaheimr/Hermod#105](https://github.com/Vanaheimr/Hermod/pull/105) (`5dc976fa`), a fix made outside this suite's own round of PRs.
**RSET discarded the authentication** (`HandleRsetAsync`, `:1122`,
`_authManager.Reset()`). No RFC sentence says RSET keeps it — but RFC 5321
§4.1.1.5 scopes RSET to the transaction, and RFC 4954 §4 says that after a
successful AUTH *"no more AUTH commands may be issued in the same session"*. A
client that RSETs (most do, between messages) is left unauthenticated with no
legitimate way back; its next relay RCPT gets 550. Postfix, Exim and Dovecot
keep the authentication. Test: `AuthTests.Rset_keeps_the_authentication`.

### S-18
**Closed** in [Vanaheimr/Hermod#125](https://github.com/Vanaheimr/Hermod/pull/125) (`e2373666`).
**The server listened on IPv4 `Any` only** (`SMTPServer.cs:145`ff): every port is a
`TcpListener(IPAddress.Any, port)`. There is no way to listen on loopback only, on one
address of a multi-homed host, or on IPv6 - an MX reachable only over IPv6, or
reachable over both (RFC 5321 §5.1 and RFC 3974 assume an MX answers on the
addresses its name has), is out of reach. Nor can a caller learn the port the system
chose for port 0, which is why the suite's fixture probes for free ports itself.
Fixed: `SMTPServerConfig.ListenAddresses` (default IPv4 `Any`), IPv6 listeners IPv6
only, and `MtaEndPoints` / `SubmissionEndPoints` / `ImplicitTlsEndPoints` with the
ports actually bound. The fixture now runs on port 0 and asks; its free-port probe
and retry loop are gone. Tests: `ListenAddressTests`, IPv4 and IPv6 loopback
together, and a loopback server reporting its ports.

### S-19
**Closed** in [Vanaheimr/Hermod#124](https://github.com/Vanaheimr/Hermod/pull/124) (`9de11710`).
**An idle session was closed without a word** (`SMTPSession.ReadLineAsync`,
`:1420`ff: the timeout ends the read, the session loop ends, the socket closes). Not
a violation - RFC 5321 §3.8 allows closing after the §4.5.3.2 timeout - but a
`421 4.4.2 ... timeout` first, as Postfix sends and as §3.8 has it for a server that
must end the session, tells the client that the server gave up rather than that the
network broke. Test: `SessionTimeoutTests.An_idle_session_is_closed_with_421`; a
second test guards that a client that keeps talking is not cut off.

Fixed: `421 4.4.2 <host> Error: timeout exceeded`, also for a timeout in the middle
of DATA or a BDAT chunk - which until then reset the transaction and waited a
second timeout for a command.

---

## Submission client (`SMTPSubmissionClient`)

### C-1
**Closed** in [Vanaheimr/Hermod#96](https://github.com/Vanaheimr/Hermod/pull/96) (`c04587fe`).
**A refused STARTTLS silently downgraded to cleartext.** With `UseTLS = STARTTLS`,
a `454` (or any non-220) reply to STARTTLS (`SMTPSubmissionClient.cs:792`) has no
else branch: the client sends EHLO again and carries on in cleartext. With
credentials it stops one step later — AUTH is never sent without TLS, so the
result is `InvalidLogin`; **without credentials the whole message goes out in
the clear.** An on-path attacker only has to rewrite one reply. RFC 3207 §6
names exactly this attack; a client configured to require TLS must stop. (The
"STARTTLS not advertised" path does throw; only the refused path leaks.) Test:
`SubmissionClientTests.A_refused_starttls_does_not_downgrade`.

Fixed: STARTTLS not offered, refused, or a failed handshake all end the attempt
with the new `MailSentStatus.TLSUnavailable`, before anything is sent, and are
not retried.

### C-2
**Closed** in [Vanaheimr/Hermod#102](https://github.com/Vanaheimr/Hermod/pull/102) (`cc65c587`).
**No HELO fallback.** RFC 5321 §3.2: a client must be able to accept 500/501/502/550
to EHLO, and should then fall back to HELO. Any non-250 EHLO reply throws
(`:769`). Also seen against Postfix `smtp-sink -e`. Tests:
`SubmissionClientTests.Ehlo_refused_falls_back_to_helo`, `SmtpSinkTests.Helo_fallback_against_a_non_esmtp_server`.

Fixed: on 500/501/502/504/550 the client sends HELO and continues without
extensions. The negotiated capabilities are reset per connection now — they had
accumulated across connections, which after a fallback would have put ESMTP
parameters on MAIL.

### C-3
**Closed** in [Vanaheimr/Hermod#118](https://github.com/Vanaheimr/Hermod/pull/118) (`e3fcd84b`).
**EHLO keywords were compared case-sensitively** (`== "STARTTLS"`, `== "8BITMIME"`,
… `:787`, `:833`ff). RFC 5321 §2.4 makes them case-insensitive; a server
advertising `starttls` gets "TLS is not supported". Test:
`SubmissionClientTests.Ehlo_keywords_are_case_insensitive`.

Fixed: each EHLO line is compared with its keyword in upper case and its
parameters as sent. The same gap made `8bitmime` and `size 100` invisible.

### C-4
**Closed** in [Vanaheimr/Hermod#103](https://github.com/Vanaheimr/Hermod/pull/103) (`e937ebd8`).
**8-bit content to a server without 8BITMIME.** RFC 5321 §2.4: *"An SMTP client
that has not successfully negotiated an appropriate extension ... MUST NOT
transmit messages with information in the high-order bit of octets."* A
`text/plain; charset=utf-8` body goes out as raw UTF-8 regardless. Also seen
against `smtp-sink -8`. Tests: `SubmissionClientTests.No_8bit_data_without_8bitmime`,
`SmtpSinkTests.No_8bit_octets_without_8bitmime`.

Fixed by the second of RFC 6152 §3's two options: Hermod has no 7-bit
conversion, so such a message ends before MAIL with
`MailSentStatus.EightBitNotSupported`. Converting unsigned messages to
quoted-printable would be the friendlier answer and is still open.

### C-5
**Closed** in [Vanaheimr/Hermod#120](https://github.com/Vanaheimr/Hermod/pull/120) (`1c056b32`).
**A bare LF in the body was sent as a bare LF** (`SendDataAsync`, `:424`, writes
each serialized line verbatim). RFC 5321 §2.3.8. Against a server with S-1's
behaviour this is exactly a smuggling primitive. Test:
`SubmissionClientTests.A_bare_LF_in_the_body_is_not_sent_bare`.

Fixed: every CR LF, bare CR and bare LF inside a serialized line ends it, before
the 8-bit check, the SIZE computation and dot-stuffing - so `\n.\n` in a body
goes out as a `..` line, and the message stays one message.

### C-6
**Closed** in [Vanaheimr/Hermod#119](https://github.com/Vanaheimr/Hermod/pull/119) (`a6ee2431`).
**The default EHLO argument was `Dns.GetHostName()`** (`:173`) — `octal` on the
test machine. RFC 5321 §4.1.4: a primary host name (FQDN) or an address literal.
Test: `SubmissionClientTests.Default_ehlo_argument_is_a_domain_or_address_literal`.

Fixed as `LocalDomain`'s documentation had promised: unset, it is the address the
connection leaves from, as an address literal (`[192.0.2.1]`, `[IPv6:…]`).
`LocalDomain` is `null` when unset now, instead of holding the host name.

### C-7
**Closed** in [Vanaheimr/Hermod#120](https://github.com/Vanaheimr/Hermod/pull/120) (`1c056b32`).
**The declared `SIZE=` was two octets short** (`:996`, `String.Join("\r\n", lines)`
omits the final CRLF). RFC 1870 §5 counts all CRLFs. Harmless except at the exact
limit. Test: `SubmissionClientTests.Declared_size_covers_the_message`.

Fixed: each line's UTF-8 octets and its CR LF; the client's own check against the
server's limit now holds to the octet.

### C-8
**Closed** in [Vanaheimr/Hermod#126](https://github.com/Vanaheimr/Hermod/pull/126) (`0297524c`).
**A failed attempt ended without QUIT.** RFC 5321 §4.1.1.10: *"The sender MUST NOT
intentionally close the transmission channel until it sends a QUIT command, and it
SHOULD wait until it receives the reply"*. A refused RCPT throws out of the send loop
(`SMTPSubmissionClient.cs:1275`ff), as do a refused MAIL, DATA or message; STARTTLS
refused, a message above the SIZE limit and 8-bit content without 8BITMIME `break`
out of it. None of them sends QUIT, and the connection stays open until the next
`Send` or `Dispose()` - the server holds a session slot for a client that has
left. Tests: `SubmissionClientTests.A_failed_attempt_ends_with_QUIT`, seven cases.

Fixed: every attempt ends with QUIT where the session can still carry one, then the
connection is closed. A delivered message stays `ok` whatever the reply to QUIT
(RFC 5321 §6.1); before, an odd one turned it into an exception.

### C-9
**Closed** in [Vanaheimr/Hermod#127](https://github.com/Vanaheimr/Hermod/pull/127) (`d2d608d2`).
**Replies were decoded one TCP read at a time** (`ReadSMTPResponsesAsync`, `:386`):
each read is turned into a string on its own, so a UTF-8 character split across two
segments becomes two U+FFFD; and whatever followed the reply in the same read is
dropped (`dataAfterLastReply`). Harmless while replies are ASCII and the client
waits for each - but servers do put UTF-8 in reply text, and PIPELINING (C-10)
needs the bytes behind a reply. Test:
`SubmissionClientTests.A_reply_split_inside_a_UTF8_character_is_read_whole`.

Fixed: octets are collected in a buffer that lives with the connection; a reply is
decoded once it is complete, and what follows it is kept for the next one.

### C-10
**Closed** in [Vanaheimr/Hermod#127](https://github.com/Vanaheimr/Hermod/pull/127) (`d2d608d2`).
**PIPELINING and CHUNKING were never used**, even when offered. Not a conformance
issue - both are MAY - but every RCPT costs a round trip of its own, and DATA one
more for the 354. Tests: `SubmissionClientTests.With_PIPELINING_MAIL_and_RCPT_go_out_together`,
`With_CHUNKING_the_message_goes_as_BDAT`.

Fixed: MAIL and all RCPTs as one pipelined group (DATA stays out of it - the client
still sends only when every recipient was accepted), the message as one
`BDAT <size> LAST`. `BODY=BINARYMIME`, sent with DATA before against RFC 3030 §3,
now goes only with BDAT.

---

## Observations without a test yet

None left. Of those the first round noted:

- **`VerifySpf` / `VerifyDkim` / `VerifyDmarc` had no effect** - fixed in Hermod
  `0eb11d09` ("The verification switches and session limits are applied"), outside
  this suite's PRs.
- **Unbounded line reads** - fixed with S-1 ([Vanaheimr/Hermod#95](https://github.com/Vanaheimr/Hermod/pull/95)):
  `SMTPLineReader` enforces the limit while reading, so a peer that never sends CR LF
  cannot grow the buffer past it.
- The others became S-18, S-19, C-8, C-9 and C-10 above, all closed.
