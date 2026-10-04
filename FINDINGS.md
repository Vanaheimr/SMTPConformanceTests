# Findings

Every finding below is pinned by at least one test that asserts what the RFC
says. Those tests carry `[Category("KnownIssue")]` and a `Finding` property with
the ID, so the merge gate stays green while they stay red. When a fix lands,
the test turns green, the nightly reports it as "now passing", and the tag
comes off — the `Finding` property stays, so the test still says which finding
it guards.

First measured against **Hermod `8af03484`** (Styx `fc2aeddb`), 2026-10-03; line
numbers refer to that revision, under `libs/Hermod/Hermod/SMTP/`. Pinned to
**Hermod `04dca36d`** (Styx `c530de16`), which closes every one of them but N-5. The second round (S-18 and on, C-8 and on) comes from the
observations the first one left without a test; its line numbers refer to
`96a8048d`. The third (O-1 and on, C-11) tests `SMTPOutboundClient`, the relay side,
which the first two did not test at all; its line numbers refer to `d2d608d2`. The
fourth (D-, M- and N-) tests what the relay owes beyond delivery: the reports to
the sender (DSN), MTA-STS and DANE; its line numbers refer to `306f2d59`.

```powershell
dotnet test SMTPConformanceTests.slnx --filter "TestCategory=KnownIssue"
```

### Open

| ID | Severity | Area | Summary | Tests | Fix proposed in |
|---|---|---|---|---|---|
| [N-5](#n-5) | medium | DANE | DANE-TA depended on the platform downloading issuers: with an unreachable AIA URL, ~15 s of waiting and a failure | 1 | [Vanaheimr/Hermod#149](https://github.com/Vanaheimr/Hermod/pull/149) |

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
| [O-1](#o-1) | **high** | outbound | Every reply but EHLO's was read as one line: a multi-line reply shifted all that followed | 5 | [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) |
| [O-2](#o-2) | **high** | outbound | A recipient the next hop refused disappeared: no bounce, no retry | 2 | [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) |
| [O-3](#o-3) | medium | outbound | No SMTPUTF8, no BODY=8BITMIME, no check that the next hop could take the message | 6 | [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) |
| [O-4](#o-4) | medium | outbound | REQUIRETLS was not passed on to the next hop | 2 | [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) |
| [O-5](#o-5) | medium | outbound | `ReadTimeoutMs` had no effect: a silent server held the delivery forever | 1 | [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) |
| [O-6](#o-6) | low | outbound | A failed delivery ended without QUIT | 3 | [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) |
| [O-7](#o-7) | low | outbound | EHLO keywords matched as substrings: "DSN" in the server's name was a DSN extension | 1 | [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) |
| [O-8](#o-8) | low | outbound | HELO after any EHLO refusal, a 421 included | 1 | [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) |
| [C-11](#c-11) | low | client | One refused recipient stopped the message for all | 1 | [Vanaheimr/Hermod#131](https://github.com/Vanaheimr/Hermod/pull/131) |
| [D-1](#d-1) | **high** | reports | Bounces had CR CR LF line ends | 1 | [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) |
| [D-4](#d-4) | **high** | reports | A message that mentions "multipart/report" or quotes a bounce failed without a bounce | 3 | [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) |
| [D-2](#d-2) | medium | reports | Every bounce had the same Message-ID, `System.Func`1[System.Guid]`, and an invalid boundary | 1 | [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) |
| [D-3](#d-3) | medium | reports | NOTIFY=NEVER, SUCCESS or DELAY still got a bounce | 6 | [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) |
| [D-5](#d-5) | medium | reports | A message given up on was reported as "delayed ... will be retried" | 1 | [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) |
| [D-6](#d-6) | medium | reports | Status guessed by substring, Diagnostic-Code not the reply | 4 | [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) |
| [D-12](#d-12) | medium | reports | The relay added RET=FULL and NOTIFY=FAILURE the client had not given | 2 | [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) |
| [D-7](#d-7) | low | reports | Original-Recipient was the Final-Recipient; ORCPT was ignored | 2 | [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) |
| [D-8](#d-8) | low | reports | No Original-Envelope-Id in bounces; ENVID not xtext-decoded | 1 | [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) |
| [D-9](#d-9) | low | reports | RET=HDRS was ignored | 1 | [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) |
| [D-10](#d-10) | low | reports | Delay notices: not DSNs, NOTIFY ignored, held back 4 h whatever the setting | 2 | [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) |
| [D-11](#d-11) | low | reports | A "relayed" DSN for every recipient once one asked for SUCCESS | 1 | [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) |
| [M-1](#m-1) | **high** | MTA-STS | `*.example.com` matched `example.com` and `foo.bar.example.com` | 7 | [Vanaheimr/Hermod#135](https://github.com/Vanaheimr/Hermod/pull/135) |
| [M-2](#m-2) | medium | MTA-STS | Any TXT record containing "v=STSv1" announced a policy | 7 | [Vanaheimr/Hermod#135](https://github.com/Vanaheimr/Hermod/pull/135) |
| [M-3](#m-3) | medium | MTA-STS | A policy needed only a mode; enforce without mx allowed every MX | 8 | [Vanaheimr/Hermod#135](https://github.com/Vanaheimr/Hermod/pull/135) |
| [M-4](#m-4) | medium | MTA-STS | Policy redirects were followed | 2 | [Vanaheimr/Hermod#135](https://github.com/Vanaheimr/Hermod/pull/135) |
| [M-5](#m-5) | medium | MTA-STS | A new policy went unseen until max_age; no matching MX failed for good at once | 3 | [Vanaheimr/Hermod#135](https://github.com/Vanaheimr/Hermod/pull/135) |
| [M-6](#m-6) | low | MTA-STS | Through a smart host, the recipient domain's policy was applied to it | 1 | [Vanaheimr/Hermod#135](https://github.com/Vanaheimr/Hermod/pull/135) |
| [N-3](#n-3) | **high** | DANE | DANE-TA accepted any certificate of the trust anchor, whatever its name | 3 | [Vanaheimr/Hermod#136](https://github.com/Vanaheimr/Hermod/pull/136) |
| [N-4](#n-4) | medium | DANE | Secure but unusable TLSA records made delivery impossible | 2 | [Vanaheimr/Hermod#136](https://github.com/Vanaheimr/Hermod/pull/136) |
| [N-1](#n-1) | **high** | DANE | A failed TLSA lookup was taken as "no TLSA records" | 4 | [Vanaheimr/Hermod#144](https://github.com/Vanaheimr/Hermod/pull/144) |
| [N-2](#n-2) | **high** | DANE | An empty TLSA answer in a signed zone was believed without a proof | 3 | [Vanaheimr/Hermod#144](https://github.com/Vanaheimr/Hermod/pull/144) |

The 152 tests for these are part of the merge gate now; the observations the first
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
`MailSentStatus.EightBitNotSupported`. Converting to quoted-printable instead
was considered and decided against: it would break DKIM and OpenPGP signatures
over the content, and those matter more than reaching the rare server without
8BITMIME. The same holds for the outbound client (O-3).

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

### C-11
**Closed** in [Vanaheimr/Hermod#131](https://github.com/Vanaheimr/Hermod/pull/131) (`306f2d59`).
**One refused recipient stopped the message for all** (`SMTPSubmissionClient.cs`, the
RCPT loop): a 550 for one recipient throws, and the others, already accepted, never
get the message. RFC 5321 §3.3 has the server accept or refuse recipients one by
one, and the usual client behaviour (Postfix, Exim) is to deliver to those accepted
and report the rest. A decision more than a violation; decided for partial delivery,
with each recipient's result in `SMTPSendResult.Recipients`. Test:
`SubmissionClientTests.A_refused_recipient_does_not_stop_the_message_for_the_others`.

Fixed: the message goes to every accepted recipient; `MailSentStatus.PartiallySent`
when some were refused, `IsSuccess` for `ok` alone.

---

## Outbound client (`SMTPOutboundClient`)

Tested through the public way in - `MailSender.SendDirectAsync`, and for O-2 the
`QueueProcessor` with its `BounceHandler` - against a scripted server set as smart
host (`OutboundClientTests`), and against Postfix (`PostfixTests`).

### O-1
**Closed** in [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) (`d581a8d9`).
**Every reply but EHLO's was read as one line** (`ReadResponseAsync`, `:569`, one
`ReadLineAsync`). RFC 5321 §4.2.1 allows any reply to have several lines, and large
providers send their refusals that way ("550-5.1.1 The email account that you tried
to reach does not exist. ... 550 5.1.1 ..."). The client takes the first line as the
reply and the second as the reply to its next command: a multi-line greeting makes
EHLO look refused, a multi-line RCPT refusal answers the next RCPT. Tests:
`OutboundClientTests.A_multi_line_reply_is_read_whole` (greeting, MAIL, RCPT, DATA)
and `A_multi_line_refusal_does_not_shift_the_replies`; a multi-line end-of-data
reply goes unnoticed (QUIT is next) and is a guard.

Fixed: `SMTPConnection` reads every reply to its final line and keeps all lines;
the text of a multi-line refusal stays whole in `SendResult.ResponseText`.

### O-2
**Closed** in [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) (`d581a8d9`).
**A recipient the next hop refused disappeared** (`TrySendToMxAsync`, `:410`ff, and
`QueueProcessor.HandleDeliveryResultAsync`). A refused RCPT is logged and skipped;
if any recipient was accepted the delivery is a `Success`, and the queue marks the
message delivered. The refused recipient gets no bounce, a 4xx-refused one is never
tried again. RFC 5321 §6.1: a relay that accepted a message "MUST NOT lose the
message", and must report a failure to the sender. Tests:
`OutboundClientTests.A_recipient_refused_by_the_next_hop_is_bounced`,
`A_recipient_refused_for_now_is_retried`.

Fixed: `SendResult.Recipients` carries every RCPT reply; on a mixed outcome the
queue delivers for those accepted, bounces each refused recipient on its own, and
queues those refused for now as a copy for them alone.

### O-3
**Closed** in [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) (`d581a8d9`).
**No SMTPUTF8, no BODY=8BITMIME** on MAIL (`:400`ff build only DSN and MT-PRIORITY
parameters). A message with a non-ASCII address goes out without SMTPUTF8 - a strict
next hop (Hermod itself since S-12, behind Postfix) refuses it with 553 5.6.7 - and
8-bit content goes out undeclared, also to a server without 8BITMIME (RFC 6152 §3,
RFC 6531 §3.2: the message must not be handed to a server that cannot take it).
Tests: four in `OutboundClientTests`, two in `PostfixTests`.

Fixed: SMTPUTF8 and BODY=8BITMIME are declared; a next hop without what the message
needs gets nothing - 553 5.6.7 or 554 5.6.3. No 7-bit conversion, as for C-4.

### O-4
**Closed** in [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) (`d581a8d9`).
**REQUIRETLS was not passed on.** S-14 made the queue carry it and the client insist
on TLS, but MAIL goes out without the REQUIRETLS parameter, and the next hop is not
asked whether it supports it (RFC 8689 §4.2.1: without it the message is not to be
sent on). Its test needed TLS to the scripted server, which the client validated strictly
once TLS was required - against the system's trust store.

Fixed: REQUIRETLS on MAIL, and 550 5.7.30 for a next hop without it.
`SmtpOutboundConfig.RemoteCertificateValidator` decides on a certificate where the
operator's trust is not the system's; the tests use it for their self-signed one.
Tests: `A_REQUIRETLS_message_goes_over_TLS_with_REQUIRETLS`,
`A_REQUIRETLS_message_is_not_sent_to_a_next_hop_without_REQUIRETLS`.

### O-5
**Closed** in [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) (`d581a8d9`).
**`ReadTimeoutMs` had no effect** (`:258`ff: it is set as the socket's
`ReceiveTimeout`, which asynchronous reads ignore). A next hop that accepts the
connection and then says nothing holds the delivery - and a queue worker - until the
caller's token fires; for the queue that is never. RFC 5321 §4.5.3.2 gives a client
its timeouts. Test: `A_silent_server_is_given_up_on_after_the_read_timeout`.

Fixed: every read and write is bounded by its timeout - a `TimeoutException`, a
temporary failure.

### O-6
**Closed** in [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) (`d581a8d9`).
**A failed delivery ended without QUIT** - as C-8 was for the submission client: only
the success path says it. Tests: three cases of `A_failed_relay_ends_with_QUIT`.

Fixed: QUIT in the session's `finally`, whenever the session can still carry it.

### O-7
**Closed** in [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) (`d581a8d9`).
**EHLO keywords were matched as substrings** (`:315`, `:397`f: `Contains("STARTTLS")`,
`Contains("DSN")`, `Contains("MT-PRIORITY")`, and `AUTH`/`PLAIN` likewise): a server
named `dsn.example` "offers" DSN and gets RET/ENVID/NOTIFY it never advertised (a
strict server answers 555). Test: `A_server_named_dsn_does_not_get_DSN_parameters`.

Fixed: `Extensions` reads the EHLO reply keyword by keyword, case-insensitively.

### O-8
**Closed** in [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) (`d581a8d9`).
**HELO after any EHLO refusal** (`:302`): also after 421, which ends the session.
RFC 5321 §3.2 has HELO as the fallback for a server that does not know EHLO.
Test: `A_421_to_EHLO_is_not_answered_with_HELO`.

Fixed: HELO after 500, 501, 502, 504 and 550 only.

---

## DSN reports

What a relay owes the sender when it cannot deliver a message, keeps trying, or hands
it to a next hop that will not report delivery (RFC 3461 §5.2, §6), in the format of
RFC 3464 and RFC 6522. `BounceHandler` and `DsnGenerator`; the tests,
`OutboundClientTests.Dsn.cs`, send a message to a Hermod server with the DSN
parameters a client would give, let the QueueProcessor relay it to a scripted next
hop, and read the reports from the queue.

### D-1
**Closed** in [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) (`a4eeab14`).
**Bounces had CR CR LF line ends** (`BounceHandler.GenerateBounceMessage`). The bounce
is built with `AppendLine` and then `Replace("\n", "\r\n")`: every CR LF of the
returned message - and on Windows every line of the bounce - becomes CR CR LF.
RFC 5322 §2.3: lines end in CR LF, CR and LF appear only together. Test:
`A_bounce_has_CR_LF_line_ends_only`.

Fixed: every report is built with CR LF from the start; the returned message's line ends are
made CR LF without touching any other character.

### D-2
**Closed** in [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) (`a4eeab14`).
**Every bounce had the same Message-ID, and an invalid boundary.** The interpolation
`{UUIDv7.Generate:N}` lacks the call parentheses: it formats the method group, and
every bounce carries `Message-ID: <bounce.System.Func`1[System.Guid]@...>` - against
RFC 5322 §3.6.4, which makes it unique - and the boundary
`=_bounce_System.Func`1[System.Guid]`, whose "`", "[" and "]" are not bchars (RFC 2046
§5.1.1). Test: `Two_bounces_have_two_valid_Message_IDs_and_valid_boundaries`.

Fixed: a Message-ID and a boundary of their own for every report.

### D-3
**Closed** in [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) (`a4eeab14`).
**NOTIFY did not decide whether a failure is reported.** `SendBounceAsync` never looks
at it. RFC 3461 §5.2.6 (b): "If a NOTIFY parameter was supplied for the recipient
which did not contain the value FAILURE, a DSN MUST NOT be issued for that
recipient." Tests: `A_failure_is_not_reported_when_NOTIFY_leaves_out_FAILURE` (NEVER,
SUCCESS, DELAY), and three guards with FAILURE or no NOTIFY.

Fixed: each recipient's own NOTIFY decides (`RecipientDsn.ReportsFailure`, `ReportsSuccess`,
`ReportsDelay`).

### D-4
**Closed** in [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) (`a4eeab14`).
**A message could talk itself out of its bounce** (`IsBouncedMessage`). Any message
whose content contains "multipart/report", "message/delivery-status", "Auto-Submitted:
auto-replied" or "From: MAILER-DAEMON" - in the body too - is taken for a bounce and
fails without a word: a mail about DSNs, one quoting a vacation reply or a bounce.
RFC 3461 §5.2.6 (c): without NOTIFY "a 'failed' DSN MUST be issued", and RFC 5321 §6.1
has the relay report what it cannot deliver. Reports cannot loop anyway: they go out
with a null reverse-path, and a message with one gets no report (RFC 3461 §6). Tests:
`A_failure_is_reported_whatever_the_message_says`, three bodies.

Fixed: only a null reverse-path stops a report; `IsBouncedMessage` is gone.

### D-5
**Closed** in [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) (`a4eeab14`).
**A message given up on was reported as delayed.** When the retries run out after
4xx answers, the bounce is a "soft" one: "Action: delayed", "Delivery will be
retried". It will not be. RFC 3461 §5.2.6: such a DSN's Action "MUST be 'failed'".
Test: `A_message_given_up_on_is_reported_as_failed`.

Fixed: a bounce is "Action: failed", whatever the last answer was.

### D-6
**Closed** in [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) (`a4eeab14`).
**The Status was guessed, the Diagnostic-Code was not the reply** (`GetStatusCode`).
Any reply containing "550" becomes 5.1.1, "554" 5.7.1, and so on - "550 5.7.1 Relaying
denied" is reported as a bad mailbox. The Diagnostic-Code is the client's summary,
"550 No recipient accepted: 5.1.1 ...", or a reply with its code twice. RFC 3461 §6.3
(g) wants the status code, (i) the next hop's reply. Tests:
`A_bounce_carries_the_status_and_reply_of_the_next_hop`, four replies.

Fixed: the Status is the enhanced status code of the next hop's reply to that recipient, when
it is of the reply's class, else X.0.0; the Diagnostic-Code is that reply as it was.

### D-7
**Closed** in [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) (`a4eeab14`).
**Original-Recipient was the Final-Recipient again, and ORCPT was ignored.** RFC 3461
§6.3 (d): "If the ORCPT parameter was provided for this recipient, the
Original-Recipient field MUST be supplied, with its value taken from the ORCPT
parameter. If no ORCPT parameter was provided for this recipient, the
Original-Recipient field MUST NOT appear." Tests:
`Original_Recipient_is_the_ORCPT_parameter`, `Without_ORCPT_there_is_no_Original_Recipient`.

Fixed: Original-Recipient from ORCPT, xtext decoded, and only from ORCPT.

### D-8
**Closed** in [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) (`a4eeab14`).
**No Original-Envelope-Id in bounces.** RFC 3461 §6.3 (a): with ENVID on the MAIL
command "an Original-Envelope-ID field MUST be supplied", its xtext decoded; the
success DSN had it, undecoded. Test: `A_bounce_carries_the_ENVID`.

Fixed: Original-Envelope-Id from ENVID, xtext decoded (`DsnParser.DecodeXtext`), in every report.

### D-9
**Closed** in [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) (`a4eeab14`).
**RET=HDRS was ignored**: the bounce returns the header and up to a hundred body lines
as a truncated message/rfc822. RFC 3461 §4.3: "HDRS requests that only the headers of
the message be returned." Test: `With_RET_HDRS_the_bounce_returns_the_header_only`.

Fixed: a failure returns the whole message unless RET=HDRS asked otherwise or it is above 1 MiB;
a report without a failure returns the header, as text/rfc822-headers.

### D-10
**Closed** in [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) (`a4eeab14`).
**Delay notices** (`SendDelayNotificationAsync`) are plain text, not DSNs (RFC 3461 §6.2:
"A DSN is transmitted as a MIME message with a top-level content-type of
multipart/report"); they ignore NOTIFY - §5.2.5 (c): "If the NOTIFY parameter was
supplied which did not contain the DELAY keyword, a 'delayed' DSN MUST NOT be issued"
- and wait four hours whatever `QueueProcessorConfig.DelayNotificationAfter` says.
Tests: `A_delay_is_reported_as_a_delayed_DSN_when_asked_for`, and the guard
`A_delay_is_not_reported_when_NOTIFY_leaves_out_DELAY`.

Fixed: delay notices are DSNs with "Action: delayed" and Will-Retry-Until, for the recipients
whose NOTIFY includes DELAY or who gave none, when `DelayNotificationAfter` says it is time.

### D-11
**Closed** in [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) (`a4eeab14`).
**A "relayed" DSN for every recipient** once one of them asked for SUCCESS: the queue
ORs the recipients' NOTIFY together, and `SendRelayNotificationAsync` reports on all.
RFC 3461 §5.2.2 (b), (e): a "relayed" DSN for the recipient that asked, none for one
that did not. Test: `Only_the_recipient_that_asked_gets_a_relayed_DSN`.

Fixed: a "relayed" DSN for the recipients that asked for SUCCESS, and only for them.

### D-12
**Closed** in [Vanaheimr/Hermod#134](https://github.com/Vanaheimr/Hermod/pull/134) (`a4eeab14`).
**The relay made up DSN parameters.** A message received without RET goes on with
"RET=FULL", a recipient without NOTIFY with "NOTIFY=FAILURE" - `DsnParser` fills in
defaults, and they are relayed as if given. RFC 3461 §5.2.1 (b): "If no RET parameter
was present in the MAIL command when the message was received, the RET parameter
MUST NOT be supplied when the message is relayed", and (c) the same for NOTIFY.
Tests: `A_relay_adds_no_RET_the_client_did_not_give`,
`A_relay_adds_no_NOTIFY_the_client_did_not_give`.

Fixed: NOTIFY and RET are nullable through the queue (`RecipientDsn.Notify`, `QueuedMail.Ret`,
`DsnParameters.Ret`) - null for "not given" - and only what was given is passed on.

---

## MTA-STS

RFC 8461, as `MtaStsResolver` and `SMTPOutboundClient` apply it. Before the fix only M-1
could be tested from outside: the resolver fetched policies with an `HttpClient` of its
own, through the system resolver and trust store. The fix added
`SmtpOutboundConfig.MtaStsHttpHandler`; `MtaStsTests` and `OutboundClientTests.Policies.cs`
serve policies through it (`MtaStsPolicyHost`), with the stub DNS for the TXT and MX
records.

### M-1
**Closed** in [Vanaheimr/Hermod#135](https://github.com/Vanaheimr/Hermod/pull/135) (`8975ddc2`).
**`*` matched any number of labels, and none** (`MtaStsPolicy.MatchesMx`):
"*.example.com" allows "example.com" and "foo.bar.example.com". RFC 8461 §4.1: "the
wildcard character '*' may only be used to match the entire left-most label in the
presented identifier. Thus, the mx pattern '*.example.com' matches 'mail.example.com'
but not 'example.com' or 'foo.bar.example.com'." Under enforce, mail can go to hosts
the domain never named. Tests: `MtaStsTests.An_mx_pattern_matches_as_RFC_8461_says`,
seven patterns.

Fixed: "*." stands for exactly the left-most label; case and a trailing dot do not matter.

### M-2
**Closed** in [Vanaheimr/Hermod#135](https://github.com/Vanaheimr/Hermod/pull/135) (`8975ddc2`).
**Any TXT record containing "v=STSv1" announced a policy** (`LookupMtaStsTxtAsync`):
"id=1; v=STSv1", "v=STSv10; ...", one of two records, one without an id. RFC 8461
§3.1: "records that do not begin with 'v=STSv1;' are discarded. If the number of
resulting records is not one, or if the resulting record is syntactically invalid,
senders MUST assume the recipient domain does not have an available MTA-STS Policy."

Fixed: exactly one record, beginning with "v=STSv1", an id of 1 to 32 letters and digits, every
other field a well-formed extension. Tests: `MtaStsTests.Only_one_valid_TXT_record_announces_a_policy`,
seven records.

### M-3
**Closed** in [Vanaheimr/Hermod#135](https://github.com/Vanaheimr/Hermod/pull/135) (`8975ddc2`).
**A policy needed nothing but a mode** (`ParsePolicy`): no version, no max_age (a day
is assumed), an enforce policy without a single mx - which then allows every MX -
and a repeated field counts the last time. RFC 8461 §3.2: version, mode and max_age
"required once", mx "required at least once, except when mode is 'none'"; of a
repeated field "all entries except for the first SHALL be ignored". And "senders
SHOULD validate that the media type is 'text/plain'", which nothing does.

Fixed: a policy that is not one is no policy; max_age is capped at 31557600 seconds; only
text/plain is taken. Tests: `Only_a_valid_policy_counts` (six policies),
`A_policy_that_is_not_text_plain_does_not_count`, `A_max_age_above_a_year_is_a_year`.

### M-4
**Closed** in [Vanaheimr/Hermod#135](https://github.com/Vanaheimr/Hermod/pull/135) (`8975ddc2`).
**Redirects were followed**: the resolver's `HttpClient` has the default handler. RFC
8461 §3.3: "HTTP 3xx redirects MUST NOT be followed".

Fixed: the resolver's own handler follows no redirects, only a 200 counts, and a policy that a
handler of the operator's (`SmtpOutboundConfig.MtaStsHttpHandler`) reached through a redirect is
not taken. Tests: `A_redirect_is_not_a_policy` (a guard), `A_policy_reached_through_a_redirect_is_not_taken`.

### M-5
**Closed** in [Vanaheimr/Hermod#135](https://github.com/Vanaheimr/Hermod/pull/135) (`8975ddc2`).
**A new policy went unseen, and no matching MX failed for good.** A cached policy is
used until its max_age without a look at the TXT record, so a domain's new policy
stays unknown for weeks; and when no MX matches an enforce policy, the delivery is a
permanent "550 MTA-STS policy violation" and a bounce at once. RFC 8461 §5: "a
compliant MTA MUST NOT permanently fail to deliver messages before checking, via DNS,
for the presence of an updated policy ... MTAs SHOULD treat such failures as
transient errors".

Fixed: the TXT record is looked at on every attempt - a new id fetches the new policy, the cached
one applies when no live one can be had - and no allowed MX is `451 4.7.5`, tried again. Tests:
`A_new_policy_id_fetches_the_new_policy`, `The_cached_policy_applies_when_no_live_one_can_be_had`
(a guard), `OutboundClientTests.No_MX_the_MTA_STS_policy_allows_is_a_temporary_failure`.

### M-6
**Closed** in [Vanaheimr/Hermod#135](https://github.com/Vanaheimr/Hermod/pull/135) (`8975ddc2`).
**Through a smart host, the recipient domain's policy was applied to the smart
host**: its enforce mode demands TLS with a valid certificate of the relay, which the
policy does not name. RFC 8461 §3.4: "compliant senders MUST treat the smart host
domain as the Policy Domain".

Fixed: the smart host's own policy applies, its mx patterns included; an address literal has
none. Test: `OutboundClientTests.Through_a_smart_host_the_recipient_domains_policy_does_not_apply`.

---

## DANE

RFC 7672 on the relay (`DaneResolver`, `DaneAuthenticator`, `SMTPOutboundClient`).
`DaneResolverTests` signs a zone for the test and gives the resolver its trust anchor;
for N-3 and N-4 the outbound client trusts such a zone through
`SmtpOutboundConfig.DnssecTrustAnchors`, which the fix added, and delivers to a smart
host "localhost" whose certificate - and chain - the scripted server presents
(`OutboundClientTests.Policies.cs`).

### N-1
**Closed** in [Vanaheimr/Hermod#144](https://github.com/Vanaheimr/Hermod/pull/144) (`d0ddcc3f`), after the DNS fixes
[#139](https://github.com/Vanaheimr/Hermod/pull/139) to [#141](https://github.com/Vanaheimr/Hermod/pull/141).
**A failed TLSA lookup was taken as "no TLSA records"** (`ResolveTlsaAsync`): an
exception becomes `DaneResult.None`, a SERVFAIL an empty answer, and the message goes
out with opportunistic TLS. RFC 7672 §2.1.2: "If any DNS queries used to locate TLSA
records fail ... the SMTP client MUST treat that server as unreachable and MUST NOT
deliver the message via that server." Tests:
`A_failed_TLSA_lookup_defers_delivery` (SERVFAIL, timeout), and the guard
`A_signed_TLSA_record_is_secure`.

Not fixed at first, and for a reason. Deferring on every failed lookup is safe only with
the check of §2.2.2 before it - TLSA is asked only for hosts whose address records
are signed, because nameservers of some large unsigned providers answer TLSA queries
with SERVFAIL - and that check, like N-2, needs a DNS stack whose answers can be
trusted. Tried against the real DNS with the root anchor (2026-10-04, 1.1.1.1),
Hermod's is not there yet:

- with the query cache on (the default), an answer from the cache has lost its
  RRSIGs: `_25._tcp.mail.sys4.de` validates "secure" when asked first, "insecure"
  after another query in the zone - DANE silently stops after the first message;
- the validator judges signed .org zones "bogus" - `isc.org`, `www.ietf.org` - which
  the resolver answers with AD;
- Cloudflare's compact NODATA (`mail.ietf.org A`, an NSEC-signed "no such type")
  comes back as SERVFAIL.

A resolver that defers on those would hold mail for every Cloudflare-hosted signed
zone and every .org host. They belonged to the DNS side
([DNSConformanceTests](https://github.com/Vanaheimr/DNSConformanceTests)) first, and are
fixed there: [Vanaheimr/Hermod#139](https://github.com/Vanaheimr/Hermod/pull/139) (the
cache keeps signatures), [#140](https://github.com/Vanaheimr/Hermod/pull/140) (a zone
with two key-signing keys), [#141](https://github.com/Vanaheimr/Hermod/pull/141)
(compact denial). The same probe against `8dc9663a` finds every zone above "secure",
and the denials of `mail.ietf.org A` and `_25._tcp.www.isc.org TLSA` validated.

Fixed in [Vanaheimr/Hermod#144](https://github.com/Vanaheimr/Hermod/pull/144):
the address records first (§2.2.2) - insecure ones mean no TLSA lookup and no DANE -
and for a host whose address records are secure, every failed TLSA lookup and every
empty answer without a valid denial defers delivery. More tests for it: the guard
`An_unsigned_host_is_not_asked_for_TLSA_records` (an unsigned host whose TLSA lookup
fails is not held), and for N-2 `A_proven_absence_of_TLSA_records_is_no_DANE` (a signed
zone's NXDOMAIN with its NSEC proof is no DANE).

### N-2
**Closed** in [Vanaheimr/Hermod#144](https://github.com/Vanaheimr/Hermod/pull/144) (`d0ddcc3f`), with N-1.
**An empty TLSA answer in a signed zone was believed without a proof.** RFC 7672
§2.1.1 and RFC 4035 §5.4: in a signed zone, "no TLSA records" is a fact only with a
validated denial of existence; an empty answer without one is what an attacker who
strips the records produces, and DANE turns into opportunistic TLS. Tests:
`An_empty_answer_without_proof_in_a_signed_zone_defers_delivery`, and the guard
`No_TLSA_records_outside_a_signed_zone_is_no_DANE`. Fixed with N-1: an empty answer
for a host in a signed zone is validated as a denial of existence, and is bogus without
a valid one.

### N-3
**Closed** in [Vanaheimr/Hermod#136](https://github.com/Vanaheimr/Hermod/pull/136) (`3edbccd5`).
**DANE-TA accepted any certificate of the trust anchor**
(`DaneAuthenticator.Matches`): it checks that the anchor is in the chain - or that the
record matches the server certificate itself - and not the name. RFC 7672 §3.2.2:
"With DANE-TA(2), the server certificate MUST contain a name that matches one of the
reference identifiers". With a public CA's intermediate as the anchor - "2 1 1" for
Let's Encrypt is common - any certificate of that CA passes as the destination's.

Fixed: a DANE-TA match counts when the anchor is in the presented chain and the certificate names
the TLSA base domain or, for an MX host, the next-hop domain. Tests (against a zone signed for the
test, trusted through `SmtpOutboundConfig.DnssecTrustAnchors`):
`OutboundClientTests.DANE_TA_refuses_a_certificate_for_another_name`, and the guards
`DANE_TA_accepts_a_certificate_for_the_host`, `DANE_EE_authenticates_the_next_hop`.

### N-4
**Closed** in [Vanaheimr/Hermod#136](https://github.com/Vanaheimr/Hermod/pull/136) (`3edbccd5`).
**Secure but unusable TLSA records made delivery impossible.** A secure RRset of only
PKIX-TA(0) or PKIX-EE(1) records - which SMTP does not use (§3.1.3) - counts as
"DANE active", no record can ever match, and every attempt ends in a TLS failure until
the message is given up. RFC 7672 §2.2: then "Any connection to the MTA MUST be made
via TLS, but authentication is not required."

Fixed: `DaneResult.RequiresTls` beside `IsUsable` - TLS for both, authentication only against
usable records. Tests: `Unusable_TLSA_records_need_TLS_but_no_authentication`, and the guard
`Unusable_TLSA_records_still_need_TLS`.

### N-5
**DANE-TA depended on the platform downloading issuers** (`SMTPOutboundClient`, the
`SslClientAuthenticationOptions` of STARTTLS). The guard
`DANE_TA_accepts_a_certificate_for_the_host` failed now and then on Windows, the first
run after a build: three seconds between connecting and the certificate check, and the
chain the validation callback got lacked the intermediate the server had sent - the
DANE-TA anchor. `SslStream` builds the server's chain with the default policy, which
fetches missing issuers from the certificates' AIA URLs; the test's anchor is an
intermediate whose root nobody has, so Windows went looking for it, and when that times
out the chain comes back without the certificates the server presented. Under DANE the
presented chain is all there is to authenticate against (RFC 7672 §3.1.2). In practice:
a private CA whose AIA URL does not answer from the MTA's network makes every DANE-TA
delivery wait some 15 seconds, and fail. Test:
`OutboundClientTests.DANE_TA_does_not_depend_on_certificate_downloads` - the anchor gets
an AIA URL in TEST-NET-1 (`http://192.0.2.1/`), which makes the failure certain:
17.5 s against the pin.

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
