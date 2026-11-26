# Findings

Every finding below is pinned by at least one test that asserts what the RFC
says. Those tests carry `[Category("KnownIssue")]` and a `Finding` property with
the ID, so the merge gate stays green while they stay red. When a fix lands,
the test turns green, the nightly reports it as "now passing", and the tag
comes off — the `Finding` property stays, so the test still says which finding
it guards.

First measured against **Hermod `8af03484`** (Styx `fc2aeddb`), 2026-10-03; line numbers
refer to that revision, under `libs/Hermod/Hermod/SMTP/`. Pinned to **Hermod `69096a60`**
(Styx `6dc4bb30`), which closes every finding of all twenty-seven rounds and of the follow-up
E-14 to E-16. The second round (S-18 and on, C-8 and on) comes from the observations the
first one left without a test; its line numbers refer to `96a8048d`. The third (O-1 and
on, C-11) tests `SMTPOutboundClient`, the relay side, which the first two did not test at
all; its line numbers refer to `d2d608d2`. The fourth (D-, M- and N-) tests what the
relay owes beyond delivery: the reports to the sender (DSN), MTA-STS and DANE; its line
numbers refer to `306f2d59`. The fifth (V- and P-) tests what Hermod's SMTP gained
between `bbbf88b6` and `4b8be28a` - SPF, DKIM and DMARC on inbound mail, DNS blocklists,
recipient checks, the AUTH configuration, submission to the application, outbound mail to
public addresses only, smart host credentials, DKIM signing, the file queue after a crash
and the certificate chain; its line numbers refer to `4b8be28a`. The sixth (A-, R-, T-,
Q-, L-, V-3 and V-4) tests the parts of Hermod's SMTP no round had tested: ARC (RFC
8617), the DMARC reports (RFC 7489 §7), TLS reporting (RFC 8460), MT-PRIORITY (RFC 6710)
and the connection and recipient limits; its line numbers refer to `287d1c43`, under
`libs/Hermod/Hermod/SMTP/`. The seventh (E-, I-, K- and G-) tests what of Hermod's mail
code no round had tested, none of it changed since: MIME and the message format as Hermod
builds and reads mail (RFC 2045 to 2047, 2231, 5322), the reports that arrive (DSN,
DMARC, TLS-RPT), message disposition notifications (RFC 8098), PGP/MIME (RFC 3156) and
the Public Suffix List under DMARC; its line numbers refer to `72c2366d`. E-14 to E-16
follow it up: what the older `EMail.Parse` makes of a Content-Type that is not written in
lower case, as the MIME reader would read it, seen while fixing the MDN findings; their
line numbers refer to `0504586f`. The eighth (V-5 and on, O-9 and on, P-2 and P-3) tests
what of SPF, DKIM and the way to the next hop the earlier rounds took for granted: how
check_host() comes to its result (RFC 7208 §4 to §6), what a DKIM verifier checks of a
signature and its key record before it hashes anything (RFC 6376 §6.1, RFC 8301), how the
relay finds its MX hosts (RFC 5321 §5.1), and the DKIM keys Hermod makes; its line
numbers refer to `887a8795`. The ninth (V-18 and on, S-20 and on, C-12 and C-13) tests
when a DMARC policy is applied at all (RFC 7489 §6.6.2, §6.6.3) and SASL in its details:
SCRAM-SHA-256 on both sides (RFC 5802, RFC 7677, RFC 4422 §3) and EXTERNAL (RFC 4422
Appendix A); its line numbers refer to `a687f198`. The tenth (S-28 and on, O-13 and O-14,
C-14, D-13) tests what RFC 5321 asks of a server beyond its commands, and of a client
beyond its dialogue: the trace fields and final delivery (§4.4), loop detection (§6.3),
the paths of MAIL and RCPT as the grammar of §4.1.2 has them - source routes, quoted
local parts -, HELP, EXPN and VRFY, the timeouts of the clients (§4.5.3.2), and SMTPUTF8
in ORCPT and in bounces (RFC 6533), and the ORCPT the relay writes (RFC 3461 §4.2); its
line numbers refer to `1e2e04d9`. The eleventh (O-15 and on, C-15 and on, S-35 and on,
V-23 and on) tests how the two clients read a reply code - by its first digit, as RFC
5321 §4.2.1 has it, and 552 to RCPT as §4.5.3.1.10 has it - and internationalized domain
names wherever Hermod meets one: in the DNS lookups of the relay, of SPF, DKIM and DMARC
(RFC 6531 §3.2, RFC 8616), in the local domains of the server, and in the names the
server and the clients give themselves (RFC 6531 §3.7.1); its line numbers refer to
`a9d149de`. The twelfth (S-37 and on, O-19 and O-20, C-17 and C-18) tests SMTP AUTH
beyond its dialogue (RFC 4954 §4 to §6): how long a SASL response may be (RFC 4616 §2),
the base64 it is written in, how an exchange ends, a user store that cannot be asked, the
AUTH parameter the relay owes a smart host it signed in to, and the initial response and
the challenges of the two clients; its line numbers refer to `21fe948d`. The thirteenth
(S-41 and S-42, O-21 and O-22) tests the edges of a session: what a server says when it
is stopped (RFC 5321 §3.8), a parameter that may be given once given twice (RFC 3461
§4.5, RFC 1870 §6), and a next hop that refuses the session - at the first of its MX
hosts, or at one of its addresses (RFC 5321 §3.1, §5.1, RFC 7504 §3); its line numbers
refer to `63e6df5c`. The fourteenth (O-23 and on, D-14 and D-15, C-19) tests REQUIRETLS
(RFC 8689) beyond the option itself: which MX hosts a message that requires TLS may go to,
what follows when one cannot take it, a bounce that carries the option and the bounce of a
message that does, the TLS-Required header field, and the option as the submission client
gives it; its line numbers refer to `efbaf986`. The fifteenth (S-43 to S-47) tests the
header fields the server writes into a message: Authentication-Results - what it keeps of
those the message brought along (RFC 8601 §5), and what it says SPF authenticated (§2.7.2)
- and the Received field of an SMTPUTF8 transaction (RFC 6531 §3.7.3); its line numbers
refer to `5fed035a`. The sixteenth (C-20 and C-21) tests SMTPUTF8 as the submission client
uses it: an internationalized message to a server without SMTPUTF8 (RFC 6531 §3.2, §3.5),
and the parameter with a message that does not need it (§3.4); its line numbers refer to
`44ad353b`. The seventeenth (C-22 to C-24) tests DSN as the two clients ask for it when an
application hands them a message - the submission client, and the relay by
`MailSender.SendDirectAsync`: ENVID as xtext (RFC 3461 §4, §4.4), RET and NOTIFY=NEVER as
the caller gave them (§4.1, §4.3); its line numbers refer to `98fa0297`. The eighteenth
(S-48 to S-50) tests the store a server keeps local mail in when it is given none of its
own, `FileMailStorage`: what it writes on top of a message (RFC 5322 §2.2, RFC 5321 §4.4),
and a valid message it cannot keep (RFC 5322 §3.6.4); its line numbers refer to `1544d14a`.
The nineteenth (R-8 to R-12, T-5 and T-6) tests where the two reporters send a report and
what the DMARC failure report says of the message: the mailto URIs of rua and ruf (RFC
7489 §6.2, §6.4, RFC 8460 §3, RFC 6068 §2), and the fields of the failure report that come
from DNS and from the session (RFC 6591 §4, RFC 5965 §3.5); its line numbers refer to
`a95ddebc`. The twentieth (E-17 to E-21) tests the parts an HTML mail refers to, and what a
part is for: the Content-ID, a msg-id that a cid: URL names (RFC 2045 §7, RFC 5322 §3.6.4,
RFC 2392), multipart/related and its type and start (RFC 2387), and Content-Disposition
(RFC 2183) - as `MimeAttachment` and `MimeMultipart` write them and `MimeMessage` reads
them; its line numbers refer to `67cf52e5`. The twenty-first (E-22 to E-25) tests what
an answer takes from the message it answers and the list it came through: the subject of a
reply (RFC 5322 §3.6.5), List-Post as `MailReplies` reads it and the older builder writes
it (RFC 2369 §2, §3.4), and the mailto URL in it (RFC 6068 §2); its line numbers refer to
`cb9c13c1`. The twenty-second (E-26 to E-29) tests what a part is when the reader does not
know its subtype, and the message a message carries: a text (RFC 2046 §4.1.4) and a message
(§5.2.4) of a subtype the reader does not know, message/global for an attached message with
UTF-8 in its header (RFC 6532 §3.7), and what 7bit and 8bit promise of its octets (RFC 2045
§2.7, §2.8, §6.2) - as `MimeMessage` reads them and `MimeAttachedMessage` writes them; its
line numbers refer to `45315aa7`. The twenty-third (O-28 to O-31) tests when the relay tries
again, and how many copies it sends - the sending strategy of RFC 5321 §4.5.4.1: the delay
before a destination that failed is tried again, the retry interval, the parameters of the
retry algorithm, and one copy for the recipients of one domain - as `QueueProcessor` and
`RetryCalculator` retry and the server queues what it relays; its line numbers refer to
`0a93a6fb`. The twenty-fourth (C-25, C-26, O-32, O-33) tests binary data on the wire - a
line of more than 998 octets, a NUL (RFC 2045 §2.7 to §2.9) - and BODY=BINARYMIME over BDAT
(RFC 3030 §3), as `SMTPSubmissionClient` and `SMTPOutboundClient` send a message; its line
numbers refer to `e7ab2253`. The twenty-fifth (R-13, R-14, K-11) tests the reports Hermod
sends in answer to a message: a DMARC failure report in answer to an ARF report (RFC 6650
§6), what Auto-Submitted says of a failure report (RFC 3834 §5.2), and the MDNs for a
recipient named twice (RFC 8098 §2.1); its line numbers refer to `83b63bb0`. The
twenty-sixth (D-16, D-17) tests what the relay's reports say of the next hop: the
Diagnostic-Code of a multi-line reply (RFC 3461 §9.2), and the Remote-MTA of a next hop
known by its address (§9.3); its line numbers refer to `0aec4e4a`. The twenty-seventh
(S-51, S-52) tests the sizes of RFC 5321 §4.5.3.1 on the server - a domain of 255 octets, a
path of 256, a reply line of 512 - and what it makes of a name or a path longer than they
allow: the header lines it writes of it (RFC 5322 §2.1.1), and the reply that repeats it;
its line numbers refer to `0aa5a6e6`.

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
| [S-20](#s-20) | medium | SCRAM | The server-final-message (v=) travelled in the 235 reply, which SMTP has no room for, not as a 334 challenge | 1 | [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284) |
| [S-27](#s-27) | medium | EXTERNAL | The TLS handshake never asked for a client certificate: SASL EXTERNAL was never offered and never worked | 1 | [Vanaheimr/Hermod#285](https://github.com/Vanaheimr/Hermod/pull/285) |
| [S-28](#s-28) | medium | trace | No loop detection: a message with 150 Received fields was delivered, and relayed on | 2 | [Vanaheimr/Hermod#287](https://github.com/Vanaheimr/Hermod/pull/287) |
| [S-29](#s-29) | medium | trace | No Return-Path at final delivery; one the client wrote into the message was the only one the mailbox saw | 4 | [Vanaheimr/Hermod#287](https://github.com/Vanaheimr/Hermod/pull/287) |
| [S-30](#s-30) | medium | trace | The EHLO argument went into Received unchecked: a client wrote the TCP-info it liked in front of the true one | 3 | [Vanaheimr/Hermod#287](https://github.com/Vanaheimr/Hermod/pull/287) |
| [S-35](#s-35) | medium | IDN | A local domain in the other form - U-labels for A-labels, or the reverse - was a relay request, refused | 2 | [Vanaheimr/Hermod#294](https://github.com/Vanaheimr/Hermod/pull/294) |
| [S-40](#s-40) | medium | AUTH | A user store that could not be asked was 535, "credentials invalid", not 454: every client was told its password is wrong | 2 | [Vanaheimr/Hermod#297](https://github.com/Vanaheimr/Hermod/pull/297) |
| [S-43](#s-43) | medium | trace | An Authentication-Results field the message brought along, with this server's authserv-id, was kept: a sender wrote "dmarc=pass" for the reader's filters | 3 | [Vanaheimr/Hermod#308](https://github.com/Vanaheimr/Hermod/pull/308) |
| [S-21](#s-21) | low | SCRAM | The channel binding flag "y" was refused, though Hermod offers no -PLUS | 1 | [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284) |
| [S-22](#s-22) | low | SCRAM | The c= attribute was not compared with the GS2 header | 1 | [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284) |
| [S-23](#s-23) | low | SCRAM | A requested authorization identity (a=) was ignored: alice asking to act as bob was alice | 1 | [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284) |
| [S-24](#s-24) | low | SCRAM | "=2C" and "=3D" in the user name were not decoded, and a bare "=" was not refused | 3 | [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284) |
| [S-25](#s-25) | low | SCRAM | A mandatory extension (m=) did not fail the authentication | 1 | [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284) |
| [S-26](#s-26) | low | SCRAM | Passwords were not normalized (SASLprep) before they were hashed | 1 | [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284) |
| [S-31](#s-31) | low | paths | A source route was taken as part of the mailbox: a local recipient behind one was a relay request | 4 | [Vanaheimr/Hermod#288](https://github.com/Vanaheimr/Hermod/pull/288) |
| [S-32](#s-32) | low | paths | A quoted local part with "@" or ">" in it was cut at the wrong place | 4 | [Vanaheimr/Hermod#288](https://github.com/Vanaheimr/Hermod/pull/288) |
| [S-33](#s-33) | low | commands | HELP and EXPN were unknown commands (500), VRFY without an argument was 252 | 3 | [Vanaheimr/Hermod#288](https://github.com/Vanaheimr/Hermod/pull/288) |
| [S-34](#s-34) | low | SMTPUTF8 | An ORCPT of the UTF-8 address type, in UTF-8, was refused | 1 | [Vanaheimr/Hermod#290](https://github.com/Vanaheimr/Hermod/pull/290) |
| [S-36](#s-36) | low | IDN | A server named in U-labels wrote them into its greeting and its reply to EHLO | 1 | [Vanaheimr/Hermod#294](https://github.com/Vanaheimr/Hermod/pull/294) |
| [S-37](#s-37) | low | AUTH | The longest PLAIN response - 255 octets of authzid, authcid and passwd each - was "500 Line too long" | 2 | [Vanaheimr/Hermod#297](https://github.com/Vanaheimr/Hermod/pull/297) |
| [S-38](#s-38) | low | AUTH | Spaces and tabs in a SASL response were ignored, not refused: what is no base64 signed in | 4 | [Vanaheimr/Hermod#297](https://github.com/Vanaheimr/Hermod/pull/297) |
| [S-39](#s-39) | low | AUTH | A line too long in an AUTH exchange left the exchange open: the next command was taken for a SASL response | 1 | [Vanaheimr/Hermod#297](https://github.com/Vanaheimr/Hermod/pull/297) |
| [S-41](#s-41) | low | server | A server that was stopped closed every session without a word: no 421 | 4 | [Vanaheimr/Hermod#302](https://github.com/Vanaheimr/Hermod/pull/302) |
| [S-42](#s-42) | low | server | RET, ENVID, SIZE, NOTIFY and ORCPT given twice with the same value were taken, not 501 | 5 | [Vanaheimr/Hermod#302](https://github.com/Vanaheimr/Hermod/pull/302) |
| [S-44](#s-44) | low | trace | An Authentication-Results field of a version not supported was kept | 1 | [Vanaheimr/Hermod#308](https://github.com/Vanaheimr/Hermod/pull/308) |
| [S-45](#s-45) | low | trace | The SPF result named the local-part of the reverse-path, which SPF did not authenticate | 1 | [Vanaheimr/Hermod#308](https://github.com/Vanaheimr/Hermod/pull/308) |
| [S-46](#s-46) | low | SMTPUTF8 | An SMTPUTF8 transaction was received "with ESMTP", not "with UTF8SMTP" | 1 | [Vanaheimr/Hermod#308](https://github.com/Vanaheimr/Hermod/pull/308) |
| [S-47](#s-47) | low | SMTPUTF8 | A server named in U-labels wrote A-labels into the Received field of an SMTPUTF8 transaction | 1 | [Vanaheimr/Hermod#308](https://github.com/Vanaheimr/Hermod/pull/308) |
| [S-48](#s-48) | medium | storage | The default store wrote the SPF record of the sender's domain into the stored header as DNS gave it: a line break in it made a header field of its own - "X-DMARC-Result: Pass" - an empty line ended the header | 4 | [Vanaheimr/Hermod#312](https://github.com/Vanaheimr/Hermod/pull/312) |
| [S-49](#s-49) | low | storage | The default store wrote fields of its own before the Return-Path: a stored message did not begin with it | 2 | [Vanaheimr/Hermod#312](https://github.com/Vanaheimr/Hermod/pull/312) |
| [S-50](#s-50) | low | storage | A message whose Message-ID was too long for a file name could not be stored: 451 at every try | 2 | [Vanaheimr/Hermod#312](https://github.com/Vanaheimr/Hermod/pull/312) |
| [S-51](#s-51) | low | trace fields | An EHLO name or a path longer than RFC 5321 allows was taken, and written into a header line of more than 998 characters | 4 | [Vanaheimr/Hermod#335](https://github.com/Vanaheimr/Hermod/pull/335) |
| [S-52](#s-52) | low | replies | EHLO and HELO repeated an argument longer than a domain name in a reply line of more than 512 octets | 2 | [Vanaheimr/Hermod#335](https://github.com/Vanaheimr/Hermod/pull/335) |
| [C-10](#c-10) | low | client | PIPELINING and CHUNKING were never used | 2 | [Vanaheimr/Hermod#127](https://github.com/Vanaheimr/Hermod/pull/127) |
| [O-1](#o-1) | **high** | outbound | Every reply but EHLO's was read as one line: a multi-line reply shifted all that followed | 5 | [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) |
| [O-2](#o-2) | **high** | outbound | A recipient the next hop refused disappeared: no bounce, no retry | 2 | [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) |
| [O-3](#o-3) | medium | outbound | No SMTPUTF8, no BODY=8BITMIME, no check that the next hop could take the message | 6 | [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) |
| [O-4](#o-4) | medium | outbound | REQUIRETLS was not passed on to the next hop | 2 | [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) |
| [O-5](#o-5) | medium | outbound | `ReadTimeoutMs` had no effect: a silent server held the delivery forever | 1 | [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) |
| [O-6](#o-6) | low | outbound | A failed delivery ended without QUIT | 3 | [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) |
| [O-7](#o-7) | low | outbound | EHLO keywords matched as substrings: "DSN" in the server's name was a DSN extension | 1 | [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) |
| [O-8](#o-8) | low | outbound | HELO after any EHLO refusal, a 421 included | 1 | [Vanaheimr/Hermod#130](https://github.com/Vanaheimr/Hermod/pull/130) |
| [O-9](#o-9) | medium | outbound routing | A temporary error of the MX lookup sent the message to the domain's own address | 2 | [Vanaheimr/Hermod#280](https://github.com/Vanaheimr/Hermod/pull/280) |
| [O-10](#o-10) | low | outbound routing | A domain that did not exist, or whose MX hosts did not, was retried instead of reported | 2 | [Vanaheimr/Hermod#280](https://github.com/Vanaheimr/Hermod/pull/280) |
| [O-11](#o-11) | low | outbound routing | MX hosts of the same preference were always tried in the order of the answer | 1 | [Vanaheimr/Hermod#280](https://github.com/Vanaheimr/Hermod/pull/280) |
| [O-12](#o-12) | low | outbound routing | The relay sent to itself, and to MX hosts behind itself, when it was an MX host of the domain | 3 | [Vanaheimr/Hermod#280](https://github.com/Vanaheimr/Hermod/pull/280) |
| [O-13](#o-13) | medium | outbound | The relay waited 60 seconds for the reply to the end of data, not 10 minutes: a slow next hop got the message again | 1 | [Vanaheimr/Hermod#289](https://github.com/Vanaheimr/Hermod/pull/289) |
| [O-14](#o-14) | medium | outbound | The ORCPT the relay wrote was no xtext: a recipient with a "+" was refused by a next hop that checks it - Postfix | 4 | [Vanaheimr/Hermod#290](https://github.com/Vanaheimr/Hermod/pull/290) |
| [O-15](#o-15) | **high** | outbound | A reply code was read by its exact value: a 2yz to MAIL other than 250 was taken for the delivery, and the message reported delivered unsent | 2 | [Vanaheimr/Hermod#293](https://github.com/Vanaheimr/Hermod/pull/293) |
| [O-16](#o-16) | low | outbound | 552 to RCPT, "too many recipients", bounced the recipient instead of trying it again | 2 | [Vanaheimr/Hermod#293](https://github.com/Vanaheimr/Hermod/pull/293) |
| [O-17](#o-17) | medium | outbound routing | A recipient domain in U-labels was never delivered to: its MX lookup failed, and was retried for days | 2 | [Vanaheimr/Hermod#294](https://github.com/Vanaheimr/Hermod/pull/294) |
| [O-18](#o-18) | low | outbound | A relay named in U-labels said EHLO with them | 1 | [Vanaheimr/Hermod#294](https://github.com/Vanaheimr/Hermod/pull/294) |
| [O-19](#o-19) | medium | outbound | The relay signed in to its smart host and left AUTH=<> out of MAIL FROM: the smart host took every message, forwarded ones too, for one its account submitted | 2 | [Vanaheimr/Hermod#298](https://github.com/Vanaheimr/Hermod/pull/298) |
| [O-20](#o-20) | low | outbound | AUTH PLAIN went with its initial response, however long: an AUTH line of more than 512 octets | 1 | [Vanaheimr/Hermod#298](https://github.com/Vanaheimr/Hermod/pull/298) |
| [O-21](#o-21) | medium | outbound | A 554 or 521 greeting of the first MX host bounced the message: the other MX hosts of the domain were never tried | 2 | [Vanaheimr/Hermod#301](https://github.com/Vanaheimr/Hermod/pull/301) |
| [O-22](#o-22) | medium | outbound | A refused session at one address of a multihomed next hop ended the attempt: its other addresses were never tried | 2 | [Vanaheimr/Hermod#301](https://github.com/Vanaheimr/Hermod/pull/301) |
| [O-23](#o-23) | medium | REQUIRETLS | A REQUIRETLS message went to an MX host that neither DNSSEC nor an MTA-STS policy vouched for | 1 | [Vanaheimr/Hermod#304](https://github.com/Vanaheimr/Hermod/pull/304) |
| [O-24](#o-24) | medium | REQUIRETLS | An MX host without REQUIRETLS bounced the message: the other MX hosts of the domain were never tried | 1 | [Vanaheimr/Hermod#304](https://github.com/Vanaheimr/Hermod/pull/304) |
| [O-25](#o-25) | low | REQUIRETLS | No TLS for a REQUIRETLS message - no STARTTLS, a certificate not trusted - was a failure for now, not 5.7.10 | 2 | [Vanaheimr/Hermod#304](https://github.com/Vanaheimr/Hermod/pull/304) |
| [O-26](#o-26) | low | REQUIRETLS | A bounce that carried REQUIRETLS was refused to a next hop without it, 5.7.30, and lost | 1 | [Vanaheimr/Hermod#304](https://github.com/Vanaheimr/Hermod/pull/304) |
| [O-27](#o-27) | low | REQUIRETLS | "TLS-Required: No" was not heeded: an MTA-STS policy held back a report on the domain's broken TLS | 2 | [Vanaheimr/Hermod#304](https://github.com/Vanaheimr/Hermod/pull/304) |
| [O-28](#o-28) | medium | outbound | A next hop that refused the session for now was tried again at once for the next message to it | 2 | [Vanaheimr/Hermod#329](https://github.com/Vanaheimr/Hermod/pull/329) |
| [O-29](#o-29) | low | outbound | The retry intervals and the give-up time could not be configured | 2 | [Vanaheimr/Hermod#329](https://github.com/Vanaheimr/Hermod/pull/329) |
| [O-30](#o-30) | low | outbound | A message refused for now could be tried again after 27 minutes | 1 | [Vanaheimr/Hermod#329](https://github.com/Vanaheimr/Hermod/pull/329) |
| [O-31](#o-31) | low | outbound | Recipients at one domain written two ways - in other capitals, in U-labels and A-labels - got a copy each | 2 | [Vanaheimr/Hermod#329](https://github.com/Vanaheimr/Hermod/pull/329) |
| [O-32](#o-32) | medium | outbound | The relay sent binary data to a next hop without BINARYMIME | 4 | [Vanaheimr/Hermod#331](https://github.com/Vanaheimr/Hermod/pull/331) |
| [O-33](#o-33) | low | outbound | The relay sent binary data as DATA to a next hop that offers BINARYMIME | 1 | [Vanaheimr/Hermod#331](https://github.com/Vanaheimr/Hermod/pull/331) |
| [C-11](#c-11) | low | client | One refused recipient stopped the message for all | 1 | [Vanaheimr/Hermod#131](https://github.com/Vanaheimr/Hermod/pull/131) |
| [C-12](#c-12) | medium | SCRAM client | A 235 without the server-final-message was taken as success: the server never proved it knows the password | 1 | [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284) |
| [C-13](#c-13) | low | SCRAM client | The client did not normalize the password (SASLprep) | 1 | [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284) |
| [C-14](#c-14) | low | client | The submission client waited 30 seconds for the reply to the end of data: a slow server got the message twice | 1 | [Vanaheimr/Hermod#289](https://github.com/Vanaheimr/Hermod/pull/289) |
| [C-15](#c-15) | medium | client | A reply code was read by its exact value: a 252 to MAIL or RCPT, a 350 to DATA, a 251 to the end of data failed the message | 5 | [Vanaheimr/Hermod#293](https://github.com/Vanaheimr/Hermod/pull/293) |
| [C-16](#c-16) | low | client | A client named in U-labels said EHLO with them | 1 | [Vanaheimr/Hermod#294](https://github.com/Vanaheimr/Hermod/pull/294) |
| [C-17](#c-17) | low | client | AUTH PLAIN went with its initial response, however long: an AUTH line of more than 512 octets | 1 | [Vanaheimr/Hermod#298](https://github.com/Vanaheimr/Hermod/pull/298) |
| [C-18](#c-18) | low | client | A SCRAM challenge that is no base64 was not cancelled with "*": the client threw, and its QUIT was taken for the response | 2 | [Vanaheimr/Hermod#298](https://github.com/Vanaheimr/Hermod/pull/298) |
| [C-19](#c-19) | medium | REQUIRETLS | The submission client gave a REQUIRETLS message to a server without REQUIRETLS, and left the option out | 1 | [Vanaheimr/Hermod#305](https://github.com/Vanaheimr/Hermod/pull/305) |
| [C-20](#c-20) | medium | SMTPUTF8 | The submission client sent an internationalized message to a server without SMTPUTF8 - UTF-8 addresses in MAIL and RCPT, UTF-8 in the header | 4 | [Vanaheimr/Hermod#309](https://github.com/Vanaheimr/Hermod/pull/309) |
| [C-21](#c-21) | low | SMTPUTF8 | The submission client asked for SMTPUTF8 for a message whose only non-ASCII octets are in an 8-bit body | 1 | [Vanaheimr/Hermod#309](https://github.com/Vanaheimr/Hermod/pull/309) |
| [C-22](#c-22) | medium | DSN | ENVID went on MAIL as the caller gave it, not as xtext: a space, "=" or "+" made it another parameter or another value, a line break another command - a recipient of the ENVID's making | 7 | [Vanaheimr/Hermod#311](https://github.com/Vanaheimr/Hermod/pull/311) |
| [C-23](#c-23) | low | DSN | RET without NOTIFY and ENVID was left out: the failed DSN returned the whole message | 2 | [Vanaheimr/Hermod#311](https://github.com/Vanaheimr/Hermod/pull/311) |
| [C-24](#c-24) | low | DSN | NOTIFY=NEVER could not be asked for: `DsnNotify.Never` was taken for no request, and the failed DSNs came | 2 | [Vanaheimr/Hermod#311](https://github.com/Vanaheimr/Hermod/pull/311) |
| [C-25](#c-25) | low | client | Binary data went as BODY=8BITMIME to a server that offers BINARYMIME | 2 | [Vanaheimr/Hermod#331](https://github.com/Vanaheimr/Hermod/pull/331) |
| [C-26](#c-26) | medium | client | Binary data - a line of more than 998 octets, a NUL - went to a server without BINARYMIME | 4 | [Vanaheimr/Hermod#331](https://github.com/Vanaheimr/Hermod/pull/331) |
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
| [D-13](#d-13) | low | reports | The bounce of an SMTPUTF8 message had UTF-8 in message/delivery-status and in message/rfc822 | 2 | [Vanaheimr/Hermod#290](https://github.com/Vanaheimr/Hermod/pull/290) |
| [D-14](#d-14) | medium | REQUIRETLS | The bounce of a REQUIRETLS message returned the whole message, body and all, RET=FULL or none | 2 | [Vanaheimr/Hermod#305](https://github.com/Vanaheimr/Hermod/pull/305) |
| [D-15](#d-15) | low | REQUIRETLS | The bounce of a REQUIRETLS message was queued without REQUIRETLS | 1 | [Vanaheimr/Hermod#305](https://github.com/Vanaheimr/Hermod/pull/305) |
| [D-16](#d-16) | low | reports | A multi-line reply of the next hop lost its reply codes in Diagnostic-Code, and made a line of more than 998 characters | 6 | [Vanaheimr/Hermod#334](https://github.com/Vanaheimr/Hermod/pull/334) |
| [D-17](#d-17) | low | reports | The Remote-MTA of a next hop known by its address was no domain-literal: "dns; 127.0.0.1" | 2 | [Vanaheimr/Hermod#334](https://github.com/Vanaheimr/Hermod/pull/334) |
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
| [N-5](#n-5) | medium | DANE | DANE-TA depended on the platform downloading issuers: with an unreachable AIA URL, ~15 s of waiting | 1 | [Vanaheimr/Hermod#149](https://github.com/Vanaheimr/Hermod/pull/149) |
| [V-1](#v-1) | medium | inbound | A DKIM key record without its optional `v=DKIM1` was not found: the signature failed | 1 | [Vanaheimr/Hermod#258](https://github.com/Vanaheimr/Hermod/pull/258) |
| [V-2](#v-2) | low | inbound | Authentication-Results of a null sender: `smtp.mailfrom=<>`, not the HELO identity SPF checked | 1 | [Vanaheimr/Hermod#259](https://github.com/Vanaheimr/Hermod/pull/259) |
| [P-1](#p-1) | low | outbound | `PublicAddressesOnly` took the IPv4 documentation ranges (RFC 5737) for public | 3 | [Vanaheimr/Hermod#257](https://github.com/Vanaheimr/Hermod/pull/257) |
| [P-2](#p-2) | low | DKIM signing | `DkimSigner` signed with, and the key generators made, RSA keys of fewer than 1024 bits | 2 | [Vanaheimr/Hermod#281](https://github.com/Vanaheimr/Hermod/pull/281) |
| [P-3](#p-3) | low | DKIM signing | `DkimKeyGenerator` wrote the key record as one character-string of 410 characters | 1 | [Vanaheimr/Hermod#281](https://github.com/Vanaheimr/Hermod/pull/281) |
| [R-1](#r-1) | medium | DMARC reports | The aggregate XML lacked sp, fo, envelope_from and the SPF scope, which Appendix C requires | 4 | [Vanaheimr/Hermod#261](https://github.com/Vanaheimr/Hermod/pull/261) |
| [R-2](#r-2) | medium | DMARC reports | The size limit of a report URI (`!10m`) was cut off and ignored | 1 | [Vanaheimr/Hermod#261](https://github.com/Vanaheimr/Hermod/pull/261) |
| [R-3](#r-3) | low | DMARC reports | The Report-ID of the subject was no msg-id | 1 | [Vanaheimr/Hermod#261](https://github.com/Vanaheimr/Hermod/pull/261) |
| [R-4](#r-4) | low | DMARC reports | The rua of the destination's own record did not replace the policy domain's | 1 | [Vanaheimr/Hermod#261](https://github.com/Vanaheimr/Hermod/pull/261) |
| [R-5](#r-5) | medium | DMARC reports | Failure reports lacked Identity-Alignment and SPF-DNS (REQUIRED) | 2 | [Vanaheimr/Hermod#261](https://github.com/Vanaheimr/Hermod/pull/261) |
| [R-6](#r-6) | low | DMARC reports | fo=1 was ignored: only DMARC failures were reported | 1 | [Vanaheimr/Hermod#261](https://github.com/Vanaheimr/Hermod/pull/261) |
| [R-7](#r-7) | low | DMARC | p=reject with pct=0 let a failing message through as p=none, not quarantined | 1 | [Vanaheimr/Hermod#261](https://github.com/Vanaheimr/Hermod/pull/261) |
| [R-8](#r-8) | medium | DMARC reports | A line break in a rua or ruf URI went into the report: a Bcc field of its own, a recipient with a line break in it - and into RCPT TO | 3 | [Vanaheimr/Hermod#316](https://github.com/Vanaheimr/Hermod/pull/316) |
| [R-9](#r-9) | low | DMARC reports | A mailto URI was taken for an address: percent-encoding not decoded, its header fields part of the domain | 2 | [Vanaheimr/Hermod#316](https://github.com/Vanaheimr/Hermod/pull/316) |
| [R-10](#r-10) | medium | DMARC reports | A line break in the SPF record made a field of the failure report of its own: "Identity-Alignment: dkim, spf" | 3 | [Vanaheimr/Hermod#316](https://github.com/Vanaheimr/Hermod/pull/316) |
| [R-11](#r-11) | low | DMARC reports | Original-Mail-From was no reverse-path: the address without its angle brackets | 1 | [Vanaheimr/Hermod#316](https://github.com/Vanaheimr/Hermod/pull/316) |
| [R-12](#r-12) | low | DMARC reports | An IPv6 Source-IP was no IPv6 address literal: no "IPv6:" | 1 | [Vanaheimr/Hermod#316](https://github.com/Vanaheimr/Hermod/pull/316) |
| [R-13](#r-13) | medium | DMARC reports | A failure report was sent in answer to an ARF report | 3 | [Vanaheimr/Hermod#332](https://github.com/Vanaheimr/Hermod/pull/332) |
| [R-14](#r-14) | low | DMARC reports | A failure report was labelled Auto-Submitted: auto-generated | 3 | [Vanaheimr/Hermod#332](https://github.com/Vanaheimr/Hermod/pull/332) |
| [T-1](#t-1) | medium | TLS-RPT | Two records, a record not beginning with `v=TLSRPTv1;`, or `v=tlsrptv1` still named destinations | 3 | [Vanaheimr/Hermod#262](https://github.com/Vanaheimr/Hermod/pull/262) |
| [T-2](#t-2) | low | TLS-RPT | No policy-string in the JSON | 1 | [Vanaheimr/Hermod#262](https://github.com/Vanaheimr/Hermod/pull/262) |
| [T-3](#t-3) | medium | TLS-RPT | Under an MTA-STS policy in testing mode, a certificate that failed the policy was reported as a success | 1 | [Vanaheimr/Hermod#262](https://github.com/Vanaheimr/Hermod/pull/262) |
| [T-4](#t-4) | low | TLS-RPT | Through a smart host, the session was reported to the recipient's domain, under the smart host's policy | 1 | [Vanaheimr/Hermod#262](https://github.com/Vanaheimr/Hermod/pull/262) |
| [T-5](#t-5) | medium | TLS-RPT | A line break in an rua URI went into the report: a Bcc field of its own, a recipient with a line break in it - and into RCPT TO | 2 | [Vanaheimr/Hermod#316](https://github.com/Vanaheimr/Hermod/pull/316) |
| [T-6](#t-6) | low | TLS-RPT | A mailto URI was taken for an address: percent-encoding not decoded, its header fields part of it | 2 | [Vanaheimr/Hermod#316](https://github.com/Vanaheimr/Hermod/pull/316) |
| [Q-1](#q-1) | low | MT-PRIORITY | `+3`, `-0`, `05` were taken | 3 | [Vanaheimr/Hermod#263](https://github.com/Vanaheimr/Hermod/pull/263) |
| [Q-2](#q-2) | low | MT-PRIORITY | MT-PRIORITY twice was taken | 1 | [Vanaheimr/Hermod#263](https://github.com/Vanaheimr/Hermod/pull/263) |
| [Q-3](#q-3) | medium | MT-PRIORITY | A client nobody vouched for raised its own priority | 1 | [Vanaheimr/Hermod#263](https://github.com/Vanaheimr/Hermod/pull/263) |
| [Q-4](#q-4) | low | MT-PRIORITY | No PRIORITY clause in Received | 1 | [Vanaheimr/Hermod#263](https://github.com/Vanaheimr/Hermod/pull/263) |
| [L-1](#l-1) | medium | limits | 100 recipients per session, not per message: the second message ran short | 1 | [Vanaheimr/Hermod#264](https://github.com/Vanaheimr/Hermod/pull/264) |
| [L-2](#l-2) | low | limits | The 421/554 of a connection refused at accept ended in a bare LF on Linux | 1 | [Vanaheimr/Hermod#264](https://github.com/Vanaheimr/Hermod/pull/264) |
| [L-3](#l-3) | low | limits | After a 554 greeting the connection was closed, not held for QUIT | 1 | [Vanaheimr/Hermod#264](https://github.com/Vanaheimr/Hermod/pull/264) |
| [L-4](#l-4) | low | limits | After a 421 to AUTH the connection stayed open | 1 | [Vanaheimr/Hermod#264](https://github.com/Vanaheimr/Hermod/pull/264) |
| [A-1](#a-1) | **high** | ARC | No limit of 50 ARC sets; `i=2147483647` kept the validator counting forever, on every unauthenticated message | 2 | [Vanaheimr/Hermod#260](https://github.com/Vanaheimr/Hermod/pull/260) |
| [A-2](#a-2) | medium | ARC | An ARC-Seal with an h= tag was accepted | 1 | [Vanaheimr/Hermod#260](https://github.com/Vanaheimr/Hermod/pull/260) |
| [A-3](#a-3) | low | ARC | A tag twice in an ARC tag-list: the last one counted (`cv=fail; cv=pass` passed) | 1 | [Vanaheimr/Hermod#260](https://github.com/Vanaheimr/Hermod/pull/260) |
| [A-4](#a-4) | low | ARC | The sealer sealed a chain whose last seal said cv=fail once more | 1 | [Vanaheimr/Hermod#260](https://github.com/Vanaheimr/Hermod/pull/260) |
| [A-5](#a-5) | low | ARC | The sealer's AMS signed the ARC header fields it was configured to | 1 | [Vanaheimr/Hermod#260](https://github.com/Vanaheimr/Hermod/pull/260) |
| [V-3](#v-3) | medium | DKIM, ARC | rsa-sha1 signatures verified | 2 | [Vanaheimr/Hermod#260](https://github.com/Vanaheimr/Hermod/pull/260) |
| [V-4](#v-4) | medium | DKIM, ARC | A signature whose b= tag came first never verified | 2 | [Vanaheimr/Hermod#260](https://github.com/Vanaheimr/Hermod/pull/260) |
| [V-5](#v-5) | medium | SPF | A DNS error - SERVFAIL, a timeout - was taken for no record or no match: `none`, or `fail` under `-all`, never `temperror` | 6 | [Vanaheimr/Hermod#277](https://github.com/Vanaheimr/Hermod/pull/277) |
| [V-6](#v-6) | low | SPF | `v=spf10` was taken for an SPF record, and of two SPF records the first | 3 | [Vanaheimr/Hermod#277](https://github.com/Vanaheimr/Hermod/pull/277) |
| [V-7](#v-7) | low | SPF | The record was evaluated up to the term that matched; syntax errors after it, or a bad address before it, went unnoticed | 3 | [Vanaheimr/Hermod#277](https://github.com/Vanaheimr/Hermod/pull/277) |
| [V-8](#v-8) | low | SPF | redirect= or exp= twice was no `permerror` | 2 | [Vanaheimr/Hermod#277](https://github.com/Vanaheimr/Hermod/pull/277) |
| [V-9](#v-9) | low | SPF | `ptr` never matched | 2 | [Vanaheimr/Hermod#277](https://github.com/Vanaheimr/Hermod/pull/277) |
| [V-10](#v-10) | low | SPF | `mx` with more than ten MX names took the first ten | 1 | [Vanaheimr/Hermod#277](https://github.com/Vanaheimr/Hermod/pull/277) |
| [V-11](#v-11) | low | SPF | No limit on void lookups | 1 | [Vanaheimr/Hermod#277](https://github.com/Vanaheimr/Hermod/pull/277) |
| [V-12](#v-12) | low | SPF | A client on an IPv4-mapped address matched no `ip4` or `a` | 2 | [Vanaheimr/Hermod#277](https://github.com/Vanaheimr/Hermod/pull/277) |
| [V-13](#v-13) | medium | DKIM verifier | A signature that did not sign From verified, and DMARC passed on it whatever From was put in | 2 | [Vanaheimr/Hermod#279](https://github.com/Vanaheimr/Hermod/pull/279) |
| [V-14](#v-14) | medium | DKIM verifier | Signatures with RSA keys of fewer than 1024 bits verified | 1 | [Vanaheimr/Hermod#279](https://github.com/Vanaheimr/Hermod/pull/279) |
| [V-15](#v-15) | low | DKIM verifier | A signature without v= or a=, or with v=2, verified | 3 | [Vanaheimr/Hermod#279](https://github.com/Vanaheimr/Hermod/pull/279) |
| [V-16](#v-16) | low | DKIM verifier | A signature whose i= was outside its d= verified | 1 | [Vanaheimr/Hermod#279](https://github.com/Vanaheimr/Hermod/pull/279) |
| [V-17](#v-17) | low | DKIM verifier | The key record's h=, s=, t=s and k= were not applied | 4 | [Vanaheimr/Hermod#279](https://github.com/Vanaheimr/Hermod/pull/279) |
| [V-18](#v-18) | medium | DMARC | A temporary error of SPF, with no signature passing, failed DMARC and applied p=reject | 1 | [Vanaheimr/Hermod#282](https://github.com/Vanaheimr/Hermod/pull/282) |
| [V-19](#v-19) | low | DMARC | A DNS error at the From domain's record fell back to the Organizational Domain's record | 1 | [Vanaheimr/Hermod#282](https://github.com/Vanaheimr/Hermod/pull/282) |
| [V-20](#v-20) | low | DMARC | Of two DMARC records the first was applied | 1 | [Vanaheimr/Hermod#282](https://github.com/Vanaheimr/Hermod/pull/282) |
| [V-21](#v-21) | low | DMARC | The version was not matched exactly: `v=dmarc1` and `v=DMARC1x` counted, `v = DMARC1` did not | 3 | [Vanaheimr/Hermod#282](https://github.com/Vanaheimr/Hermod/pull/282) |
| [V-22](#v-22) | low | DMARC | A record without a valid p=, or with an invalid sp=, and without rua was applied | 3 | [Vanaheimr/Hermod#282](https://github.com/Vanaheimr/Hermod/pull/282) |
| [V-23](#v-23) | medium | SPF | A sender domain in U-labels was looked up in U-labels: no record was found, "-all" was "none" | 3 | [Vanaheimr/Hermod#295](https://github.com/Vanaheimr/Hermod/pull/295) |
| [V-24](#v-24) | medium | DKIM verifier | A signature with d= in U-labels was checked against a key looked up under a mis-decoded name | 1 | [Vanaheimr/Hermod#295](https://github.com/Vanaheimr/Hermod/pull/295) |
| [V-25](#v-25) | medium | DMARC | The policy of an author domain in U-labels was looked up in U-labels: the domain's own p=reject was never found | 2 | [Vanaheimr/Hermod#295](https://github.com/Vanaheimr/Hermod/pull/295) |
| [E-1](#e-1) | **high** | message format | A comment after the address named the mailbox: `From: mallory@evil.example (<ceo@company.example>)` read as ceo@company.example, and was DKIM-signed for company.example | 7 | [Vanaheimr/Hermod#269](https://github.com/Vanaheimr/Hermod/pull/269) |
| [I-1](#i-1) | **high** | TLS-RPT ingest | A gzip bomb was inflated whole, in memory and onto disk, before the reply to DATA | 1 | [Vanaheimr/Hermod#271](https://github.com/Vanaheimr/Hermod/pull/271) |
| [I-2](#i-2) | **high** | DMARC reader | Deeply nested XML overflowed the stack and ended the process | 1 | [Vanaheimr/Hermod#271](https://github.com/Vanaheimr/Hermod/pull/271) |
| [K-1](#k-1) | **high** | MDN | Read receipts were sent automatically to any address a message named - a third party, for a null reverse-path, to several | 4 | [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272) |
| [K-2](#k-2) | **high** | MDN | A field folded onto many lines kept the session busy for a time that grew with the square of their number - 240000 lines, 34 seconds | 1 | [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272) |
| [G-1](#g-1) | **high** | PGP/MIME | A ciphertext was decrypted whether its MDC held or not, and without one at all (EFAIL) | 2 | [Vanaheimr/Hermod#273](https://github.com/Vanaheimr/Hermod/pull/273) |
| [E-2](#e-2) | medium | message format | A date with nested comments took quadratic time: 16 KB of `((…))` held the parser for seconds, 1 MB for hours | 1 | [Vanaheimr/Hermod#269](https://github.com/Vanaheimr/Hermod/pull/269) |
| [E-3](#e-3) | medium | message format | Header lines of more than 998 characters: a long word, a long header value, a long non-ASCII file name | 4 | [Vanaheimr/Hermod#270](https://github.com/Vanaheimr/Hermod/pull/270) |
| [E-4](#e-4) | medium | message format | The older builders' boundary held `<`, which is no bchars | 1 | [Vanaheimr/Hermod#270](https://github.com/Vanaheimr/Hermod/pull/270) |
| [E-5](#e-5) | medium | message format | `EMail.Parse` threw on delimiter lines with transport padding, and on a multipart without delimiters | 2 | [Vanaheimr/Hermod#269](https://github.com/Vanaheimr/Hermod/pull/269) |
| [I-3](#i-3) | medium | TLS-RPT ingest | A quoted-printable report part was not decoded, so the report was lost | 1 | [Vanaheimr/Hermod#271](https://github.com/Vanaheimr/Hermod/pull/271) |
| [I-4](#i-4) | medium | DMARC reader | XML in UTF-16, or in UTF-8 with a byte order mark, was no report | 3 | [Vanaheimr/Hermod#271](https://github.com/Vanaheimr/Hermod/pull/271) |
| [K-3](#k-3) | medium | MDN | The MDN was sent from the recipient's address, not from the null reverse-path | 1 | [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272) |
| [K-4](#k-4) | medium | MDN | An MDN was answered with an MDN | 1 | [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272) |
| [K-5](#k-5) | medium | MDN | No Original-Recipient field, from the message's header or from ORCPT | 3 | [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272) |
| [G-2](#g-2) | medium | PGP/MIME | A multipart/signed with a third, unsigned part verified as valid | 1 | [Vanaheimr/Hermod#273](https://github.com/Vanaheimr/Hermod/pull/273) |
| [G-3](#g-3) | medium | PGP/MIME | An attached part was signed trimmed and sent untrimmed; 8 bit was signed as 8 bit | 2 | [Vanaheimr/Hermod#273](https://github.com/Vanaheimr/Hermod/pull/273) |
| [E-6](#e-6) | low | message format | White space or a comment inside the time (obsolete) made the time 00:00:00 | 2 | [Vanaheimr/Hermod#269](https://github.com/Vanaheimr/Hermod/pull/269) |
| [E-7](#e-7) | low | message format | `EMail.Parse` did not read obsolete zones (EST, PDT, UT) or comments in the time: Date was 0001-01-01 | 4 | [Vanaheimr/Hermod#269](https://github.com/Vanaheimr/Hermod/pull/269) |
| [E-8](#e-8) | low | message format | An obsolete msg-id with CFWS (`<1234 @ local(blah) .machine .example>`) was kept as raw text | 1 | [Vanaheimr/Hermod#269](https://github.com/Vanaheimr/Hermod/pull/269) |
| [E-9](#e-9) | low | message format | A reply to a parent without References but with In-Reply-To left the grandparent out of References | 1 | [Vanaheimr/Hermod#270](https://github.com/Vanaheimr/Hermod/pull/270) |
| [E-10](#e-10) | low | message format | A part with an unknown Content-Transfer-Encoding was shown as the text of the message | 1 | [Vanaheimr/Hermod#269](https://github.com/Vanaheimr/Hermod/pull/269) |
| [E-11](#e-11) | low | message format | Quoted-printable decoding kept trailing white space that RFC 2045 says must be deleted | 1 | [Vanaheimr/Hermod#269](https://github.com/Vanaheimr/Hermod/pull/269) |
| [E-12](#e-12) | low | message format | `MimeMessageBuilder` wrote a second From, Date, Subject, Message-ID or To named among its further headers | 5 | [Vanaheimr/Hermod#270](https://github.com/Vanaheimr/Hermod/pull/270) |
| [E-13](#e-13) | low | message format | The older builders wrote the List-ID description raw: 8-bit and with specials | 1 | [Vanaheimr/Hermod#270](https://github.com/Vanaheimr/Hermod/pull/270) |
| [E-14](#e-14) | medium | message format | `EMail.Parse` read the media type and the name `boundary` with case: a `Multipart/Mixed` had no parts, a `Multipart/Signed` with a valid signature was "no signature", a `Multipart/Encrypted` could not be decrypted | 9 | [Vanaheimr/Hermod#276](https://github.com/Vanaheimr/Hermod/pull/276) |
| [E-15](#e-15) | low | message format | `EMail.Parse` took white space around `=` and comments in the Content-Type for part of the names and values | 3 | [Vanaheimr/Hermod#276](https://github.com/Vanaheimr/Hermod/pull/276) |
| [E-16](#e-16) | low | message format | `EMail.Parse` took a body for a multipart when its Content-Type held the text `boundary=`, not when it was a multipart: multipart/related had no parts, a text/plain lost what followed a line `--` | 2 | [Vanaheimr/Hermod#276](https://github.com/Vanaheimr/Hermod/pull/276) |
| [E-17](#e-17) | low | MIME | A Content-ID with a comment was not read as a msg-id: the part its cid: URL names, and the root start= names, not found | 3 | [Vanaheimr/Hermod#317](https://github.com/Vanaheimr/Hermod/pull/317) |
| [E-18](#e-18) | medium | MIME | A part of a disposition type the reader does not know was lost: neither the body nor an attachment | 1 | [Vanaheimr/Hermod#317](https://github.com/Vanaheimr/Hermod/pull/317) |
| [E-19](#e-19) | low | MIME | A text marked inline with a file name was taken for an attachment: the message had no body | 1 | [Vanaheimr/Hermod#317](https://github.com/Vanaheimr/Hermod/pull/317) |
| [E-20](#e-20) | low | MIME | A Content-ID was written whether it was a msg-id or not: no @, a space, a non-ASCII character as "?" | 3 | [Vanaheimr/Hermod#317](https://github.com/Vanaheimr/Hermod/pull/317) |
| [E-21](#e-21) | low | MIME | A multipart/related was written without its type parameter | 1 | [Vanaheimr/Hermod#317](https://github.com/Vanaheimr/Hermod/pull/317) |
| [E-22](#e-22) | low | answers | The subject of a reply to a list's post had two "Re: ": "Re: [dev] Re: Hello" | 2 | [Vanaheimr/Hermod#318](https://github.com/Vanaheimr/Hermod/pull/318) |
| [E-23](#e-23) | low | answers | White space inside the angle brackets of List-Post lost the list: the reply went to the sender | 2 | [Vanaheimr/Hermod#318](https://github.com/Vanaheimr/Hermod/pull/318) |
| [E-24](#e-24) | low | answers | List-Post was read for the first mailto anywhere in it: in a comment, after what RFC 2369 says to ignore | 3 | [Vanaheimr/Hermod#318](https://github.com/Vanaheimr/Hermod/pull/318) |
| [E-25](#e-25) | low | message format | The older builder wrote List-Post's mailto URL with the address as it is: "?", "#", "%", "/" not percent-encoded | 4 | [Vanaheimr/Hermod#318](https://github.com/Vanaheimr/Hermod/pull/318) |
| [E-26](#e-26) | low | MIME | A text of a subtype the reader does not know was an attachment: a text/markdown mail had no body | 3 | [Vanaheimr/Hermod#326](https://github.com/Vanaheimr/Hermod/pull/326) |
| [E-27](#e-27) | low | MIME | A message part of a subtype the reader does not know was lost: neither the text nor an attachment | 3 | [Vanaheimr/Hermod#326](https://github.com/Vanaheimr/Hermod/pull/326) |
| [E-28](#e-28) | low | MIME | An attached message with UTF-8 in its header was written message/rfc822, not message/global | 3 | [Vanaheimr/Hermod#326](https://github.com/Vanaheimr/Hermod/pull/326) |
| [E-29](#e-29) | low | MIME | An attached message with a line over 998 octets or a NUL was written 7bit or 8bit, not binary | 3 | [Vanaheimr/Hermod#326](https://github.com/Vanaheimr/Hermod/pull/326) |
| [I-5](#i-5) | low | DMARC reader | A date_range outside years 1 to 9999 threw `ArgumentOutOfRangeException` | 2 | [Vanaheimr/Hermod#271](https://github.com/Vanaheimr/Hermod/pull/271) |
| [I-6](#i-6) | low | DSN | A next hop's status code with leading zeros went into the DSN as it was | 3 | [Vanaheimr/Hermod#271](https://github.com/Vanaheimr/Hermod/pull/271) |
| [I-7](#i-7) | low | TLS-RPT ingest | The preamble of the multipart was read as a report part | 1 | [Vanaheimr/Hermod#271](https://github.com/Vanaheimr/Hermod/pull/271) |
| [K-6](#k-6) | low | MDN | `Build` addressed the receipt to the first of several requesters only | 1 | [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272) |
| [K-7](#k-7) | low | MDN | `GoesElsewhere` compared the local-part without case and saw nothing to confirm without a Return-Path, with a null one, or with several requesters | 4 | [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272) |
| [K-8](#k-8) | low | MDN | `CreateReadReceipt` defaulted to automatic-action/MDN-sent-automatically | 1 | [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272) |
| [K-9](#k-9) | low | MDN | The delivering server wrote no Original-Recipient header field from ORCPT | 1 | [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272), [#274](https://github.com/Vanaheimr/Hermod/pull/274) |
| [K-10](#k-10) | low | MDN | The returned header lost all but the first of repeated fields and the white space of folded ones | 2 | [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272) |
| [K-11](#k-11) | low | MDN | A recipient named twice was sent two MDNs | 1 | [Vanaheimr/Hermod#332](https://github.com/Vanaheimr/Hermod/pull/332) |
| [G-4](#g-4) | low | PGP/MIME | A broken signature part threw out of `VerifyPgpSignature` | 2 | [Vanaheimr/Hermod#273](https://github.com/Vanaheimr/Hermod/pull/273) |
| [G-5](#g-5) | low | PGP/MIME | `PgpMime.Signed` took a signed part with trailing white space | 1 | [Vanaheimr/Hermod#273](https://github.com/Vanaheimr/Hermod/pull/273) |
| [G-6](#g-6) | low | PGP/MIME | micalg `pgp-sha3_256` instead of `pgp-sha3-256` | 2 | [Vanaheimr/Hermod#273](https://github.com/Vanaheimr/Hermod/pull/273) |

The 557 tests for these are part of the merge gate now; the observations the first
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

The ninth round's SASL tests: `ScramTests` run SCRAM-SHA-256 exchanges against the
submission port with the suite's own client half (`ScramSha256`), which can send another
GS2 header, another c=, a mandatory extension, an unescaped user name and a normalized
password; `ExternalAuthTests` present self-made client certificates in the STARTTLS
handshake. Covered without a finding: an authorization identity that is the user's own; an
ASCII password, normalized or not; an unlisted certificate, and none, authenticate nobody
with EXTERNAL.

### S-20
**Closed** in [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284)
(`be8520c4`). **The server-final-message travelled in the 235 reply**
(`SMTPSession.cs:481` to `:484`, `ScramSha256AuthHandler.cs:194` to `:202`): the server's
"v=" ServerSignature is appended, base64, to "235 2.7.0 Authentication successful". RFC
4954 §4: "the SMTP protocol doesn't support the SASL feature of returning additional data
with a successful outcome"; RFC 4422 §3: "Where the mechanism specifies that the server is
to return additional data to the client with a successful outcome and this field is
unavailable or unused, the additional data is sent as a challenge whose response is empty.
After receiving this response, the server then indicates the successful outcome." A client
that keeps to it waits for a 334 it never gets, and cannot authenticate the server - the
half of SCRAM that RFC 5802 §5 has the client do (C-12 is Hermod's own client accepting
that). Test: `The_server_final_message_is_a_challenge`.
`AuthTests.Scram_sha_256_succeeds_with_mutual_authentication` takes either form and still
passes.

Fixed: the server-final-message is a 334, and 235 follows the empty response - an empty
line or "="; a response with data fails.

### S-21
**Closed** in [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284)
(`be8520c4`). **The channel binding flag "y" was refused**
(`ScramSha256AuthHandler.cs:85`, `parts[0] != "n"`): RFC 5802 §6: a client that supports
channel binding and does not see the -PLUS mechanism "MUST NOT use an "n" gs2-cbind-flag"
- it sends "y" - and "If the flag is set to "y" and the server supports channel binding,
the server MUST fail authentication". Hermod offers no SCRAM-SHA-256-PLUS; such a client
is turned away with 535. Test:
`A_client_that_supports_channel_binding_is_authenticated_with_the_y_flag`.

Fixed: "y" is authenticated; "p=" is still refused.

### S-22
**Closed** in [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284)
(`be8520c4`). **The c= attribute was not compared with the GS2 header**
(`ScramSha256AuthHandler.cs:166`: c= is taken into the AuthMessage as it came): RFC 5802
§6: "The server MUST always validate the client's "c=" field. The server does this by
constructing the value of the "c=" attribute and then checking that it matches the
client's c= attribute value." A client-first-message with "n,," and a c= of "y,," is
accepted - the check that tells a downgraded channel binding apart. Test:
`A_c_attribute_that_is_not_the_GS2_header_is_refused`.

Fixed: c= has to be the GS2 header of the client-first-message, authorization identity
included.

### S-23
**Closed** in [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284)
(`be8520c4`). **A requested authorization identity was ignored**
(`ScramSha256AuthHandler.cs:85` to `:92`: the GS2 header is skipped): RFC 5802 §5.1, a:
"Upon the receipt of this value the server verifies its correctness according to the used
SASL protocol profile. Failed verification results in failed authentication exchange."
alice asking to act as bob ("n,a=bob,") is authenticated - as alice. PLAIN refuses the
same request (`AuthConfigurationTests.Acting_as_somebody_else_is_refused`). Test:
`Asking_to_act_as_another_user_is_refused`;
`Naming_oneself_as_the_authorization_identity_is_authenticated` is the guard.

Fixed: as with PLAIN, one may name oneself, and nobody else.

### S-24
**Closed** in [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284)
(`be8520c4`). **"=2C" and "=3D" in the user name were not decoded**
(`ScramSha256AuthHandler.cs:97`, `:206`): the user is looked up as "a=3Db", not "a=b"; and
"n=a=b" finds the user "a=b". RFC 5802 §5.1, n: "The characters ',' or '=' in usernames
are sent as '=2C' and '=3D' respectively. If the server receives a username that contains
'=' not followed by either '2C' or '3D', then the server MUST fail the authentication."
Tests: `A_user_name_with_an_escaped_comma_or_equals_sign_is_authenticated` (two cases),
`A_user_name_with_an_unescaped_equals_sign_is_refused`.

Fixed: the saslname is decoded, "=2C" and "=3D" in either case, and any other "=" fails
the authentication.

### S-25
**Closed** in [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284)
(`be8520c4`). **A mandatory extension did not fail the authentication**
(`ScramSha256AuthHandler.cs:206`: attributes the handler does not know are passed over):
RFC 5802 §5.1, m: "its presence in a client or a server message MUST cause authentication
failure when the attribute is parsed by the other end." Test:
`A_mandatory_extension_fails_the_authentication`.

Fixed: m= fails the authentication, in the client-first-message and in the
client-final-message.

### S-26
**Closed** in [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284)
(`be8520c4`). **Passwords were not normalized before they were hashed**
(`ScramCredentialGenerator.cs:42`, `Encoding.UTF8.GetBytes(password)`): RFC 5802 §2.2:
SaltedPassword := Hi(Normalize(password), salt, i), "Normalize(str): Apply the SASLprep
profile [RFC4013] to the "str" string". A password set as "A" and a combining diaeresis is
stored as those code points; a client that normalizes, as the RFC has it, proves it knows
"Ä", and is refused. Test: `A_password_is_normalized_as_SASLprep_has_it`;
`An_ASCII_password_is_authenticated_normalized_or_not` is the guard.

Fixed: `SaslPrep` has RFC 4013 - mapping, NFKC, prohibited output, the bidirectional rules
-, and `ScramCredentialGenerator` and `FileUserStore`'s password check for PLAIN and LOGIN
normalize with it; a password SASLprep refuses is used as it is.

### S-27
**Closed** in [Vanaheimr/Hermod#285](https://github.com/Vanaheimr/Hermod/pull/285)
(`69b768a4`). **The TLS handshake never asked for a client certificate**
(`SMTPSession.cs:592`, `ClientCertificateRequired = false`): with it false, .NET's
SslStream sends no CertificateRequest, and a client sends a certificate only when asked
(RFC 8446 §4.3.2, §4.4.2; RFC 5246 §7.4.4, §7.4.6). So Hermod never has one: EXTERNAL,
which it offers once a client presented a certificate (`SmtpAuthManager.cs:71`) and lists
among its mechanisms, is never offered, and "AUTH EXTERNAL" is always 535. RFC 4422
Appendix A: EXTERNAL authenticates by "some external means" - here, the certificate whose
thumbprint is listed for an account (`FileUserStore`). Test:
`A_listed_client_certificate_authenticates_with_EXTERNAL`;
`An_unlisted_client_certificate_is_refused` and
`EXTERNAL_without_a_client_certificate_is_refused` are the guards.

Fixed: the handshake asks for a client certificate, and does not require one: a client
without it goes on without EXTERNAL.

### S-28
**Closed** in [Vanaheimr/Hermod#287](https://github.com/Vanaheimr/Hermod/pull/287)
(`cec3e841`). **There was no loop detection** (`SMTPSession.cs:1195`,
`ProcessReceivedMessageAsync`): nothing counts the Received fields of a message, or looks
at them at all; a message that has been through 150 hops is delivered, and relayed on. RFC
5321 §6.3: "Simple counting of the number of "Received:" header fields in a message has
proven to be an effective, although rarely optimal, method of detecting loops in mail
systems. SMTP servers using this technique SHOULD use a large rejection threshold,
normally at least 100 Received entries. Whatever mechanisms are used, servers MUST contain
provisions for detecting and stopping trivial loops." Two servers that forward to each
other - an alias, a smart host or an MX pointing back - pass the message back and forth
until it outgrows the size limit, a copy queued at every turn. RFC 3463 §3.5 has X.4.6,
"Routing loop detected", for the refusal. Tests:
`A_message_with_150_Received_fields_is_refused`,
`A_message_with_150_Received_fields_is_not_relayed`;
`A_message_with_50_Received_fields_is_delivered_and_relayed` is the guard.

Fixed: a message with more Received fields than `SMTPServerConfig.MaxReceivedFields`, 100
by default, is refused at the end of data with 554 5.4.6, neither stored nor queued.

### S-29
**Closed** in [Vanaheimr/Hermod#287](https://github.com/Vanaheimr/Hermod/pull/287)
(`cec3e841`). **There was no Return-Path at final delivery** (`SMTPSession.cs:1435`): the
message goes to the storage with this hop's trace fields on top and nothing above them;
the envelope sender reaches the storage as an argument only, and `FileMailStorage` writes
it as `X-Envelope-From` (`MailStorage/FileMailStorage.cs:47`). RFC 5321 §4.4: "When the
delivery SMTP server makes the "final delivery" of a message, it inserts a return-path
line at the beginning of the mail data. This use of return-path is required; mail systems
MUST support it." A Return-Path the client wrote into the message stays, and is the only
one the mailbox has: what reads it - a mail program answering with an MDN (RFC 8098 §2.1:
"Confirmation from the user MUST be obtained (or no MDN sent) if there is no Return-Path
header field"), a filter, a forwarder - takes the sender's word for where errors go. §4.4:
"exactly one return path SHOULD be present when the message is delivered", and "SMTP
servers making final delivery MAY remove Return-path header fields before adding their
own". Tests: `A_delivered_message_begins_with_the_Return_Path`,
`A_delivered_bounce_begins_with_an_empty_Return_Path`,
`A_Return_Path_in_the_message_is_not_the_one_delivered`,
`A_copy_with_an_Original_Recipient_begins_with_the_Return_Path`;
`A_relayed_message_gets_no_Return_Path` is the guard.

Fixed: every stored copy begins with "Return-Path: <reverse-path>" - "<>" for a bounce -
above its Original-Recipient and this hop's trace; the Return-Path fields the message came
with are removed; a relayed message gets none and keeps its own.

### S-30
**Closed** in [Vanaheimr/Hermod#287](https://github.com/Vanaheimr/Hermod/pull/287)
(`cec3e841`). **The EHLO argument went into Received unchecked** (`SMTPSession.cs:343`,
`:1690`): `HandleEhloAsync` takes any text for the client's name, and the Received field
writes it as the From-domain, in front of the TCP-info in parentheses. "EHLO
client.example (mail.trusted.example [203.0.113.5])" gives "Received: from client.example
(mail.trusted.example [203.0.113.5]) (unknown [127.0.0.1])": a reader of the trace, or a
filter, takes the first TCP-info for the connection's - an address the client chose. RFC
5321 §4.4: Extended-Domain = Domain / ( Domain FWS "(" TCP-info ")" ) / ( address-literal
FWS "(" TCP-info ")" ), and TCP-info is "Information derived by server from TCP connection
not client EHLO". §4.1.1.1: ehlo = "EHLO" SP ( Domain / address-literal ) CRLF; §4.1.4:
"If the EHLO command is not acceptable to the SMTP server, 501, 500, 502, or 550 failure
replies MUST be returned as appropriate." A "by" in the argument starts a By-domain of the
client's, a ";" ends the clauses, and the date after it is the client's too. Test:
`The_Received_line_names_the_address_of_the_connection` (three claims);
`The_Received_line_takes_an_address_literal_from_EHLO` is the guard.

Fixed: HELO and EHLO take one token - a name, with the underscores and final dot of names
in the wild, or an address literal - and anything else is 501; a name that is no Domain is
not the From-domain: the connection's address is, the name a comment.

### S-31
**Closed** in [Vanaheimr/Hermod#288](https://github.com/Vanaheimr/Hermod/pull/288)
(`cca86d1c`). **A source route was taken as part of the mailbox** (`SMTPSession.cs:686`,
`:800`, `ExtractDomain` at `:1731`): the path is whatever stands between "<" and ">", and
its domain whatever follows the first "@". "RCPT TO:<@relay.example:alice@hermod.test>" is
a recipient at the domain "relay.example:alice@hermod.test" - not local, so a relay
request: refused without AUTH, queued for that domain with it. RFC 5321 §4.1.2: A-d-l,
"the so-called "source route", MUST BE accepted, SHOULD NOT be generated, and SHOULD be
ignored"; §4.1.1.3: "Receiving systems MUST recognize source route syntax but SHOULD strip
off the source route specification and utilize the domain name associated with the mailbox
as if the source route had not been provided". In MAIL the route stays in the envelope
sender, where bounces go and where SPF looks for the domain. Tests:
`A_source_route_before_a_local_mailbox_is_ignored` (one hop, two hops),
`A_source_route_in_the_reverse_path_is_ignored`,
`A_source_route_before_a_remote_mailbox_is_ignored_or_refused` - refusing it is allowed
(§3.3: "MAY decline to support the relaying they imply").

Fixed: `SmtpPath` recognizes the route and drops it, in MAIL and in RCPT; a route without
its ":" is 501.

### S-32
**Closed** in [Vanaheimr/Hermod#288](https://github.com/Vanaheimr/Hermod/pull/288)
(`cca86d1c`). **A quoted local part was cut at the wrong place** (`SMTPSession.cs:686`,
`:800`, `:1731`): the path ends at the first ">", the domain begins after the first "@".
RFC 5321 §4.1.2: Local-part = Dot-string / Quoted-string, and qtextSMTP: "within a quoted
string, any ASCII graphic or space is permitted without blackslash-quoting except
double-quote and the backslash itself" - "@" and ">" among them. `RCPT
TO:<"alice@home"@hermod.test>` is a recipient at `home"@hermod.test`, a relay request; in
`RCPT TO:<"a>b"@hermod.test>` the path is `"a`, and the rest is taken for a parameter:
"501 5.5.4 Invalid parameter". A MAIL with such a reverse-path likewise. Tests:
`A_quoted_local_part_is_one_local_part` (an "@", a ">"),
`A_quoted_local_part_with_an_angle_bracket_is_a_reverse_path`,
`A_quoted_local_part_with_an_at_sign_is_relayed_to_its_domain`;
`A_quoted_local_part_with_a_space_is_a_local_recipient` is the guard.

Fixed: `SmtpPath` ends the path at the ">" after the mailbox, quoted-pairs taken as they
are, and the domain is what follows the local part - for the session, and for every
address it groups and checks.

### S-33
**Closed** in [Vanaheimr/Hermod#288](https://github.com/Vanaheimr/Hermod/pull/288)
(`cca86d1c`). **HELP and EXPN were unknown commands, VRFY without an argument was 252**
(`SMTPSession.cs:320` to `:328`): HELP and EXPN fall to the default, "500 5.5.1
Unrecognized command", and count as invalid commands; VRFY is 252 whatever follows it,
nothing included. RFC 5321 §4.1.1.8: "SMTP servers SHOULD support HELP without arguments";
§4.2.4: "502 SHOULD be used when the command is actually recognized by the SMTP server,
but not implemented. If the command is not recognized, code 500 SHOULD be returned"; §7.3:
"If a site disables these commands for security reasons, the SMTP server MUST return a 252
response". §4.1.1.6: vrfy = "VRFY" SP String CRLF. Tests:
`HELP_without_an_argument_is_answered_with_help`,
`EXPN_is_answered_as_a_command_that_is_known`,
`VRFY_without_an_argument_is_a_syntax_error`; `HELP_in_a_transaction_leaves_it_open` is
the guard.

Fixed: HELP is 214, with an argument or without, at any time; EXPN is 502; VRFY without
its string is 501.

### S-34
**Closed** in [Vanaheimr/Hermod#290](https://github.com/Vanaheimr/Hermod/pull/290)
(`8ac4ccb1`). **An ORCPT of the UTF-8 address type, in UTF-8, was refused**
(`ESMTPParameters.cs:217` to `:220`): ORCPT has to be xtext, ASCII only, also after "MAIL
FROM:<...> SMTPUTF8". RFC 6533 §3: "An SMTP server that advertises both the SMTPUTF8
extension [RFC6531] and the DSN extension [RFC3461] MUST accept a UTF-8 address type in
the ORCPT parameter including 8-bit UTF-8 characters" - utf-8-addr-unitext. Hermod
advertises both; "RCPT TO:<jörg@hermod.test> ORCPT=utf-8;jörg@hermod.test" is 501, and a
client that does as RFC 6533 says loses the recipient. Test:
`An_ORCPT_of_the_UTF_8_address_type_in_UTF_8_is_accepted`;
`An_ORCPT_of_the_UTF_8_address_type_in_ASCII_is_accepted` - utf-8-addr-xtext, "\x{F6}" -
is the guard.

Fixed: in an SMTPUTF8 transaction an ORCPT of the UTF-8 address type is utf-8-addr-unitext
- UTF-8 and "\x{HEXPOINT}"; in another one utf-8-addr-xtext, as before.

### S-35
**Closed** in [Vanaheimr/Hermod#294](https://github.com/Vanaheimr/Hermod/pull/294)
(`78d89917`). **A local domain in the other form was a relay request**
(`SMTPServerConfig.cs:247` to `:254`, `IsLocalDomain`): the recipient domain is compared
with `LocalDomains` as a string, case-insensitively, and nothing else. "bücher.test" and
"xn--bcher-kva.test" are one domain - its U-labels and its A-labels (RFC 5890 §2.3.2.1) -
and RFC 6531 §3.7 has the client write either: "When RFC 5321 specifies a domain name,
the internationalized domain name SHOULD be in U-label form if the SMTPUTF8 extension is
supported; otherwise, it SHOULD be in A-label form." A server configured with the
A-labels, as the domain is in the DNS, answers "RCPT TO:<alice@bücher.test>" of an
SMTPUTF8 transaction with "550 5.7.1 Relay access denied"; one configured with the
U-labels refuses the A-labels a client without SMTPUTF8 has to send. Mail for the
server's own domain is refused, by a client that does what the RFC says. Test:
`A_recipient_of_a_local_domain_in_either_form_is_local`, two cases; the third, the same
form on both sides, is the guard.

Fixed: a domain is local in either form, however `LocalDomains` writes it:
`Idna.SameDomain` compares A-labels, and a `LocalDomainCheck` is asked about the domain
as given, its A-labels and its U-labels.

### S-36
**Closed** in [Vanaheimr/Hermod#294](https://github.com/Vanaheimr/Hermod/pull/294)
(`78d89917`). **A server named in U-labels wrote them into its greeting and its reply to
EHLO** (`SMTPSession.cs:131`, `:366`): `config.Hostname` as it is, "220 mx.bücher.test
ESMTP" and "250-mx.bücher.test Hello" - octets above 127, written as Latin-1. RFC 6531
§3.7.1: "If the SMTPUTF8-aware SMTP server provides domain names in the EHLO response,
they MUST be in the form of LDH labels or A-labels", and the greeting comes before any
client could have said it takes UTF-8 (RFC 5321 §4.2: Greeting = "220 " ( Domain /
address-literal ), Domain the LDH grammar of §4.1.2). Test:
`The_server_names_itself_in_A_labels_in_its_greeting_and_its_reply_to_EHLO`.

Fixed: the server names itself by the A-labels of its `Hostname` - in the greeting, the
reply to EHLO, the 221, the 421 of a timeout and the "by" of the Received field.

### S-37
**Closed** in [Vanaheimr/Hermod#297](https://github.com/Vanaheimr/Hermod/pull/297)
(`7cf5dac1`). **The longest PLAIN response was "500 Line too long"**
(`SMTPSession.cs:135`, `ReadLineAsync(config.MaxCommandLineLength)` for every line, the
lines of an AUTH exchange included; `SMTPServerConfig.cs:100`, 1024 octets). RFC 4616 §2:
"Servers MUST be capable of accepting authzid, authcid, and passwd productions up to and
including 255 octets" - 767 octets of PLAIN message, 1024 of base64; RFC 4954 §4: "Note
that these [BASE64] strings can be much longer than normal SMTP commands. Clients and
servers MUST be able to handle the maximum encoded size of challenges and responses
generated by their supported authentication mechanisms. This requirement is independent
of any line length limitations the client or server may have in other parts of its
protocol implementation. (At the time of writing of this document, 12288 octets is
considered to be a sufficient line length limit for handling of deployed authentication
mechanisms.)" "AUTH PLAIN " and the 1024 octets are 1037 with CR LF, the response alone
after "334 " 1026: both are "500 5.5.6 Line too long", for credentials that are right.
Tests: `The_longest_PLAIN_initial_response_signs_in`,
`The_longest_PLAIN_response_after_the_challenge_signs_in`;
`A_long_identity_and_password_without_authzid_sign_in` - the same account, 684 octets of
base64 - is the guard.

Fixed: the session reads every line up to `SMTPServerConfig.MaxAuthLineLength`, 12288
octets as RFC 4954 §4 suggests, and holds a line that is neither an AUTH command nor a
line of its exchange to `MaxCommandLineLength`, as before.

### S-38
**Closed** in [Vanaheimr/Hermod#297](https://github.com/Vanaheimr/Hermod/pull/297)
(`7cf5dac1`). **Spaces and tabs in a SASL response were ignored, not refused**
(`AuthHandler.cs:60`, `Convert.FromBase64String`, which skips white space;
`SMTPSession.cs:441`, the initial response is all that follows the mechanism, spaces
included). RFC 4954 §4: "servers and clients MUST reject (and not ignore) any character
not explicitly allowed by the BASE64 alphabet, and MUST reject any sequence of BASE64
characters that contains the pad character ('=') anywhere other than the end of the
string"; its grammar has initial-response = base64 / "=", and AUTH one SP before it.
"AUTH PLAIN AGFsaWNl AGNvcnJl...", the same with a tab after the 334, or with a space at
the end, are 235. Test: `A_response_that_is_no_base64_is_refused`, four cases; a pad
character inside the response and a response without its pad characters, which
`Convert.FromBase64String` refuses already, are the guards.

Fixed: `SaslBase64.Decode` takes the alphabet in groups of four, the pad character at the
end only, "=" and the empty text as no octets; anything else is 501 5.5.2.

### S-39
**Closed** in [Vanaheimr/Hermod#297](https://github.com/Vanaheimr/Hermod/pull/297)
(`7cf5dac1`). **A line too long in an AUTH exchange left the exchange open**
(`SMTPSession.cs:142`: "500 5.5.6 Line too long", and `continue` - `_inAuthExchange`,
`:193`, stays set). RFC 4954 §4: "If, during an authentication exchange, the server
receives a line that is longer than the server's authentication buffer, the server fails
the AUTH command with the 500 reply." The AUTH command failed, the client goes on with a
command - and the server takes it for the next SASL response: "NOOP" is valid base64, and
is answered "535 5.7.8"; a MAIL is answered 501 and lost, a new AUTH counts as a failed
attempt. Test: `A_line_too_long_in_the_exchange_fails_the_AUTH_command`;
`A_cancelled_exchange_is_over` is the guard.

Fixed: the 500 5.5.6 ends the exchange; the next line is a command.

### S-40
**Closed** in [Vanaheimr/Hermod#297](https://github.com/Vanaheimr/Hermod/pull/297)
(`7cf5dac1`). **A user store that could not be asked was 535** (`PlainAuthHandler.cs:83`,
`LoginAuthHandler.cs:99`: any exception is "535 5.7.8 Authentication failed"). RFC 4954
§6: "454 4.7.0 Temporary authentication failure - This response to the AUTH command
indicates that the authentication failed due to a temporary server failure. The client
SHOULD NOT prompt the user for another password in this case"; 535 5.7.8 is "invalid or
insufficient authentication credentials". With the user database down, every client is
told its password is wrong: a mail program asks its user for another one, an application
gives up on credentials that are right, a fail2ban counts the failures - and the
`ConnectionTracker` does, `MaxAuthAttemptsPerIpPerHour`. Test:
`A_user_store_that_is_down_is_a_temporary_failure`, PLAIN and LOGIN.

Fixed: an exception of the user store is `AuthResult.TemporaryFailure`, "454 4.7.0
Temporary authentication failure", for PLAIN, LOGIN, SCRAM-SHA-256 and EXTERNAL - neither
counted as a failed attempt nor delayed.

### S-41
**Closed** in [Vanaheimr/Hermod#302](https://github.com/Vanaheimr/Hermod/pull/302)
(`a55c65eb`). **A server that was stopped closed every session without a word**
(`SMTPSession.cs:1977`: a read cancelled by `SMTPServer.Stop`, `SMTPServer.cs:445`, is
taken for a lost connection, and the session ends; no reply). RFC 5321 §3.8: "An SMTP
server MUST NOT intentionally close the connection under normal operational circumstances
(see Section 7.8) except: ... After detecting the need to shut down the SMTP service and
returning a 421 response code. This response code can be issued after the server receives
any command or, if necessary, asynchronously from command receipt"; and "An SMTP server
that is forcibly shut down via external means SHOULD attempt to send a line containing a
421 response code to the SMTP client before exiting". A client in the middle of a
transaction sees the connection drop, and cannot tell a server that went away from a
network that broke. Test: `A_server_that_shuts_down_says_421_before_it_closes` - after
the greeting, after EHLO, in a mail transaction, in the middle of DATA.

Fixed: a session the server stops says "421 4.3.2 ... Service shutting down, closing
connection" before it closes - in the middle of DATA or of a BDAT chunk too, and what was
not answered with 250 is not taken; not after QUIT or a timeout, which have had their
reply. A client that does not read holds the shutdown up for five seconds at most.

### S-42
**Closed** in [Vanaheimr/Hermod#302](https://github.com/Vanaheimr/Hermod/pull/302)
(`a55c65eb`). **A parameter that may be given once, given twice with the same value, was
taken** (`ESMTPParameters.cs:106`: a keyword given twice is refused only with two
different values, and MT-PRIORITY always). RFC 3461 §4.5: "The RET and ENVID parameters
MUST NOT appear more than once each in any single MAIL command. If more than one of
either of these parameters appears in a MAIL command, the ESMTP server SHOULD respond
with "501 syntax error in parameters or arguments"", and the same for NOTIFY and ORCPT on
RCPT; RFC 1870 §6: "Only one SIZE parameter may be specified in a single MAIL command".
"MAIL FROM:<...> RET=HDRS RET=HDRS" is 250. The rule that takes SMTPUTF8 twice -
CPython's smtplib adds one of its own next to its caller's - holds for every parameter.
Test: `A_parameter_given_twice_is_501` - RET, ENVID, SIZE, NOTIFY, ORCPT; guard:
`Each_parameter_once_is_taken`.

Fixed: RET, ENVID, SIZE, NOTIFY, ORCPT and MT-PRIORITY given a second time are "501 5.5.4
... given more than once", with the same value too; any other parameter given twice with
the same value - SMTPUTF8, BODY, which smtplib adds of its own - is still taken.

### S-43
**Closed** in [Vanaheimr/Hermod#308](https://github.com/Vanaheimr/Hermod/pull/308)
(`364c9cb8`). **An Authentication-Results field of this server's, brought along, was kept**
(`SMTPSession.cs:1430`: the server's own field goes above the message as it came;
nothing of the message's header is looked at). RFC 8601 §5: "any MTA conforming to this
specification MUST delete any discovered instance of this header field that claims, by
virtue of its authentication service identifier, to have been added within its trust
boundary but that did not come directly from another trusted MTA. For example, an MTA for
example.com receiving a message MUST delete or otherwise obscure any instance of this
header field bearing an authentication service identifier indicating that the header field
was added within example.com prior to adding its own header fields." A sender writes
"Authentication-Results: mx.hermod.test; dkim=pass header.d=bank.example; dmarc=pass
header.from=bank.example" into its message, and the mailbox holds two fields of
mx.hermod.test - the filter or MUA that trusts that authserv-id reads either. Test:
`A_forged_Authentication_Results_field_of_this_server_is_removed` - the authserv-id as it
is, in other case, with version 1.

Fixed: before the server adds its own field, it takes out of the header every
Authentication-Results field whose authserv-id is its name - compared as a domain name,
in any case, A-labels and U-labels alike, after a comment, quoted or not
(`AuthenticationResultsFields.WithoutForeign`). It trusts no other MTA to add fields in
its name. Fields of other ADMDs are passed on as they came.

### S-44
**Closed** in [Vanaheimr/Hermod#308](https://github.com/Vanaheimr/Hermod/pull/308)
(`364c9cb8`). **An Authentication-Results field of a version not supported was kept** (as S-43).
RFC 8601 §5: "An MTA SHOULD remove any instance of this header field bearing a version
(express or implied) that it does not support. However, an MTA MUST remove such a header
field if the SMTP connection [SMTP] relaying the message is not from a trusted internal
MTA" - and Hermod has no notion of one. Version 1 is the only one there is: "Authentication-
Results: mx.elsewhere.example 2; dmarc=pass header.from=bank.example" is delivered as it
came. Test: `An_Authentication_Results_field_of_a_version_not_supported_is_removed`.

Fixed: a field of any version but 1 is taken out with them.

### S-45
**Closed** in [Vanaheimr/Hermod#308](https://github.com/Vanaheimr/Hermod/pull/308)
(`364c9cb8`). **The SPF result named the local-part of the reverse-path** (`SMTPSession.cs:1740`:
"smtp.mailfrom=" and the whole reverse-path). RFC 8601 §2.7.2: "If the retrieved sender
policies used to evaluate SPF do not contain explicit provisions for authenticating the
local-part (see Section 3.4.1 of [MAIL]) of an address, the "pvalue" reported along with
results for this mechanism SHOULD NOT include the local-part or the following "@"
character"; §4: "an MTA adding this header field SHOULD NOT include any data that have not
been authenticated by the method(s) being applied". An SPF pass for spf-domain.test reads
"spf=pass smtp.mailfrom=alice@spf-domain.test" - as if alice had been authenticated. Test:
`The_SPF_result_names_the_domain_SPF_authenticated_not_the_local_part`.

Fixed: smtp.mailfrom is the domain of the reverse-path.

### S-46
**Closed** in [Vanaheimr/Hermod#308](https://github.com/Vanaheimr/Hermod/pull/308)
(`364c9cb8`). **An SMTPUTF8 transaction was received "with ESMTP"** (`SMTPSession.cs:1797`: the
protocol is ESMTP, with S for TLS and A for AUTH, whatever MAIL said). RFC 6531 §3.7.3:
"The protocol value of the 'WITH' clause when this extension is used is one of the SMTPUTF8
values specified in the "IANA Considerations" section of this document" - UTF8SMTP,
UTF8SMTPA, UTF8SMTPS, UTF8SMTPSA (§4.3); §3.1 item 11: "their use should be reflected in
the trace field WITH keywords as appropriate [RFC3848]". Test:
`An_SMTPUTF8_transaction_is_received_with_UTF8SMTP`; guard:
`A_transaction_without_SMTPUTF8_is_received_with_ESMTP`.

Fixed: "with UTF8SMTP", and with S and A as ESMTP has them.

### S-47
**Closed** in [Vanaheimr/Hermod#308](https://github.com/Vanaheimr/Hermod/pull/308)
(`364c9cb8`). **A server named in U-labels wrote A-labels into the Received field of an
SMTPUTF8 transaction** (`SMTPSession.cs:1815`: "by" `ServerName`, `:1971`: the A-labels of
the host name, always - S-36). RFC 6531 §3.7.3: "When an SMTPUTF8-aware SMTP server adds a
trace field to a message that was or will be transmitted with the SMTPUTF8 parameter
included in the MAIL commands, that server SHOULD use the U-label form for
internationalized domain names in the new trace field"; and only "If the messages that
include trace fields are sent ... without the SMTPUTF8 parameter included in the MAIL
commands, trace field values must conform to RFC 5321". Test:
`In_an_SMTPUTF8_transaction_the_server_names_itself_in_U_labels_in_the_Received_field`;
guard: `Without_SMTPUTF8_the_server_names_itself_in_A_labels_in_the_Received_field`.

Fixed: in the Received field and as the authserv-id of Authentication-Results the server
names itself in its U-labels for an SMTPUTF8 transaction, in its A-labels otherwise - the
authserv-id was the configured name as it stood, U-labels in every message.

### S-48
**Closed** in [Vanaheimr/Hermod#312](https://github.com/Vanaheimr/Hermod/pull/312)
(`fd7c323c`). **The default store writes what DNS says into the stored header as it is**
(`MailStorage/FileMailStorage.cs:45`: `AddHeader` appends name, ": ", value and CR LF;
`:58`: `X-SPF-Record` is the SPF record of the sender's domain, the TXT record as it came -
`DNSVerifier.cs:643` takes any record that begins with "v=spf1 " for one, and keeps it when
its syntax is wrong, as the permerror's record; `:60` and `:64`: `X-DKIM-Details`, `X-MX-Records`
likewise). RFC 5322 §2.2: "A field body MUST NOT include CR and LF except when used in
'folding' and 'unfolding'". A TXT record is octets, line breaks among them, and the SPF record
of the sender's domain is the sender's to publish: "v=spf1 -all<CR><LF>X-DMARC-Result: Pass"
makes the stored header say `X-DMARC-Result: None`, then `X-DMARC-Result: Pass` - a DMARC
pass the server never found, in the file whatever reads the store reads; a bare LF or a bare
CR does the same for a reader that takes it for a line end. And an empty line in the record
ends the header there: the message's own fields - From, Subject, the server's
Authentication-Results and Received - are body. `FileMailStorage` is the store of every
`SMTPServer` that is given none (`SMTPServer.cs:102`). Tests:
`A_line_break_in_a_DNS_record_makes_no_header_field_of_the_stored_message` - CR LF, LF, CR -,
`An_empty_line_in_a_DNS_record_does_not_end_the_stored_header`; guard:
`With_an_SPF_record_of_the_usual_kind_the_stored_header_is_whole`.

Fixed: a value goes into the header as a field body. Each run of control characters
in it - CR, LF, NEL and the others but HTAB - and of U+2028 and U+2029 is one space,
and a value whose line would be longer than 998 octets is folded before white space in
it (RFC 5322 §2.1.1); unfolded, it is the value again.

### S-49
**Closed** in [Vanaheimr/Hermod#312](https://github.com/Vanaheimr/Hermod/pull/312)
(`fd7c323c`). **The default store writes fields of its own before the Return-Path**
(`MailStorage/FileMailStorage.cs:47` to `:64`: `X-Envelope-From`, `X-Envelope-To`,
`X-Received-At` and the verification results go first, `:73`: the message after them).
RFC 5321 §4.4: "When the delivery SMTP server makes the 'final delivery' of a message, it
inserts a return-path line at the beginning of the mail data"; RFC 5322 §3.6: "the trace
header fields and resent header fields MUST NOT be reordered, and SHOULD be kept in blocks
prepended to the message". The message as the server hands it to the store begins with its
Return-Path (S-29); the stored file does not - a reader that takes the first line for where
bounces go, or the first fields for the trace block, reads the store's own. Tests:
`A_stored_message_begins_with_its_Return_Path`, `A_stored_bounce_begins_with_an_empty_Return_Path`.

Fixed: the store's fields go behind the Return-Path, a folded one too; first only in a
message that has none.

### S-50
**Closed** in [Vanaheimr/Hermod#312](https://github.com/Vanaheimr/Hermod/pull/312)
(`fd7c323c`). **A message whose Message-ID is too long for a file name cannot be stored**
(`MailStorage/FileMailStorage.cs:39` and `:40`: the file is named after the Message-ID, of
whatever length; a name of more than 255 characters is none NTFS or ext4 take, the write
throws, and `SMTPSession.cs:1554` answers 451). RFC 5322 §3.6.4: `msg-id = [CFWS] "<"
id-left "@" id-right ">" [CFWS]`, of no length of its own but the line's (§2.1.1); RFC 5321
§4.5.3.1: "To the maximum extent possible, implementation techniques that impose no limits
on the length of these objects should be used". A Message-ID of 300 characters - a valid
message - is refused with 451 at every try, until its sender gives up and bounces it.
Tests: `A_message_with_a_long_Message_ID_is_stored` - 300 and 900 characters; guard:
`Two_messages_with_one_Message_ID_are_both_stored`.

Fixed: a Message-ID of more than 100 octets names the file by its beginning - cut
between characters, not inside one - and 16 hex digits of the SHA-256 of the whole of
it, so that long Message-IDs that begin alike name files of their own; a shorter one
names it as before.

### S-51
**Closed** in [Vanaheimr/Hermod#335](https://github.com/Vanaheimr/Hermod/pull/335) (`c7233d17`). **An EHLO name or a path longer than RFC 5321 allows was taken, and written into
a header line of more than 998 characters** (`SMTPSession.cs:397`, `:406`: an EHLO or HELO
argument of any length is taken; `:764`, `:877`: so is a path; `:1808`: the Received field
names the EHLO name, `:1824` the one recipient, `:1528` the Return-Path the reverse-path,
each on one line; `DsnGenerator.cs:312`: so does Final-Recipient). RFC 5321 §4.5.3.1.2: "The
maximum total length of a domain name or number is 255 octets"; §4.5.3.1.1, §4.5.3.1.3: a
local-part of 64 octets, a path of 256; §4.5.3.1: "Objects larger than these sizes SHOULD be
avoided when possible", clients "MUST be prepared for a server to reject them" - §4.5.3.1.9,
"501 Path too long". Taken all the same, within the command line of 1024 octets, they make
lines that RFC 5322 §2.1.1 forbids: "Each line of characters MUST be no more than 998
characters". An EHLO name of 1000 octets is a Received line of 1037 characters, a reverse-path
of 997 a Return-Path of 1010, a forward-path of 1004 a line of 1010 in Received, and a
forward-path of 989 with NOTIFY=SUCCESS a Final-Recipient of 1012 in the delivered DSN. Tests:
`No_header_line_of_more_than_998_characters` - the EHLO name, the reverse-path, the
forward-path, the delivered DSN; refused is as good as written within the limit; guard:
`Names_and_paths_of_the_sizes_RFC_5321_asks_for_are_taken` - an EHLO name of 255 octets, a
reverse-path of 256, a local-part of 64.

Fixed: a reverse-path of more than 256 octets is answered with `501 5.1.7 Path too long`, a
forward-path with `501 5.1.3 Path too long` (§4.5.3.1.9) - "<", the mailbox and ">", in
octets of UTF-8 -, and an EHLO or HELO argument of more than 255 octets with 501; what is
taken fits in the lines it goes into.

### S-52
**Closed** in [Vanaheimr/Hermod#335](https://github.com/Vanaheimr/Hermod/pull/335) (`c7233d17`). **EHLO and HELO repeated an argument longer than a domain name in a reply line of
more than 512 octets** (`SMTPSession.cs:403`: "Hello" and the HELO argument; `:415`: the first
line of the EHLO reply, the same). RFC 5321 §4.5.3.1.5: "The maximum total length of a reply
line including the reply code and the <CRLF> is 512 octets. More information may be conveyed
through multiple-line replies" - all a client has to be able to read (§4.5.3.1). An argument
of 1000 octets, which is no domain name (§4.5.3.1.2: 255 octets), is answered with a reply
line of 1027 octets to EHLO, of 1033 to HELO. Tests:
`No_reply_line_of_more_than_512_octets` - EHLO, HELO; guard: the EHLO name of 255 octets in
`Names_and_paths_of_the_sizes_RFC_5321_asks_for_are_taken`.

Fixed: an EHLO or HELO argument of more than 255 octets is answered with 501 - no enhanced
status code, as RFC 2034 §4 has it for HELO and EHLO - and greets nobody; one of 255 octets
is greeted on a line of less than 512.

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

The ninth round's SCRAM tests (`SubmissionClientTests.Scram.cs`) run the client against a
scripted SCRAM-SHA-256 server (`SmtpServerScript.ScramPassword`, `ScramEnding`). Covered
without a finding: a server-final-message as a 334 is checked and the message sent; a
wrong ServerSignature stops the client before MAIL.

### C-12
**Closed** in [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284)
(`be8520c4`). **A 235 without the server-final-message was taken as success**
(`SMTPSubmissionClient.cs:639` to `:689`): the ServerSignature is checked when a 334
brings it, and a 235 that comes at once is success. RFC 5802 §5: "the client authenticates
the server by computing the ServerSignature and comparing it to the value sent by the
server. If the two are different, the client MUST consider the authentication exchange to
be unsuccessful" - and a server that sends none has proved nothing; in SMTP the
server-final-message is a 334 (RFC 4422 §3, RFC 4954 §4). A server that does not know the
password - one in the middle - answers the client-final-message with 235, and gets the
message. Test: `Scram_without_the_servers_signature_does_not_authenticate`;
`Scram_with_the_servers_signature_authenticates` and
`Scram_with_a_wrong_server_signature_does_not_authenticate` are the guards.

Fixed: a 235 without the server-final-message is `InvalidLogin`, and a wrong v= cancels
the exchange with "*"; v= in the 235 text, as Hermod servers had it before, counts when
its signature holds.

### C-13
**Closed** in [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284)
(`be8520c4`). **The client did not normalize the password**
(`SMTPSubmissionClient.cs:667`, `ScramSha256Client.cs:40`; `SaslPrep` at `:694` escapes
"=" and "," only): RFC 5802 §2.2: SaltedPassword := Hi(Normalize(password), salt, i),
Normalize being SASLprep (RFC 4013, NFKC among it). A password typed as "A" and a
combining diaeresis is not the "Äpfelbaum" the server stores, and the client is refused.
Test: `Scram_normalizes_the_password_as_SASLprep_has_it`.

Fixed: `ScramSha256Client.SaltedPassword` normalizes with `SaslPrep`.

### C-14
**Closed** in [Vanaheimr/Hermod#289](https://github.com/Vanaheimr/Hermod/pull/289)
(`407ac0c9`). **The client waited 30 seconds for the reply to the end of data**
(`SMTPSubmissionClient.cs:200`, `CommandTimeout ?? TimeSpan.FromSeconds(30)`): one timeout
for every reply, the one after the message included. RFC 5321 §4.5.3.2: "the minimum
per-command timeout values SHOULD be as follows" - 5 minutes for the greeting, MAIL and
RCPT, 2 for DATA, 3 for each data block, and §4.5.3.2.6, DATA Termination: 10 minutes, "A
spurious timeout at this point would be very wasteful and would typically result in
delivery of multiple copies of the message, since it has been successfully sent and the
server has accepted responsibility for delivery." A server that takes 31 seconds to answer
has the message; the client reports `Timeout`, sends it again on its next try, and it
arrives twice. Test:
`A_server_that_takes_half_a_minute_for_the_end_of_data_is_waited_for`.

Fixed: the command timeout is 5 minutes by default, and the reply to "." and to BDAT LAST
has `DataTerminationTimeout`, 10 minutes.

### C-15
**Closed** in [Vanaheimr/Hermod#293](https://github.com/Vanaheimr/Hermod/pull/293)
(`bf31d448`). **A reply code was read by its exact value**
(`SMTPSubmissionClient.cs:1436`, `:1451`: MAIL; `:1399`, `IsAccepted`: RCPT is 250 or
251; `:1499`: DATA is 354; `:1489`, `:1512`: the end of data is 250). RFC 5321 §4.2.1: "a
sender-SMTP MUST be prepared to handle codes not specified in this document and MUST do
so by interpreting the first digit only" - 2yz is "Positive Completion", 3yz "Positive
Intermediate". A 252 to MAIL ends the attempt with `ExceptionOccurred`; a 252 to RCPT is
a refusal; a 350 to DATA is an error. Worst, a 251 to the end of data is reported as a
failure, though the server has taken the message (§6.1): the application is told it
failed, and if it sends it again, it arrives twice. Test:
`Another_positive_code_is_read_by_its_first_digit`, five cases (one without PIPELINING);
`A_code_without_text_is_read`, four cases, is the guard (§4.2: "clients that do not
receive it SHOULD be prepared to process the code alone").

Fixed: every reply is read by its first digit - a 2yz for the greeting, EHLO, MAIL, RCPT
and the end of data, a 3yz for DATA and AUTH; `SMTPRecipientResult.Accepted` is any 2yz.

### C-16
**Closed** in [Vanaheimr/Hermod#294](https://github.com/Vanaheimr/Hermod/pull/294)
(`78d89917`). **A client named in U-labels said EHLO with them**
(`SMTPSubmissionClient.cs:1015`, `:1115`: "EHLO " + `EhloArgument`, the local domain as
it was given): "EHLO client.bücher.test", in UTF-8. RFC 6531 §3.7.1: "Since the
SMTPUTF8-aware SMTP client cannot know whether the SMTP server supports SMTPUTF8 until
after it receives the response to the EHLO, the SMTPUTF8-aware SMTP client MUST send only
ASCII (LDH label or A-label [RFC5890]) domains in the EHLO command." A server that checks
the argument refuses it, and the HELO name SPF checks (RFC 7208 §2.3) is no name in the
DNS. Test: `The_client_says_EHLO_with_its_name_in_A_labels`.

Fixed: `EhloArgument` is the A-labels of `LocalDomain`, in EHLO and in HELO.

### C-17
**Closed** in [Vanaheimr/Hermod#298](https://github.com/Vanaheimr/Hermod/pull/298)
(`e93c6ef2`). **AUTH PLAIN went with its initial response, however long**
(`SMTPSubmissionClient.cs:742`, `AuthPlainAsync`). RFC 4954 §4: "If use of the initial
response argument would cause the AUTH command to exceed this length, the client MUST NOT
use the initial response parameter (and instead proceed as defined in Section 5.1 of
[SASL])" - 512 octets with CR LF (RFC 5321 §4.5.3.1.4). A password of 400 octets makes an
AUTH line of 553. Test: `A_long_password_goes_without_an_initial_response`.

Fixed: when "AUTH PLAIN" and the response would pass 512 octets with CR LF, the response
follows the empty 334 challenge.

### C-18
**Closed** in [Vanaheimr/Hermod#298](https://github.com/Vanaheimr/Hermod/pull/298)
(`e93c6ef2`). **A SCRAM challenge that is no base64 was not cancelled**
(`SMTPSubmissionClient.cs:666`, `Convert.FromBase64String` of the server-first-message,
which throws on what is no base64 and skips white space; CRAM-MD5 at `:768` likewise).
RFC 4954 §4: "If the client cannot BASE64 decode any of the server's challenges, it MUST
cancel the authentication using the "*" response. In particular, servers and clients MUST
reject (and not ignore) any character not explicitly allowed by the BASE64 alphabet". The
FormatException ends the attempt with `ExceptionOccurred`, and the QUIT the client sends
next is what the server reads as the response to its challenge; a challenge with a space
in it is decoded as if it had none. Test: `A_challenge_that_is_no_base64_is_cancelled`,
two cases.

Fixed: the server-first-message of SCRAM-SHA-256 and the CRAM-MD5 challenge go through
`SaslBase64.Decode`, and what is no base64 is answered "*".

### C-19
**Closed** in [Vanaheimr/Hermod#305](https://github.com/Vanaheimr/Hermod/pull/305)
(`b25dfc4d`). **The submission client gave a REQUIRETLS message to a server without
REQUIRETLS** (`SMTPSubmissionClient.cs:1330`: a REQUIRETLS envelope asks for TLS, and
nothing else; `:1399`: the REQUIRETLS option goes on MAIL when the server offers it, and is
left out when it does not). RFC 8689 §4.3: "If TLS is to be required, it MUST do so by
negotiating STARTTLS and REQUIRETLS and including the REQUIRETLS option on the MAIL FROM
command, as is done for message relay"; §2: "Following the negotiation of STARTTLS, the
SMTP server MUST advertise in the subsequent EHLO response that it supports REQUIRETLS".
A server without REQUIRETLS takes the message inside TLS and relays it as it likes - in
cleartext, if its next hop offers no STARTTLS -, and the caller is told `ok`. Test:
`A_REQUIRETLS_message_goes_to_no_server_that_does_not_offer_REQUIRETLS`; guard:
`A_REQUIRETLS_message_goes_with_REQUIRETLS_on_MAIL`.

Fixed: a message that requires TLS goes to no server that does not offer REQUIRETLS inside
TLS - `failed`, and no MAIL; to one that does, with REQUIRETLS on MAIL.

### C-20
**Closed** in [Vanaheimr/Hermod#309](https://github.com/Vanaheimr/Hermod/pull/309)
(`330f192e`). **The submission client sent an internationalized message to a server without
SMTPUTF8** (`SMTPSubmissionClient.cs:1388`: SMTPUTF8 goes on MAIL when the server offers it
and the message needs it - and when the server does not, the message goes all the same,
without it). RFC 6531 §3.2: "If the SMTPUTF8 SMTP extension is not offered by the SMTP
server, the SMTPUTF8-aware SMTP client MUST NOT transmit an internationalized email address
and MUST NOT transmit a mail message containing internationalized mail headers"; §3.5: "An
SMTPUTF8-aware SMTP client MUST NOT send an internationalized message to an SMTP server that
does not support SMTPUTF8". "RCPT TO:<jörg@scripted.test>" goes in UTF-8 to a server that
never said it reads it - and so do "MAIL FROM:<jörg@client.example>", "RCPT
TO:<you@bücher.test>" (A-labels are "not considered to be internationalized", U-labels are)
and "Subject: Grüße aus Köln". Test: `No_server_without_SMTPUTF8_gets_an_internationalized_message`
- a recipient and a sender with a UTF-8 local-part, a recipient in U-labels, a Subject in
UTF-8; guard: `An_internationalized_message_goes_with_SMTPUTF8_to_a_server_that_offers_it`.

Fixed: a message that needs SMTPUTF8 - UTF-8 in an envelope address, a local-part or a
domain in U-labels, or in the header - goes to no server that does not offer it. It is a
permanent failure, `MailSentStatus.SmtpUtf8NotSupported`, decided before MAIL, and the
session ends with QUIT; there is no downgrade, which would break DKIM signatures over the
header.

### C-21
**Closed** in [Vanaheimr/Hermod#309](https://github.com/Vanaheimr/Hermod/pull/309)
(`330f192e`). **The submission client asked for SMTPUTF8 for an 8-bit body** (`SMTPSubmissionClient.cs:636`:
a message needs SMTPUTF8 when any character of it, the body's included, is not ASCII). RFC
6531 §3.4: "If the SMTPUTF8-aware SMTP client is aware that neither the envelope nor the
message being sent requires any of the SMTPUTF8 extension capabilities, it SHOULD NOT supply
the SMTPUTF8 parameter with the MAIL command"; §3.6 - an 8-bit body is BODY=8BITMIME's (RFC
6152). A message with an ASCII envelope and header and "Grüße aus Köln" in its UTF-8 body
goes with "BODY=8BITMIME SMTPUTF8"; a fix of C-20 that kept this test would refuse it to
every server without SMTPUTF8. Test: `An_8bit_body_alone_goes_without_SMTPUTF8`; guard:
`An_8bit_body_alone_goes_to_a_server_without_SMTPUTF8`.

Fixed: a message needs SMTPUTF8 for its envelope and its header section, not for its
body; an 8-bit body alone goes with BODY=8BITMIME, to a server without SMTPUTF8 too.

### C-22
**Closed** in [Vanaheimr/Hermod#311](https://github.com/Vanaheimr/Hermod/pull/311)
(`65a80bfd`). **ENVID went on MAIL as the caller gave it** (`DsnCommands.cs:67`: `ENVID={dsn.EnvId}`,
for the submission client, `SMTPSubmissionClient.cs:1429`, and for the relay,
`SMTPOutboundClient.cs:848`, when an application hands it a message by
`MailSender.SendDirectAsync`). RFC 3461 §4: "the esmtp-values for these parameters are
encoded as 'xtext'"; §4.4: "envid-parameter = 'ENVID=' xtext", "The ENVID parameter MAY be
up to 100 characters in length", and "the value of the ENVID parameter prior to encoding as
'xtext' MUST consist entirely of printable (graphic and white space) characters from the
US-ASCII repertoire". "order 42" goes as "ENVID=order 42" - "42" a parameter of its own, which
a server refuses -, "batch=7" as "ENVID=batch=7", which no esmtp-value is, "QQ+314159" as
"ENVID=QQ+314159", which decodes to "QQ14159"; 101 characters go as they are. And an
identifier with CR LF in it ends the MAIL command there: "x\r\nRCPT TO:<intruder@evil.test>"
gives the server a RCPT of its own, and the message a recipient its sender did not name - an
application that takes the identifier from its input lets that input add recipients. The
queue (`MailSender.SendAsync`) takes the same value into `QueuedMail.EnvId`, which is the
received xtext otherwise. Tests: `ENVID_goes_as_xtext` - a space, "=", "+" -,
`An_ENVID_with_a_line_break_is_no_command_of_its_own`, `No_ENVID_goes_longer_than_100_characters`;
for the relay `The_relay_gives_ENVID_as_xtext`, `An_ENVID_with_a_line_break_is_no_command_of_the_relay`;
guard: `An_ENVID_of_xchars_goes_as_it_is`.

Fixed: `DsnParameters.EnvId` is the identifier itself, and goes on MAIL as xtext. One that
cannot be an ENVID - empty, a character that is not printable US-ASCII, more than 100
characters as xtext - is refused before anything goes out: by the submission client as
`MailSentStatus.InvalidEnvelopeId`, before MAIL; by `MailSender.SendDirectAsync` as a
permanent failure for every recipient domain; by `MailSender.SendAsync` and `Queue` with an
`ArgumentException`. The queue keeps the xtext, and an ENVID received with a message is
relayed as it came (§5.2.1 (a): "with the same value").

### C-23
**Closed** in [Vanaheimr/Hermod#311](https://github.com/Vanaheimr/Hermod/pull/311)
(`65a80bfd`). **RET without NOTIFY and ENVID was left out** (`DsnParameters.cs:44`: a DSN is
"requested" with a NOTIFY other than NEVER or an ENVID; `DsnCommands.cs:56`: otherwise
MAIL goes without RET). RFC 3461 §4.3: "The RET esmtp-keyword on the extended MAIL command
specifies whether or not the message should be included in any failed DSN issued for this
message transmission"; §4.1: "the absence of a NOTIFY parameter in a RCPT command may be
interpreted as either NOTIFY=FAILURE or NOTIFY=FAILURE,DELAY" - a failed DSN comes without
NOTIFY too. A caller who asks for `DsnRet.Hdrs` alone, to keep the body out of a bounce,
gets it back whole if the server returns full messages. Tests: `RET_goes_without_NOTIFY_and_ENVID`,
for the relay `The_relay_gives_RET_without_NOTIFY_and_ENVID`; guard: `RET_goes_with_NOTIFY`.

Fixed: RET is a request of its own; MAIL has it whenever it was given and the server
offers DSN.

### C-24
**Closed** in [Vanaheimr/Hermod#311](https://github.com/Vanaheimr/Hermod/pull/311)
(`65a80bfd`). **NOTIFY=NEVER could not be asked for** (`DsnParameters.cs:44` and
`DsnCommands.cs:79`: `DsnNotify.Never` is no request, and RCPT goes without NOTIFY;
`DsnCommands.FormatNotify` writes "NEVER", but is never given it). RFC 3461 §4.1: "A NOTIFY
parameter value of 'NEVER' requests that a DSN not be returned to the sender under any
conditions" - and without NOTIFY the server sends the failed ones. A caller that asks for no
DSN at all - an automatic sender, whose bounces nobody reads - gets them all the same.
Tests: `NOTIFY_NEVER_goes_on_RCPT`, for the relay `The_relay_gives_NOTIFY_NEVER`; guard:
`A_message_that_asks_for_no_DSN_goes_without_DSN_parameters` - the default asks for
nothing, and goes without NOTIFY.

Fixed: `DsnParameters.Notify` is nullable - null is no NOTIFY, the server's default;
`DsnNotify.Never` goes as NOTIFY=NEVER on every RCPT. A queued message keeps an explicit
NEVER with each recipient, so the queue's own meaning of a message-wide Never, none given,
stays.

### C-25
**Closed** in [Vanaheimr/Hermod#331](https://github.com/Vanaheimr/Hermod/pull/331) (`cd22515f`). **Binary data went as BODY=8BITMIME to a server that offers BINARYMIME**
(`SMTPSubmissionClient/SMTPSubmissionClient.cs:1426`: a server that offers 8BITMIME is given
BODY=8BITMIME, whatever the message; `:1428`: BODY=BINARYMIME only to one that does not).
RFC 3030 §3: binary data is BODY=BINARYMIME - "The BINARYMIME service extension can only be
used with the "CHUNKING" service extension" -, and a server that takes it "agrees to preserve
all bits in each octet passed using the BDAT command"; RFC 6152 §3: 8BITMIME "DOES NOT
provide a means of transferring an object with the BINARY content-transfer-encoding". A
message with Content-Transfer-Encoding: binary - a line of 1200 octets, a NUL - goes as BDAT,
but declared 8-bit text: the server is never told that every octet is to be kept as it is.
Tests: `Binary_data_goes_as_BODY_BINARYMIME` - a line of 1200 octets, a NUL; guard:
`Eight_bit_text_goes_to_a_server_with_BINARYMIME`.

Fixed: binary data - a line of more than 998 octets, a NUL, `MessageOctets.IsBinary` - goes
as BDAT with BODY=BINARYMIME to a server that offers BINARYMIME and CHUNKING. 8-bit text
goes as BODY=8BITMIME, as before.

### C-26
**Closed** in [Vanaheimr/Hermod#331](https://github.com/Vanaheimr/Hermod/pull/331) (`cd22515f`). **Binary data went to a server without BINARYMIME**
(`SMTPSubmissionClient/SMTPSubmissionClient.cs:1374` to `:1376`: only octets above 127 are
looked for - not the length of a line, not a NUL; `:1570`: DATA, `:1548`: BDAT, either way).
RFC 3030 §3: to a server that does not offer BINARYMIME "the sender-SMTP MUST NOT, under any
circumstances, send binary data" - it converts the message, or "may treat this as a permanent
error"; RFC 2045 §2.7 and §2.8: 7bit and 8bit data are "relatively short lines with 998 octets or
less between CRLF line separation sequences", and no NULs; §2.9: binary data is "data where
any sequence of octets whatsoever is allowed". A line of 1200 octets, or a NUL, goes to a server that offers 8BITMIME
and no BINARYMIME, declared BODY=8BITMIME. A server that keeps to its 1000 octets a line (RFC
5321 §4.5.3.1.6) refuses the message or breaks the line; a NUL ends a C string. Tests:
`Binary_data_is_not_sent_to_a_server_without_BINARYMIME` - 8BITMIME alone, CHUNKING without
BINARYMIME, each with a line of 1200 octets and with a NUL; guard:
`A_line_of_998_octets_is_no_binary_data`.

Fixed: to a server that does not offer BINARYMIME and CHUNKING, binary data is not sent -
`MailSentStatus.BinaryNotSupported`, decided before MAIL. There is no conversion, which
would break the signatures over the content.

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

The eighth round's routing tests (`OutboundClientTests.Routing.cs`) deliver through MX records of the test's DNS. The client connects to MX hosts on port 25, which no test can listen on; what it does is seen in its DNS queries - it asks for the addresses of a host when it is about to connect to it, and only then. Covered without a finding: a domain without MX records is its own MX.

### O-9
**Closed** in [Vanaheimr/Hermod#280](https://github.com/Vanaheimr/Hermod/pull/280)
(`570cb059`). **A temporary error of the MX lookup sent the message to the domain's own
address** (`SMTPOutboundClient.cs:162`, `:793` to `:813`, `:175` to `:179`):
`ResolveMxAsync` catches every error and returns no MX records, which the caller takes for
a domain without MX: the implicit MX, the domain's own address. RFC 5321 §5.1: "If a
temporary error is returned, the message MUST be queued and retried later"; the implicit
MX "applies only if there are no MX records present". A SERVFAIL or a timeout of the MX
lookup sends the mail to whatever the domain's name points at - a web server, or one that
takes mail it should not. Test: `A_temporary_error_of_the_MX_lookup_queues_the_message`,
two cases; `A_domain_without_MX_records_is_its_own_MX` is the guard.

Fixed: A failed MX lookup - an RCODE other than 0 or 3, a timeout, an exception - is
`TempFail` 451 4.4.3; the implicit MX is for an answer without MX records only.

### O-10
**Closed** in [Vanaheimr/Hermod#280](https://github.com/Vanaheimr/Hermod/pull/280)
(`570cb059`). **A domain that did not exist, or whose MX hosts did not, was retried**
(`:175` to `:179`, `:253` to `:268`): an NXDOMAIN is "no MX records", the implicit MX has
no address, and the delivery ends `TempFail`, "All MX hosts unreachable" - as does a
domain whose only MX host does not exist. RFC 5321 §5.1: "If a non-existent domain error
is returned, this situation MUST be reported as an error"; "If MX records are present, but
none of them are usable, or the implicit MX is unusable, this situation MUST be reported
as an error." The sender of a mistyped address learns of it when the queue gives up, days
later, not at once - RFC 7505 §4.1 makes the same point for the null MX, which Hermod
bounces at once. Test: `A_domain_that_cannot_be_reached_is_a_permanent_failure`, two
cases.

Fixed: NXDOMAIN is `PermFail` 550 5.1.2. A host without an address has its A and AAAA
lookups asked once more: when both answered without a record or with NXDOMAIN, it is
unusable, and when every MX host is - or is not public - the delivery is `PermFail` 550
5.4.4; a lookup that failed still means `TempFail`.

### O-11
**Closed** in [Vanaheimr/Hermod#280](https://github.com/Vanaheimr/Hermod/pull/280)
(`570cb059`). **MX hosts of the same preference were always tried in the order of the
answer** (`:207`, `OrderBy`, a stable sort): RFC 5321 §5.1: "If there are multiple
destinations with the same preference and there is no clear reason to favor one (e.g., by
recognition of an easily reached address), then the sender-SMTP MUST randomize them to
spread the load across multiple mail exchangers for a specific organization." Test:
`MX_hosts_of_the_same_preference_are_tried_in_random_order` - a.route.test first in each
of sixteen deliveries.

Fixed: sorted by preference and, within one, at random.

### O-12
**Closed** in [Vanaheimr/Hermod#280](https://github.com/Vanaheimr/Hermod/pull/280)
(`570cb059`). **The relay sent to itself, and to MX hosts behind itself** (`:207`): the MX
list is not looked at for the relay's own name. RFC 5321 §5.1: the relay "MUST then
inspect the list for any of the names or addresses by which it might be known in mail
transactions. If a matching record is found, all records at that preference level and
higher-numbered ones MUST be discarded from consideration. If there are no records left at
that point, it is an error condition, and the message MUST be returned as undeliverable."
A Hermod that is a backup MX of a domain hands the message to itself, or to backups behind
itself, instead of only to the better MX hosts; one that a domain's MX points at by
mistake loops. Test: `The_relay_does_not_send_to_itself_or_behind_itself`, three cases:
its name the only MX, the best MX with a backup behind it, a backup behind a better one.

Fixed: MX records naming `LocalHostname` drop their preference level and all higher ones;
with none left, `PermFail` 550 5.4.6.

### O-13
**Closed** in [Vanaheimr/Hermod#289](https://github.com/Vanaheimr/Hermod/pull/289)
(`407ac0c9`). **The relay waited 60 seconds for the reply to the end of data**
(`SmtpOutboundConfig.cs:38`, `ReadTimeoutMs = 60_000`, for every reply): RFC 5321
§4.5.3.2: "the minimum per-command timeout values SHOULD be as follows" - 5 minutes for
the greeting, MAIL and RCPT, 2 for DATA, 3 for each data block, and §4.5.3.2.6, DATA
Termination: 10 minutes, "A spurious timeout at this point would be very wasteful and
would typically result in delivery of multiple copies of the message, since it has been
successfully sent and the server has accepted responsibility for delivery." A next hop
that takes 61 seconds - a content filter, a slow disk - has the message; Hermod counts a
temporary failure and sends it again at the next retry. Test:
`A_next_hop_that_takes_a_minute_for_the_end_of_data_is_waited_for`.

Fixed: `ReadTimeoutMs` is 5 minutes, `WriteTimeoutMs` 3 minutes for each block of 64 KiB,
and the reply to the end of data has `DataTerminationTimeoutMs`, 10 minutes.

### O-14
**Closed** in [Vanaheimr/Hermod#290](https://github.com/Vanaheimr/Hermod/pull/290)
(`8ac4ccb1`). **The ORCPT the relay wrote was no xtext** (`DsnCommands.cs:76` to `:96`,
both `RcptToParams`): for a relayed recipient that came without ORCPT it writes
"ORCPT=rfc822;" and the address as it is, to every next hop that offers DSN, NOTIFY or
not; for a message of Hermod's own with a DSN request likewise. RFC 3461 §4.2:
original-recipient-address = addr-type ";" xtext; §4: xchar is "!" to "~" except "+" and
"=", which are "+2B" and "+3D". So "you+tag@sink.example" - an address with a tag, as
millions are - goes out as "ORCPT=rfc822;you+tag@sink.example", and Postfix answers "501
5.5.4 Error: Bad ORCPT parameter syntax": the recipient is refused, the message bounces.
Tests: `The_ORCPT_the_relay_writes_is_xtext` ("+", "="),
`The_ORCPT_of_an_own_message_is_xtext`, and through a real Postfix
`A_recipient_with_a_plus_reaches_the_next_hop_through_Postfix_with_DSN` (interop);
`A_received_ORCPT_is_relayed_as_it_came` is the guard.

Fixed: `DsnCommands.OriginalRecipientOf` writes an ASCII address as "rfc822;" and its
xtext, one with UTF-8 in it as "utf-8;" with "\x{HEXPOINT}" for what QCHAR is not - for
the UTF-8 too unless the transaction is SMTPUTF8; a received ORCPT goes on as it came, its
UTF-8 escaped for a transaction that is not SMTPUTF8.

### O-15
**Closed** in [Vanaheimr/Hermod#293](https://github.com/Vanaheimr/Hermod/pull/293)
(`bf31d448`). **A reply code was read by its exact value** (`SMTPOutboundClient.cs:688`:
MAIL is 250, `:729`: DATA is 354, and anything else goes to `ParseResponse`, `:1040`,
which reads the first digit). RFC 5321 §4.2.1: "a sender-SMTP MUST be prepared to handle
codes not specified in this document and MUST do so by interpreting the first digit
only." So a 252 to MAIL - a positive completion, "proceed as planned" - leaves the
transaction, and `ParseResponse` turns it into a `Success`: no RCPT, no DATA, QUIT, and
the queue marks the message delivered. The message is lost, and nobody learns of it. A
350 to DATA is a temporary failure, the message sent again and again until it is given up
on. RCPT and the end of data are read by the first digit already. Tests:
`MAIL_answered_with_another_2yz_goes_on_to_the_message`,
`DATA_answered_with_another_3yz_sends_the_message`;
`RCPT_answered_with_another_2yz_accepts_the_recipient`,
`The_end_of_data_answered_with_another_2yz_is_a_delivery` and
`A_code_without_text_is_read` (four cases, §4.2) are the guards.

Fixed: the greeting, EHLO, STARTTLS, MAIL, DATA and AUTH are read by their first digit; a
reply of the wrong kind - a 3yz to MAIL, a 2yz to DATA - is a refusal, permanent if it is
5yz and temporary otherwise, and never a delivery.

### O-16
**Closed** in [Vanaheimr/Hermod#293](https://github.com/Vanaheimr/Hermod/pull/293)
(`bf31d448`). **552 to RCPT bounced the recipient** (`SendResult.cs:48` to `:53`,
`RecipientOutcome.Status`: 5yz is `PermFail`, and `QueueProcessor` bounces it). RFC 5321
§4.5.3.1.10: "RFC 821 [1] incorrectly listed the error where an SMTP server exhausts its
implementation limit on the number of RCPT commands ("too many recipients") as having
reply code 552. The correct reply code for this condition is 452. Clients SHOULD treat a
552 code in this case as a temporary, rather than permanent, failure so the logic below
works" - the logic of sending those recipients in a later transaction, at least 100 at a
time. A next hop that still answers as RFC 821 did - "552 5.5.3 Too many recipients" (RFC
3463 §3.6: X.5.3, "Too many recipients"), or a bare 552 after other recipients were
accepted - has the recipients past its limit bounced to the sender, who sent nothing
wrong. Tests: `A_recipient_refused_with_552_too_many_recipients_is_retried_not_bounced`,
`A_recipient_refused_with_a_bare_552_after_others_were_accepted_is_retried`;
`A_recipient_refused_with_550_is_still_bounced` is the guard.

Fixed: `RecipientOutcome.Status` takes a 552 with X.5.3, or with no enhanced status code,
for a temporary failure, and the recipient is tried again in a later transaction; a 552
with another enhanced code - 5.2.2, the mailbox is full - is still bounced.

### O-17
**Closed** in [Vanaheimr/Hermod#294](https://github.com/Vanaheimr/Hermod/pull/294)
(`78d89917`). **A recipient domain in U-labels was never delivered to**
(`SMTPOutboundClient.cs:878`, `DomainName.Parse(domain)` of the domain as it is;
`MtaStsResolver.cs:225`, "_mta-sts." and the domain as it is). RFC 6531 §3.2: "Any domain
name to be looked up in the DNS MUST conform to and be processed as specified for
Internationalizing Domain Names in Applications (IDNA) [RFC5890]. When doing lookups, the
SMTPUTF8-aware SMTP client or server MUST either use a Unicode-aware DNS library, or
transform the internationalized domain name to A-label form". The MX lookup of
"bücher.test" fails ("451 4.4.3 The MX lookup of bücher.test failed; the message is
queued"), the MTA-STS record is asked for as "_mta-sts.bücher.test", and the message is
retried for five days and then bounced - mail to "you@bücher.test", which an SMTPUTF8
client writes so (RFC 6531 §3.7), never arrives. Tests:
`The_MX_hosts_of_a_domain_in_U_labels_are_those_of_its_A_labels`,
`Every_DNS_query_for_a_domain_in_U_labels_is_in_A_labels`;
`The_MX_hosts_of_a_domain_in_A_labels_are_found` is the guard.

Fixed: the relay converts the target domain, and a smart host, to A-labels before
anything else: the MX, MTA-STS and address lookups use them, and the relay knows itself
among the MX hosts by its A-labels.

### O-18
**Closed** in [Vanaheimr/Hermod#294](https://github.com/Vanaheimr/Hermod/pull/294)
(`78d89917`). **A relay named in U-labels said EHLO with them**
(`SMTPOutboundClient.cs:492`, `:603`: "EHLO " and `LocalHostname` as it is): "EHLO
relais.bücher.test", in UTF-8. RFC 6531 §3.7.1: the client "MUST send only ASCII (LDH
label or A-label [RFC5890]) domains in the EHLO command." Test:
`The_relay_says_EHLO_with_its_name_in_A_labels`.

Fixed: EHLO and HELO carry the A-labels of `LocalHostname`.

### O-19
**Closed** in [Vanaheimr/Hermod#298](https://github.com/Vanaheimr/Hermod/pull/298)
(`e93c6ef2`). **The relay signed in to its smart host and left AUTH=<> out of MAIL FROM**
(`SMTPOutboundClient.cs:682`, `DsnCommands.MailFrom` at `DsnCommands.cs:176`: no AUTH
parameter, ever). RFC 4954 §5: "If the server does not sufficiently trust the
authenticated identity of the client, or if the client is not authenticated, then the
server MUST behave as if the AUTH=<> parameter was supplied", and "If an AUTH=<>
parameter was supplied, either explicitly or due to the requirement in the previous
paragraph, then the server MUST supply the AUTH=<> parameter when relaying the message to
any server which it has authenticated to using the AUTH extension." Without it the smart
host takes the message for one submitted by the account the relay signed in with ("The
server MUST NOT treat the message as having been originally submitted by the
authenticated identity" is what AUTH=<> asks of it): a message forwarded from anybody, a
bounce, mail of an unauthenticated client - all of it the account's own. Test:
`A_message_relayed_through_a_smart_host_signed_in_to_carries_AUTH_empty`, two cases: from
a client that did not authenticate, with AUTH=<> from the client;
`A_next_hop_without_AUTH_gets_no_AUTH_parameter` is the guard.

Fixed: a message through a smart host the relay signed in to goes with "AUTH=<>" - the
relay vouches for no submitter; one to a next hop it did not sign in to goes without.

### O-20
**Closed** in [Vanaheimr/Hermod#298](https://github.com/Vanaheimr/Hermod/pull/298)
(`e93c6ef2`). **AUTH PLAIN went with its initial response, however long**
(`SMTPOutboundClient.cs:815`: "AUTH PLAIN " and the base64 of the credentials, always).
RFC 4954 §4: "Note that the AUTH command is still subject to the line length limitations
defined in [SMTP]. If use of the initial response argument would cause the AUTH command
to exceed this length, the client MUST NOT use the initial response parameter (and
instead proceed as defined in Section 5.1 of [SASL])" - RFC 5321 §4.5.3.1.4: 512 octets
with CR LF. A password of 400 octets - a token, a generated one - makes an AUTH line of
565, which a smart host that keeps to 512 refuses or cuts. Test:
`A_long_password_goes_to_the_smart_host_without_an_initial_response`.

Fixed: when "AUTH PLAIN" and the response would pass 512 octets with CR LF, the response
follows the empty 334 challenge.

### O-21
**Closed** in [Vanaheimr/Hermod#301](https://github.com/Vanaheimr/Hermod/pull/301)
(`2e477d77`). **A 554 or 521 greeting of the first MX host bounced the message**
(`SMTPOutboundClient.cs:495`: a greeting that is not 2yz is the result of the attempt;
`:288`: a permanent failure ends the delivery, "don't try other MX hosts"). RFC 5321
§5.1: "To provide reliable mail transmission, the SMTP client MUST be able to try (and
retry) each of the relevant addresses in this list in order, until a delivery attempt
succeeds"; §3.1: with a 554 greeting a server will "formally reject a mail session" -
this session, of this client, at this host; RFC 7504 §3: a 521 greeting is "to indicate
that the host does not accept mail under any circumstances" - the host, not the domain. A
primary MX host that has the relay on a blocklist, or one taken out of service with a
521, and the message bounces though the backup MX host would take it. A 421 greeting goes
on to the next MX host already. Test:
`A_session_refused_by_the_first_MX_host_goes_to_the_next` - 554, 521; guard: 421.

Fixed: a greeting that is no 2yz refuses the session, not the message, and the next MX
host is tried; a permanent failure later in the session - of the sender, the recipients,
the content - still ends the delivery. When every MX host refused the session, the
message bounces; when one refused only for now, or could not be reached, it is tried
again later.

### O-22
**Closed** in [Vanaheimr/Hermod#301](https://github.com/Vanaheimr/Hermod/pull/301)
(`2e477d77`). **A refused session at one address of a multihomed next hop ended the attempt**
(`SMTPOutboundClient.cs:445`: `ConnectAsync` takes the first address that answers, and
what it says is the answer of the host). RFC 5321 §5.1: "The destination host (perhaps
taken from the preferred MX record) may be multihomed, in which case the domain name
resolver will return a list of alternative IP addresses. ... the SMTP sender MUST try
them in the order presented", and the list is tried "until a delivery attempt succeeds".
A next hop with two addresses, the first of which greets 421, has every message deferred
until that address is back - the next attempt asks it first again; one that greets 554
has it bounced. Seen on the way, without a test: the connect timeout (`:441`) is one for
all the addresses together, so an address that does not answer at all leaves no time for
the next. Test:
`A_session_refused_at_one_address_of_the_next_hop_goes_to_its_next_address` - 421, 554.

Fixed: the addresses of a host are tried one by one, in the order the resolver gave them,
each with a connect timeout of its own, and an address that refuses the session is
followed by the next. When every address that answered refused it, that is the host's
answer - for now only, if one refused only for now or could not be reached.

### O-23
**Closed** in [Vanaheimr/Hermod#304](https://github.com/Vanaheimr/Hermod/pull/304)
(`1583e599`). **A REQUIRETLS message went to an MX host that nothing vouched for**
(`SMTPOutboundClient.cs:177`: the MX records are taken as the resolver gives them, signed
or not; `:146`: REQUIRETLS asks for TLS, and that is all it asks for). RFC 8689 §2: "If
the SMTP server to which the message is being transmitted is identified through an MX
record lookup, its name MUST be validated via a DNSSEC signature on the recipient domain's
MX record, or the MX hostname MUST be validated by an MTA-STS policy"; §4.2.1: "If the
server lookup is accomplished via the recipient domain's MX record (the usual case) and is
not accompanied by a valid DNSSEC signature, the client MUST also validate the SMTP server
name using MTA-STS ... If there are no more MX hosts, the client MUST NOT transmit the
message to the domain". Whoever can answer the MX lookup names a host of theirs, with a
certificate valid for its own name, and the message goes there on TLS, REQUIRETLS and all -
the attack of §8.2 that REQUIRETLS is there to stop. Test:
`A_REQUIRETLS_message_goes_to_no_MX_host_that_neither_DNSSEC_nor_MTA_STS_vouches_for`;
guard: `A_REQUIRETLS_message_goes_to_an_MX_host_its_MTA_STS_policy_names`.

Fixed: a message that requires TLS goes only to the MX hosts the domain's MTA-STS policy
names - in enforce or testing mode - or to those of an MX record that validates, through
the DNSSEC validator of DANE (`EnableDane`). An MX record that does not validate holds the
message back for now (4.7.5); none that anything vouches for is "5.7.10", and nothing is
transmitted.

### O-24
**Closed** in [Vanaheimr/Hermod#304](https://github.com/Vanaheimr/Hermod/pull/304)
(`1583e599`). **An MX host without REQUIRETLS bounced the message** (`SMTPOutboundClient.cs:746`:
"550 5.7.30" is a permanent failure of the message; `:292`: a permanent failure that is no
refused session ends the delivery). RFC 8689 §4.2.1: "If any of the above steps fail, the
client MUST issue a QUIT to the server and repeat steps 2-5 with each host on the recipient
domain's list of MX hosts in an attempt to find a mail path that meets the sender's
requirements. ... If there are no more MX hosts, the client MUST NOT transmit the message to
the domain." A primary MX host that has not got REQUIRETLS yet, and the message bounces
though the backup MX host offers it. An MX host without STARTTLS, or one that refuses it, is
followed by the next one already. Test: `A_REQUIRETLS_message_goes_on_to_the_next_MX_host` -
an MX host that offers no REQUIRETLS; guards: one that offers no STARTTLS, one that refuses
it.

Fixed: 5.7.30, and 5.7.10 for a host without TLS the relay can authenticate (O-25), are
`SendResult.UnsuitableHost`: the next MX host is tried, as after a refused session (O-21).

### O-25
**Closed** in [Vanaheimr/Hermod#304](https://github.com/Vanaheimr/Hermod/pull/304)
(`1583e599`). **No TLS for a REQUIRETLS message was a failure for now** (`SMTPOutboundClient.cs:692`:
"454 STARTTLS required but not supported"; `:650`: "454 TLS certificate validation failed").
RFC 8689 §4.2.1: "If there are no more MX hosts, the client MUST NOT transmit the message to
the domain. Following such a failure, the SMTP client MUST send a non-delivery notification
to the reverse-path of the failed message ... Unable to establish TLS-protected SMTP
session: 5.7.10 Encryption needed". The message is tried again until the queue gives up on
it, days later, and the sender learns of it then, with a status that says "for now". Test:
`No_TLS_for_a_REQUIRETLS_message_is_a_non_delivery` - a next hop that offers no STARTTLS,
one whose certificate the relay does not trust.

Fixed: no STARTTLS, a STARTTLS refused for good, a certificate that cannot be
authenticated are "550 5.7.10" for a message that requires TLS; a STARTTLS refused for
now is a failure for now still. Secure TLSA records none of which is usable no longer
stand in for authentication.

### O-26
**Closed** in [Vanaheimr/Hermod#304](https://github.com/Vanaheimr/Hermod/pull/304)
(`1583e599`). **A bounce that carried REQUIRETLS was lost at a next hop without it**
(`SMTPOutboundClient.cs:746`: "5.7.30" whatever the reverse-path; `BounceHandler.cs:54`: a
message with a null reverse-path gets no bounce). RFC 8689 §4.2.1 holds "When sending a
message tagged as requiring TLS for which the MAIL FROM return-path is not empty (an empty
MAIL FROM return-path indicating a bounce message)"; §5: "When the MAIL FROM return-path is
empty, the REQUIRETLS parameter SHOULD NOT cause a bounce message to be discarded even if
the next-hop relay does not advertise REQUIRETLS". A bounce received with "MAIL FROM:<>
REQUIRETLS", for a sender whose MX host does not offer REQUIRETLS, is refused for good, and
nobody hears of it. Test: `A_bounce_with_REQUIRETLS_goes_to_a_next_hop_without_REQUIRETLS`.

Fixed: §4.2.1 holds for a message with a sender. A bounce with REQUIRETLS goes over
STARTTLS where offered, with REQUIRETLS where the next hop offers it, and on without
either.

### O-27
**Closed** in [Vanaheimr/Hermod#304](https://github.com/Vanaheimr/Hermod/pull/304)
(`1583e599`). **"TLS-Required: No" was not heeded** (no reference to the header field anywhere
in Hermod; `SMTPSession.cs:844`: a received message is tagged with the REQUIRETLS option
only; `SMTPOutboundClient.cs:146`: an MTA-STS policy in enforce mode holds for every
message). RFC 8689 §3: "No - The SMTP client SHOULD attempt to send the message regardless
of its ability to negotiate STARTTLS with the SMTP server, ignoring policy-based mechanisms
(including MTA-STS and DANE), if any, asserted by the recipient domain. Nevertheless, the
client SHOULD negotiate STARTTLS with the server if available"; §4.1: a server "MUST tag
that message with the option specified in the TLS-Required header field". The header field
is there "to report a misconfigured mail server, such as an expired TLS certificate" - the
very report the policy holds back. Test:
`A_message_with_TLS_Required_No_sets_the_MTA_STS_policy_aside` - an MX host that offers no
STARTTLS, one the policy does not name; guards:
`A_message_without_TLS_Required_keeps_to_the_MTA_STS_policy`, and
`With_REQUIRETLS_the_TLS_Required_field_is_ignored` (§4.1: "If the REQUIRETLS MAIL FROM
parameter is specified, the TLS-Required header field MUST be ignored").

Fixed: the one TLS-Required field of the header, "No", sets the recipient domain's MTA-STS
policy and DANE aside; STARTTLS is tried all the same. With REQUIRETLS the field is
ignored.

### O-28
**Closed** in [Vanaheimr/Hermod#329](https://github.com/Vanaheimr/Hermod/pull/329) (`85b9194e`). **A next hop that refused the session for now was tried again at once for the next
message to it** (`QueueProcessor.cs:150`, `:228`: before an attempt only `CanSendToDomain`
is asked, and `:484` knows when the domain was last sent to and how often - not whether that
went well; `:345`: a failure for now sets the retry of the message, not of the destination).
RFC 5321 §4.5.4.1: "The sender MUST delay retrying a particular destination after one attempt
has failed"; "A client SHOULD keep a list of hosts it cannot reach and corresponding
connection timeouts, rather than just retrying queued mail items." A next hop that greets
with 421, or closes the connection unasked, is tried again for every message queued for it
in the meantime - each of them waiting for the same session to fail. `DomainCooldownSeconds`
(60 by default) is a rate limit: it holds back the next message after a delivery as after a
failure, and for a minute, not for the retry interval. Tests:
`A_destination_that_failed_is_not_tried_again_at_once` - a 421 greeting, a connection closed
at once; guards: `A_recipient_refused_for_now_does_not_hold_back_the_next_message` - a 450
to one RCPT is the recipient's failure, not the destination's -, and
`A_destination_that_took_a_message_takes_the_next_one_at_once`.

Fixed: the `QueueProcessor` keeps the destinations that failed at their last attempt - no
session, or none but a refusal of it, 421 or a connection closed, before any recipient was
answered - and holds back their messages until the message that failed there is due. Then
the first message that is due tries the destination, and the others wait for what it says;
one held back past its give-up time has failed and is bounced. A refusal of a recipient or
of the message is no failure of the destination.

### O-29
**Closed** in [Vanaheimr/Hermod#329](https://github.com/Vanaheimr/Hermod/pull/329) (`85b9194e`). **The retry intervals and the give-up time could not be configured**
(`RetryCalculator.cs:34`: the intervals a private array; `:50`, `:51`: `MaxRetries` a
constant, `MaxQueueTime` a static field; `QueueProcessorConfig` has neither). RFC 5321
§4.5.4.1: "The parameters to the retry algorithm MUST be configurable." An operator whose
mail must give up sooner - or later -, or who retries a smart host of their own more often,
cannot. Tests: `The_give_up_time_is_configurable` - with no time left, a message refused for
now has failed and is bounced -, and `The_retry_intervals_are_configurable` - with three
hours, it is tried again in three hours; they look for `QueueProcessorConfig.GiveUpAfter` and
`QueueProcessorConfig.RetryIntervals` by name. Guard:
`By_default_a_message_refused_for_now_is_kept`.

Fixed: `QueueProcessorConfig` has `RetryIntervals`, `GiveUpAfter` and `MaxRetries`, with the
defaults `RetryCalculator` had - 30 minutes up to a day, five days, 12 attempts. The
Will-Retry-Until of a delay DSN is the give-up time the processor uses.

### O-30
**Closed** in [Vanaheimr/Hermod#329](https://github.com/Vanaheimr/Hermod/pull/329) (`85b9194e`). **A message refused for now could be tried again after 27 minutes**
(`RetryCalculator.cs:37`: 30 minutes the first retry; `:60`: plus or minus 10 % "jitter").
RFC 5321 §4.5.4.1: "In general, the retry interval SHOULD be at least 30 minutes". The jitter
spreads the retries, as it should - but around 30 minutes, so that every other first retry
comes sooner, as soon as after 27. Test: `No_retry_comes_sooner_than_30_minutes` - 20 copies
of a message, each refused for now, the soonest of their retries.

Fixed: the jitter only adds, up to 10 %: no retry comes sooner than its interval.

### O-31
**Closed** in [Vanaheimr/Hermod#329](https://github.com/Vanaheimr/Hermod/pull/329) (`85b9194e`). **Recipients at one domain written two ways got a copy each**
(`SMTPSession.cs:1593`: the relayed recipients are grouped by their domain as written,
ordinally). RFC 5321 §4.5.4.1: when the server "to which a copy of the message is to be sent
is the same for multiple recipients, then only one copy of the message SHOULD be
transmitted. That is, the SMTP client SHOULD use the command sequence: MAIL, RCPT, RCPT, ...,
RCPT, DATA"; §2.4: "Mailbox domains follow normal DNS rules and are hence not case
sensitive"; RFC 5890 §2.3.2.1: a U-label and its A-label are the same label. RCPT TO:
first@outbound.test and second@OUTBOUND.test are queued as two messages for two "domains",
and go in two transactions to the same MX host; first@bücher.test and
second@xn--bcher-kva.test alike. `MailSender` groups without regard to case, but not the two
forms of a name either. Tests: `Recipients_at_one_domain_get_one_copy` - other capitals,
U-labels and A-labels; guards: the same domain written alike, and
`Recipients_at_two_domains_get_two_copies`.

Fixed: the server and `MailSender` group the recipients by `Idna.Key` - A-labels, lower
case, no trailing dot - and the queued message targets that name.

### O-32
**Closed** in [Vanaheimr/Hermod#331](https://github.com/Vanaheimr/Hermod/pull/331) (`cd22515f`). **The relay sent binary data to a next hop without BINARYMIME**
(`SMTPOutboundClient.cs:830`, `:837`: only octets above 127 are looked for - not the length
of a line, not a NUL; `:913`, `:922`: every message goes as DATA). RFC 3030 §3: to a server
that does not offer BINARYMIME "the sender-SMTP MUST NOT, under any circumstances, send binary
data" - it converts the message, or "may treat this as a permanent error"; RFC 2045 §2.7 and §2.8: 7bit and 8bit data are "relatively short lines with 998 octets or
less between CRLF line separation sequences", and no NULs; §2.9: binary data is "data where
any sequence of octets whatsoever is allowed".
A message with Content-Transfer-Encoding: binary that an application gave `MailSender` - a
line of 1200 octets, a NUL - goes on as DATA, without any BODY= even, since none of its octets
is above 127. The server takes a message sent as BDAT as its octets (`SMTPSession.cs:1215`),
so binary data a client sent it goes on the same way. Tests:
`Binary_data_is_not_relayed_to_a_next_hop_without_BINARYMIME` - 8BITMIME alone, CHUNKING
without BINARYMIME, each with a line of 1200 octets and with a NUL; guard:
`A_line_of_998_octets_is_relayed`.

Fixed: to a next hop that does not offer BINARYMIME and CHUNKING, binary data is a permanent
failure, 5.6.3, and bounced - "it may treat this as a permanent error"; no conversion.

### O-33
**Closed** in [Vanaheimr/Hermod#331](https://github.com/Vanaheimr/Hermod/pull/331) (`cd22515f`). **The relay sent binary data as DATA to a next hop that offers BINARYMIME**
(`SMTPOutboundClient.cs:913`: the relay knows no BDAT; `:852`: BODY=8BITMIME is the one body
type it gives). RFC 3030 §3: "BINARYMIME cannot be used with the DATA command", and binary
data is BODY=BINARYMIME; RFC 6152 §3: 8BITMIME "DOES NOT provide a means of transferring an
object with the BINARY content-transfer-encoding". A next hop that offers CHUNKING and
BINARYMIME is sent a line of 1200 octets as DATA, declared nothing. Test:
`Binary_data_goes_to_a_next_hop_with_BINARYMIME_as_BODY_BINARYMIME_only` - as BDAT with
BODY=BINARYMIME, or not at all.

Fixed: binary data goes to a next hop that offers BINARYMIME and CHUNKING as BDAT LAST, with
BODY=BINARYMIME, its octets as they are (`MessageOctets.Bdat`); everything else as DATA, as
before.

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

### D-13
**Closed** in [Vanaheimr/Hermod#290](https://github.com/Vanaheimr/Hermod/pull/290)
(`8ac4ccb1`). **The bounce of an SMTPUTF8 message had UTF-8 where 7 bits are the rule**
(`DsnGenerator.cs:225`, `:246`, `:274`): the status part is always
message/delivery-status, and "Final-Recipient: rfc822; jörg@outbound.test" goes into it as
it is; the returned message is message/rfc822 with "Content-Transfer-Encoding: 8bit", its
Received field naming the recipient in UTF-8. RFC 3464 §2.1, message/delivery-status:
""7bit" encoding is sufficient and MUST be used"; RFC 6533 §4: "As the present standard
DSN format does not permit the return of undeliverable SMTPUTF8 messages, three new media
types have been defined" - message/global-delivery-status (§4.1), message/global and
message/global-headers; RFC 6532 §3.7: a message with "8-bit UTF-8 header values" is a
message/global message. Tests:
`The_status_of_a_UTF_8_recipient_is_a_message_global_delivery_status`,
`A_returned_message_with_UTF_8_header_values_is_message_global`.

Fixed: a status with UTF-8 in it is message/global-delivery-status, with
report-type=global-delivery-status and its UTF-8 addresses of the UTF-8 address type; a
returned message with UTF-8 header values is message/global, its header alone
message/global-headers.

### D-14
**Closed** in [Vanaheimr/Hermod#305](https://github.com/Vanaheimr/Hermod/pull/305)
(`b25dfc4d`). **The bounce of a REQUIRETLS message returned the whole message**
(`BounceHandler.cs:221`: the RET the message was received with; `DsnGenerator.cs:247`: the
whole message for a failure unless RET=HDRS). RFC 8689 §5: "If a REQUIRETLS message is
bounced, the server MUST behave as if RET=HDRS was present, as described in [RFC3461]. If
both RET=FULL and REQUIRETLS are present, the RET=FULL MUST be disregarded." The body of a
message that was to travel on TLS only goes back in a bounce that does not have to (D-15).
Test: `The_bounce_of_a_REQUIRETLS_message_returns_its_header_only` - with RET=FULL, without
RET.

Fixed: the reports on a queued message that requires TLS are generated with RET=HDRS.

### D-15
**Closed** in [Vanaheimr/Hermod#305](https://github.com/Vanaheimr/Hermod/pull/305)
(`b25dfc4d`). **The bounce of a REQUIRETLS message was queued without REQUIRETLS**
(`BounceHandler.cs:224`, `:239`: the report is queued with its envelope, and RequireTls
left false). RFC 8689 §5: non-delivery messages "MUST be protected in the same manner as
the original message. All non-delivery messages resulting from messages with the REQUIRETLS
SMTP option, whether resulting from a REQUIRETLS error or some other issue, MUST also specify
the REQUIRETLS SMTP option unless redacted as described below" - the header of the message,
which the bounce returns, goes to the sender in cleartext, if the sender's MX host offers no
STARTTLS. Test: `The_bounce_of_a_REQUIRETLS_message_requires_TLS`.

Fixed: every report on such a message - bounce, delay, relayed - is queued with
RequireTls, and goes with REQUIRETLS where the next hop offers it (O-26).

### D-16
**Closed** in [Vanaheimr/Hermod#334](https://github.com/Vanaheimr/Hermod/pull/334) (`531ffcf2`). **A multi-line reply of the next hop lost its reply codes in Diagnostic-Code,
and made a line of more than 998 characters** (`SMTPConnection.cs:59`, `:65`: the text of a
reply is the text of its lines without their codes, joined by a space, and "code text" one
line; `SMTPOutboundClient.cs:908`: so a recipient's outcome keeps it; `DsnGenerator.cs:390`:
the Diagnostic-Code is put on one line). RFC 3461 §9.2, the "smtp" diagnostic-type:
diagnostic-code = *( 3*DIGIT "-" *text ) 3*DIGIT SPACE *text - "For a single-line SMTP reply
to an SMTP command, the diagnostic-code SHOULD be an exact transcription of the reply. For
multi-line SMTP replies, it is necessary to insert a SPACE before each line after the
first", the example "550-mailbox unavailable" folded onto " 550 user has moved with no
forwarding address". The reply `550-5.1.1 mailbox unavailable` / `550 5.1.1 user has moved
with no forwarding address` is written `smtp; 550 5.1.1 mailbox unavailable 5.1.1 user has
moved with no forwarding address` - one reply line that the next hop never sent, in the
bounce, the delayed and the relayed DSN alike. And on one line: three reply lines of 500
octets, each within RFC 5321 §4.5.3.1.5 ("The maximum total length of a reply line including
the reply code and the <CRLF> is 512 octets"), make a line of 1511 characters in the bounce -
RFC 5322 §2.1.1: "Each line of characters MUST be no more than 998 characters". Tests:
`A_multi_line_reply_is_transcribed_line_by_line` - the bounce, of a reply to RCPT, to MAIL,
to the end of the data, the delayed DSN, the relayed DSN;
`A_reply_of_three_long_lines_makes_no_line_longer_than_998_characters`; guard:
`A_single_line_reply_is_transcribed_exactly`.

Fixed: `SMTPReply.Transcript` is the reply as it was received, every line with its code; a
recipient's outcome keeps it, a refusal of MAIL, DATA or the message and the reply that takes
the message keep it as their text. `DsnGenerator` writes every line of it on a line of its
own, after CR LF SPACE, and folds a line too long for one at a space within it (RFC 5322
§2.2.3), which unfolding takes back exactly.

### D-17
**Closed** in [Vanaheimr/Hermod#334](https://github.com/Vanaheimr/Hermod/pull/334) (`531ffcf2`). **The Remote-MTA of a next hop known by its address was no domain-literal**
(`DsnGenerator.cs:317`: `Remote-MTA: dns;` and the next hop as the relay was given it -
`SMTPOutboundClient.cs:186`, a smart host as configured). RFC 3461 §6.3 (h): "the Remote-MTA
field MUST be supplied for each of those recipients. The mta-name-type subfields of those
Remote-MTA fields will be "dns""; §9.3: "MTA names of type "dns" SHOULD be valid Internet
domain names. If such domain names are not available, a domain-literal containing the
internet protocol address is acceptable", domain-literal = "[" 1*3DIGIT 3("." 1*3DIGIT) "]".
A smart host given as 127.0.0.1 is written `Remote-MTA: dns; 127.0.0.1`, a domain name it is
not; `dns; [127.0.0.1]` says what it is. Tests:
`The_Remote_MTA_of_a_next_hop_given_as_an_address_is_a_domain_literal` - the bounce, the
relayed DSN.

Fixed: `DsnGenerator.MtaName` writes an address as a domain-literal, `[192.0.2.1]`, or
`[IPv6:2001:db8::1]` (RFC 5321 §4.1.3); a name, or a literal, as it is.

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

The guard first modelled the unsigned host as an unsigned A record inside the anchored
zone. That is not an unsigned host but a stripped signature, and since
[#155](https://github.com/Vanaheimr/Hermod/pull/155) (`903c82a6`) Hermod rightly calls it
Bogus: an unsigned answer is Insecure only on a proof that a delegation between the
anchor and the data is unsigned (RFC 4035 §4.3). The host now lies in `plain.dane.test`,
an unsigned child of the signed zone, whose parent answers the DS query with its signed
NSEC - NS set, DS and SOA clear (§5.2). Without that NSEC the guard fails.

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
**Closed** in [Vanaheimr/Hermod#149](https://github.com/Vanaheimr/Hermod/pull/149) (`12baa4e6`).
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
an AIA URL in TEST-NET-1 (`http://192.0.2.1/`), which makes the wait certain:
17.5 s against the pin.

Fixed: under DANE the client builds the server's chain offline - no downloads, no
revocation check. Measured on the client alone, the handshake with such an anchor took
15.5 s before and 1.3 s after. The suite's test is a guard since: it asserts the outcome
and only warns about the time, because with the scripted server the old code delivered
after the wait, and on some Windows images the server side (SChannel) builds its own
chain and waits as well, which a time bound cannot tell apart. The counter-check is
Hermod's `DANE_TA_does_not_depend_on_certificate_downloads`, where the old code ends in
TempFail ([#151](https://github.com/Vanaheimr/Hermod/pull/151) makes its CAs unique, after
an occasional Windows failure: every anchor was "CN=DANE trust anchor" without key
identifiers, and the chain engine could take one of an earlier test from its cache - the
suite's `TestCertificate.CreateIssuedCertificate` does the same now).

---

## Message authentication on inbound mail

RFC 7208, RFC 6376, RFC 7489 and RFC 8601 as `SMTPSession` and `DNSVerifier` apply them
to mail from other servers (`MessageAuthenticationTests`). The messages are signed by
the suite's own DKIM signer (`TestDkimKey`), which `DkimToolingTests` checks against the
suite's own verifier. Covered without a finding: two From: fields or two addresses in
one do not pass DMARC on either; forwarded mail with the author's aligned signature
passes DMARC despite an SPF fail, and with only a foreign one does not; DMARC passes on
the author's signature behind a mail service's; a null sender is not exempt from DMARC.
`BlocklistTests` (RFC 5782): the reversed octets and nibbles, a listed client refused
with 5.7.1 at RCPT and still reaching the postmaster.

### V-1
**Closed** in [Vanaheimr/Hermod#258](https://github.com/Vanaheimr/Hermod/pull/258) (`4053085f`).
**A DKIM key record without a version tag was not found**
(`DNSVerifier.cs:612`, `GetTxtRecordAsync(dkimDomain, "v=DKIM1", ct)`, and `:946`,
`txt.Text.StartsWith(prefix, ...)`): a key record is taken only when it begins with
"v=DKIM1", so "k=rsa; p=..." is "No DKIM record found", and the signature fails. RFC 6376
§3.6.1: "v= Version of the DKIM key record (plain-text; RECOMMENDED, default is
"DKIM1")". A domain whose record leaves the tag out has every signature fail - and with
p=reject, its mail refused. Test: `A_key_record_without_a_version_tag_verifies`.

Fixed: a TXT record that does not begin with v=, or whose v= is "DKIM1" exactly, is a key
record; one with another version is discarded, as §3.6.1 says - the prefix match had also
taken "v=DKIM1.0", which it must not. Of several, the first with a p= tag. The ARC
validator, which reads the same records, uses the same lookup.

### V-2
**Closed** in [Vanaheimr/Hermod#259](https://github.com/Vanaheimr/Hermod/pull/259) (`1cd85617`).
**The SPF result of a null sender did not name the identity checked**
(`SMTPSession.cs:1516`, `var mailFrom = String.IsNullOrEmpty(_mailFrom) ? "<>" : _mailFrom;`,
and `:1530`): since the security review a null reverse-path is checked on the HELO
identity, as RFC 7208 §2.4 says - "When the reverse-path is null, this document defines
the "MAIL FROM" identity to be the mailbox composed of the local-part "postmaster" and
the "HELO" identity" - but the header says `spf=pass smtp.mailfrom=<>`. RFC 8601 §2.7.2:
"For SPF, the ptype used is "smtp", and the property is either "mailfrom" or "helo",
since those values are the ones SPF can evaluate". Either `smtp.helo=` the HELO name or
`smtp.mailfrom=postmaster@` it says what passed; `<>` says nothing a filter can align.
Test: `The_SPF_result_of_a_null_sender_names_the_HELO_identity`.

Fixed: a null reverse-path, or one without a domain, reports `smtp.helo=` the HELO name;
a HELO that is an address literal gave SPF no domain, and its `spf=none` names no
identity. A reverse-path with a domain still says `smtp.mailfrom=` it.

### V-3
**Closed** in [Vanaheimr/Hermod#260](https://github.com/Vanaheimr/Hermod/pull/260) (`1c051d7e`).
**rsa-sha1 signatures verified** (`DNSVerifications/DNSVerifier.cs:629` and `:672`,
`algorithm.Contains("sha256") ? ... SHA256 : ... SHA1`; the same in `Arc/ArcValidator.cs:127`
and `:157`): an a= that does not say sha256 is verified with SHA-1, whatever it says. RFC
8301 §3.1: "rsa-sha1 MUST NOT be used for signing or verifying", and signatures with it
"have permanently failed evaluation". ARC imports the methods of RFC 6376 (RFC 8617 §5.2).
A SHA-1 signature is a forgery target; DMARC passes on it. Tests:
`A_signature_with_rsa_sha1_does_not_pass`, `A_chain_sealed_with_rsa_sha1_fails`.

Fixed: DKIM accepts rsa-sha256 and ed25519-sha256, ARC rsa-sha256; any other a= fails.
No Hermod signer writes rsa-sha1.

### V-4
**Closed** in [Vanaheimr/Hermod#260](https://github.com/Vanaheimr/Hermod/pull/260) (`b76deeb0`).
**A signature whose b= tag came first never verified**
(`DNSVerifications/DkimCanonicalization.cs:234` and `:252`): the b= value is removed with
`(^|;)(\s*b\s*=)[^;]*` - run on the whole field, `DKIM-Signature: b=...`, where `^` is
the start of the field name, not of the value. A b= right after the colon is neither, so
its value stays in what is hashed, and the signature cannot match. RFC 6376 §3.2: tags
come in any order; §3.7: the signature is computed "with the value of the "b=" tag
(including all surrounding whitespace) deleted". DKIM, the AMS and the AS alike. Tests:
`A_signature_whose_b_tag_comes_first_verifies`, `A_chain_whose_signatures_come_first_passes`
- the suite's verifiers take both (`DkimToolingTests`, `ArcToolingTests`).

Fixed: the b= value is removed from the field's value, wherever the tag stands (RFC 6376
§3.7) - in DKIM, the AMS and the AS.

The eighth round's SPF tests (`SpfEvaluationTests`) call `DNSVerifier.CheckSpfAsync` - the
evaluation the server applies to the MAIL FROM and HELO identities - against the test's
DNS; its DKIM tests (`DkimVerifierTests`) call `DNSVerifier.VerifyDkimAsync`, and
`VerifyAsync` for DMARC, with signatures of the suite's own signer that are valid over what
they say. Covered without a finding: NXDOMAIN in a mechanism's lookup counts as no records;
unknown modifiers are ignored; ten MX names and two void lookups are within the limits; a
reverse name whose addresses are not the client's is not validated; a key of 1024 bits, an
i= in a subdomain of d=, and key records with h=sha1:sha256, s=email, s=* or t=s for an i= of
d= itself verify.

### V-5
**Closed** in [Vanaheimr/Hermod#277](https://github.com/Vanaheimr/Hermod/pull/277)
(`d0c354a6`). **A DNS error was taken for no record or no match**
(`DNSVerifications/DNSVerifier.cs:976` to `:1000`, `:403` to `:427`, `:1057` to `:1078`):
the lookups of the record, of the addresses for a, mx and exists, and of the MX names for
mx catch every error and go on as if there were no record, no address or no MX name. A
SERVFAIL or a timeout of the SPF record gives `none`; of an a:, mx or exists: lookup no
match - `fail` under `-all`; of an include: target's record `permerror`. RFC 7208 §4.4:
"If the DNS lookup returns a server failure (RCODE 2) or some other error (RCODE other
than 0 or 3), or if the lookup times out, then check_host() terminates immediately with
the result "temperror""; §5: for a mechanism's lookups "the mechanism stops and the
topmost check_host() returns "temperror"". A moment of trouble at the sender's DNS fails
its mail: DMARC fails where DKIM does not pass, and a receiver that refuses on `fail`
refuses it - where `temperror` would have it tried again. Tests:
`A_DNS_error_is_a_temporary_error`, six cases; `A_name_that_does_not_exist_is_no_error` is
the guard.

Fixed: every query of check_host() goes through one lookup that ends it with `temperror`
on an RCODE other than 0 or 3 or a timeout - also from inside an include: or a redirect=,
whose result is the topmost (§5.2); NXDOMAIN is no records.

### V-6
**Closed** in [Vanaheimr/Hermod#277](https://github.com/Vanaheimr/Hermod/pull/277)
(`d0c354a6`). **`v=spf10` was an SPF record, and of two SPF records the first counted**
(`:990`, `txt.Text.StartsWith(prefix)`, the first that does): RFC 7208 §4.5: "discard
records that do not begin with a version section of exactly "v=spf1". Note that the
version section is terminated by either an SP character or the end of the record. As an
example, a record with a version section of "v=spf10" does not match and is discarded";
"If the resultant record set includes more than one record, check_host() produces the
"permerror" result." Test: `Only_one_record_of_exactly_v_spf1_is_evaluated`, three cases
and a guard (an SPF record among other TXT records).

Fixed: only TXT records whose version section is exactly `v=spf1`, followed by a space or
nothing, are SPF records; two of them are `permerror`.

### V-7
**Closed** in [Vanaheimr/Hermod#277](https://github.com/Vanaheimr/Hermod/pull/277)
(`d0c354a6`). **The record was evaluated up to the term that matched, not checked first**
(`:212` to `:325`): the terms are read one at a time and the first that matches returns;
what follows it is never looked at, and an address or prefix length the parser cannot use
is a term that does not match. So `v=spf1 +all frobnicate:example.test` passes, and so
does `ip4:192.0.2.1/33` behind the term that matches, or `ip4:192.0.2` before it. RFC 7208
§4.6: "The syntax of the record is validated first, and if there are any syntax errors
anywhere in the record, check_host() returns immediately with the result "permerror",
without further interpretation or evaluation"; §5.6: `ip4-network = qnum "." qnum "." qnum
"." qnum`, `ip4-cidr-length = "/" ("0" / %x31-39 0*1DIGIT) ; value range 0-32`. Test:
`A_syntax_error_anywhere_is_a_permanent_error`, three cases;
`An_unknown_modifier_is_no_syntax_error` is the guard.

Fixed: the whole record is checked against the ABNF of §12 - mechanisms and their
arguments, IPv4 addresses, prefix lengths, domain-specs and their macros - before it is
evaluated, and so is every record an include: or redirect= names.

### V-8
**Closed** in [Vanaheimr/Hermod#277](https://github.com/Vanaheimr/Hermod/pull/277)
(`d0c354a6`). **redirect= or exp= twice** (`:223`): of two redirect= the last is followed,
a second exp= is not noticed. RFC 7208 §6: "These two modifiers MUST NOT appear in a
record more than once each. If they do, then check_host() exits with a result of
"permerror"." Test: `A_modifier_given_twice_is_a_permanent_error`, two cases.

Fixed: part of the syntax check: redirect= and exp= at most once each.

### V-9
**Closed** in [Vanaheimr/Hermod#277](https://github.com/Vanaheimr/Hermod/pull/277)
(`d0c354a6`). **`ptr` never matched** (`:312` to `:318`): the mechanism counts against the
limit of ten and is skipped. RFC 7208 §5.5 says it "SHOULD NOT be published", and: "It is,
however, still in use as part of the SPF protocol, so compliant check_host()
implementations MUST support it." A domain that still names its servers by their reverse
names - `v=spf1 ptr -all` - gets `fail` for all its mail. Test:
`The_ptr_mechanism_matches_a_validated_name`, two cases (ptr, ptr:domain);
`The_ptr_mechanism_does_not_match_a_name_that_is_not_validated` is the guard.

Fixed: the client's reverse names whose addresses include its own are validated, the first
ten; ptr matches one that is the target or within it. A DNS error of the PTR lookup is no
match, one of an address lookup skips that name (§5.5).

### V-10
**Closed** in [Vanaheimr/Hermod#277](https://github.com/Vanaheimr/Hermod/pull/277)
(`d0c354a6`). **`mx` with more than ten MX names took the first ten** (`:397`,
`mxHosts.Take(10)`): RFC 7208 §4.6.4: "the evaluation of each "MX" record MUST NOT result
in querying more than 10 address records -- either "A" or "AAAA" resource records. If this
limit is exceeded, the "mx" mechanism MUST produce a "permerror" result." Test:
`An_mx_mechanism_with_more_than_ten_names_is_a_permanent_error`; ten names is the guard.

Fixed: more than ten MX names are `permerror`.

### V-11
**Closed** in [Vanaheimr/Hermod#277](https://github.com/Vanaheimr/Hermod/pull/277)
(`d0c354a6`). **No limit on void lookups** (`:376` to `:427`): RFC 7208 §4.6.4: "SPF
implementations SHOULD limit "void lookups" to two. ... Exceeding the limit produces a
"permerror" result" - the limit that keeps a record full of names that do not exist from
turning each check into lookups at someone else's DNS (§11.1). Test:
`A_third_void_lookup_is_a_permanent_error`; `Two_void_lookups_are_within_the_limit` is the
guard.

Fixed: A third term whose lookup returns no records or NXDOMAIN is `permerror`.

### V-12
**Closed** in [Vanaheimr/Hermod#277](https://github.com/Vanaheimr/Hermod/pull/277)
(`d0c354a6`). **A client on an IPv4-mapped address matched no `ip4` or `a`** (`:244`,
`:382`): the mechanisms compare address families, and ::ffff:192.0.2.25 is an IPv6
address. RFC 7208 §5: "SPF implementations on IPv6 servers need to handle both "AAAA" and
"A" records, for clients on IPv4-mapped IPv6 addresses [RFC4291]." The server's listeners
are not dual-mode, so its own sessions see IPv4 clients as IPv4; `CheckSpfAsync` and
`VerifyAsync` take the address they are given - the blocklist check maps it back
(`DNSVerifications/DNSVerifier.Blocklists.cs:54`), SPF does not. Test:
`A_client_on_an_IPv4_mapped_address_is_matched_as_IPv4`, two cases;
`A_client_on_its_IPv4_address_is_matched` is the guard.

Fixed: an IPv4-mapped client is evaluated as its IPv4 address; a and mx fetch A or AAAA as
the client's family asks, exists A (§5.7).

### V-13
**Closed** in [Vanaheimr/Hermod#279](https://github.com/Vanaheimr/Hermod/pull/279)
(`8bc62f93`). **A signature that did not sign From verified** (`:612` to `:656`): the h=
list is hashed as it stands. RFC 6376 §6.1.1: "If the "h=" tag does not include the From
header field, the Verifier MUST ignore the DKIM-Signature header field and return PERMFAIL
(From field not signed)." Such a signature holds whatever the From says - one can be put
in after signing - and DMARC passes on it when its d= is aligned with the From written
there: a message signed by a domain, with h= leaving out From, can be sent again as from
anyone at that domain. Tests: `A_signature_that_does_not_sign_From_does_not_verify`,
`A_signature_that_does_not_sign_From_does_not_pass_DMARC`.

Fixed: A signature whose h= does not name From fails.

### V-14
**Closed** in [Vanaheimr/Hermod#279](https://github.com/Vanaheimr/Hermod/pull/279)
(`8bc62f93`). **Signatures with RSA keys of fewer than 1024 bits verified** (`:684`): the
key is imported and used whatever its size. RFC 8301 §3.2: "Verifiers MUST NOT consider
signatures using RSA keys of less than 1024 bits as valid signatures" - such signatures
"have permanently failed evaluation". A 512-bit key is factored in hours on rented
machines; whoever has done so signs as the domain, and DMARC passes. Test:
`A_signature_with_a_key_of_512_bits_does_not_verify`;
`A_signature_with_a_key_of_1024_bits_verifies` is the guard.

Fixed: an RSA key of fewer than 1024 bits fails the signature.

### V-15
**Closed** in [Vanaheimr/Hermod#279](https://github.com/Vanaheimr/Hermod/pull/279)
(`8bc62f93`). **A signature without v= or a=, or with v=2, verified** (`:612` to `:623`):
of the tags RFC 6376 §3.5 requires, d=, s=, b= and bh= are required; a missing a= is taken
for rsa-sha256, and v= is not read. §6.1.1: "If any tag listed as "required" in Section
3.5 is omitted from the DKIM-Signature header field, the Verifier MUST ignore the
DKIM-Signature header field and return PERMFAIL"; "Verifiers MUST return PERMFAIL
(incompatible version) when presented a DKIM-Signature header field with a "v=" tag that
is inconsistent with this specification"; §3.5, v=: "It MUST have the value "1" for
implementations compliant with this version of DKIM." Test:
`A_signature_without_a_required_tag_or_of_another_version_does_not_verify`, three cases.

Fixed: v=, a=, b=, bh=, d=, h= and s= are required, and v= is "1".

### V-16
**Closed** in [Vanaheimr/Hermod#279](https://github.com/Vanaheimr/Hermod/pull/279)
(`8bc62f93`). **A signature whose i= was outside its d= verified** (`:612` to `:684`; i=
is read only for the failure report): RFC 6376 §6.1.1: "Verifiers MUST confirm that the
domain specified in the "d=" tag is the same as or a parent domain of the domain part of
the "i=" tag. If not, the DKIM-Signature header field MUST be ignored". A signature of
author.test that names news@evil.test as the agent it signed for is taken. Test:
`A_signature_whose_i_is_outside_its_d_does_not_verify`;
`A_signature_whose_i_is_a_subdomain_of_its_d_verifies` is the guard.

Fixed: i=, by default `@d`, has to be d= or within it.

### V-17
**Closed** in [Vanaheimr/Hermod#279](https://github.com/Vanaheimr/Hermod/pull/279)
(`8bc62f93`). **The key record's h=, s=, t=s and k= were not applied** (`:636` to `:684`):
of the record, p= is read, and k= only to tell Ed25519 from the rest. A key limited to
SHA-1 (`h=sha1`) verifies rsa-sha256 signatures, a key for another service (`s=other`)
mail, a key with `t=s` signatures whose i= is a subdomain of d=, and a key of another type
(`k=dsa`) is used as an RSA key. RFC 6376 §6.1.2: "If the "h=" tag exists in the
public-key record and the hash algorithm implied by the "a=" tag in the DKIM-Signature
header field is not included in the contents of the "h=" tag, the Verifier MUST ignore the
key record"; "If the public-key data is not suitable for use with the algorithm and key
types defined by the "a=" and "k=" tags in the DKIM-Signature header field, the Verifier
MUST immediately return PERMFAIL (inappropriate key algorithm)"; §3.6.1, s=: "Verifiers
for a given service type MUST ignore this record if the appropriate type is not listed";
t=s: "the "i=" domain MUST NOT be a subdomain of "d="". Test:
`The_tags_of_the_key_record_are_applied`, four cases, and four guards (h=sha1:sha256,
s=email, s=*, t=s with an i= of d=).

Fixed: k= is rsa or ed25519; h=, where given, lists sha256; s=, where given, lists * or
email; t=s takes an i= of d= itself only.

The ninth round's DMARC tests (`DmarcPolicyTests`) call `DNSVerifier.VerifyAsync` with
unsigned mail from author.test through a client no SPF record names. Covered without a
finding: such mail fails under p=reject; an aligned signature passes whatever SPF says; a
From domain without a record falls back to its Organizational Domain's, and its sp=; a
record among other TXT records, or without a space after ";", is applied; a record with an
invalid p= but a valid rua is p=none.

### V-18
**Closed** in [Vanaheimr/Hermod#282](https://github.com/Vanaheimr/Hermod/pull/282)
(`0ebac1f6`). **A temporary error of SPF failed DMARC and applied the policy**
(`DNSVerifications/DNSVerifier.cs:1300`: pass is SPF or DKIM aligned, everything else
fail): SPF "temperror" - now that SPF has one (V-5) - and no signature that passes give
`dmarc=fail`, and p=reject rejects. RFC 7489 §6.6.2: "If neither passes and one or both of
them fail due to a temporary error, the Receiver evaluating the message is unable to
conclude that the DMARC mechanism had a permanent failure; they therefore cannot apply the
advertised DMARC policy." A moment of DNS trouble at the sender's domain bounces its mail
for good. Test: `A_temporary_error_of_SPF_does_not_apply_the_policy`;
`A_temporary_error_of_SPF_beside_an_aligned_signature_passes` is the guard.

Fixed: a message neither check passed, whose aligned SPF check or aligned signature ended
in a temporary error, is DMARC `temperror` with the disposition none; a temporary error of
an unaligned check changes nothing.

### V-19
**Closed** in [Vanaheimr/Hermod#282](https://github.com/Vanaheimr/Hermod/pull/282)
(`0ebac1f6`). **A DNS error at the From domain's record fell back to the Organizational
Domain** (`:1269` to `:1278`, `GetTxtRecordAsync` `:1465` to `:1490`: an error is no
record): a SERVFAIL for _dmarc.news.author.test, and the record of author.test is applied
in its place. RFC 7489 §6.6.3 asks the Organizational Domain "If the set is now empty" -
the From domain said it has no record - and sets "any indication that there is no such
record" apart from "a transient DNS error", whose handling "is left to the discretion of
the Mail Receiver": fail open, or 4yx. Another domain's policy, which may be laxer or
stricter than the one that could not be read, is neither. Test:
`A_DNS_error_at_the_From_domain_does_not_fall_back_to_the_organizational_domain`;
`A_From_domain_without_a_record_falls_back_to_the_organizational_domain` is the guard.

Fixed: a DMARC lookup that fails - an RCODE other than 0 or 3, a timeout - ends policy
discovery as `temperror`, at the From domain as at the Organizational Domain; NXDOMAIN and
an answer without a record still fall back.

### V-20
**Closed** in [Vanaheimr/Hermod#282](https://github.com/Vanaheimr/Hermod/pull/282)
(`0ebac1f6`). **Of two DMARC records the first was applied** (`:1479`, the first record
that starts with "v=DMARC1"): RFC 7489 §6.6.3: "If the remaining set contains multiple
records or no records, policy discovery terminates and DMARC processing is not applied to
this message." Test: `Only_one_record_of_version_DMARC1_is_applied`, one case, and a guard
(one record among other TXT records).

Fixed: two records end policy discovery, at the From domain without asking the
Organizational Domain.

### V-21
**Closed** in [Vanaheimr/Hermod#282](https://github.com/Vanaheimr/Hermod/pull/282)
(`0ebac1f6`). **The version was not matched exactly** (`:1479`, `StartsWith("v=DMARC1",
OrdinalIgnoreCase)`): "v=dmarc1" and "v=DMARC1x" are DMARC records, "v = DMARC1" is none.
RFC 7489 §6.3, v: "It MUST have the value of "DMARC1". The value of this tag MUST match
precisely; if it does not or it is absent, the entire retrieved record MUST be ignored";
§6.4: `dmarc-version = "v" *WSP "=" *WSP %x44 %x4d %x41 %x52 %x43 %x31` - white space
around "=" is allowed, and the value is in upper case. Test:
`Only_one_record_of_version_DMARC1_is_applied`, three cases, and a guard (no space after
";").

Fixed: `IsDmarcRecord` has the ABNF of §6.4: "v", white space, "=", white space, "DMARC1"
as it is written, then the separator or the end.

### V-22
**Closed** in [Vanaheimr/Hermod#282](https://github.com/Vanaheimr/Hermod/pull/282)
(`0ebac1f6`). **A record without a valid p=, or with an invalid sp=, and without rua was
applied** (`:1439`, `:1440`: a missing p= is "none", any other value taken as it is):
"v=DMARC1; sp=reject" and "v=DMARC1; p=bogus" give `dmarc=fail`, "v=DMARC1; p=reject;
sp=bogus" rejects. RFC 7489 §6.6.3: "If a retrieved policy record does not contain a valid
"p" tag, or contains an "sp" tag that is not valid, then: 1. if a "rua" tag is present and
contains at least one syntactically valid reporting URI, the Mail Receiver SHOULD act as
if a record containing a valid "v" tag and "p=none" was retrieved, and continue
processing; 2. otherwise, the Mail Receiver applies no DMARC processing to this message."
Test: `A_record_without_a_valid_policy_and_without_rua_is_not_applied`, three cases;
`A_record_without_a_valid_policy_but_with_rua_is_p_none` is the guard.

Fixed: such a record is p=none when its rua has a syntactically valid URI, and is not
applied without one.

### V-23
**Closed** in [Vanaheimr/Hermod#295](https://github.com/Vanaheimr/Hermod/pull/295)
(`d03d2fd3`). **A sender domain in U-labels was looked up in U-labels**
(`DNSVerifier.cs:191`, `LookupSpfRecordAsync`, `:606`, with the domain of MAIL FROM as it
is; the macros of §7 likewise): "MAIL FROM:<news@bücher.test> SMTPUTF8" has its record
asked for at "bücher.test", where there is none, and SPF is "none". RFC 8616 §4: "An IDN
in MAIL FROM can be either U-labels or A-labels. All U-labels MUST be converted to
A-labels before being used for an SPF validation. This includes both the labels in the
name used for the original DNS lookup, described in Section 3 of [RFC7208], and those
used in the macro expansion of domain-spec, described in Section 7." A domain that
publishes "v=spf1 -all" - the record of a domain that sends no mail - has it ignored for
every message whose envelope writes it in U-labels: the forger only has to. Tests:
`SPF_of_a_sender_domain_in_U_labels_is_the_record_of_its_A_labels`,
`SPF_fail_of_a_sender_domain_in_U_labels_is_not_lost`,
`The_macro_of_a_sender_domain_in_U_labels_expands_to_A_labels`;
`SPF_of_a_sender_domain_in_A_labels_passes` is the guard.

Fixed: `VerifySpfAsync` converts the domain, the HELO name and the domain of MAIL FROM to
A-labels before check_host() begins, so the macros expand to A-labels too.

### V-24
**Closed** in [Vanaheimr/Hermod#295](https://github.com/Vanaheimr/Hermod/pull/295)
(`d03d2fd3`). **A signature with d= in U-labels was checked against a key looked up under
a mis-decoded name** (`DNSVerifier.cs:1086`, `:1600`): the key of "d=sig.bücher.test;
s=test" is asked for at "test._domainkey.sig.bã¼cher.test" - the header read as Latin-1,
the UTF-8 of "ü" as two characters - and the signature fails. RFC 8616 §5: in
internationalized header fields "IDNs SHOULD be represented as U-labels" in d=, i= and
s=; §3: "When a domain name found in a mail header field includes U-labels, those labels
are translated to A-labels before being looked up in the DNS". The signature of an EAI
message, signed as RFC 8616 recommends, never passes - and under the author's p=reject
the message is refused. Test:
`A_signature_with_d_in_U_labels_is_verified_with_the_key_of_its_A_labels`;
`A_signature_with_d_in_A_labels_on_an_internationalized_message_passes` is the guard.

Fixed: the tags of DKIM-Signature are decoded as the UTF-8 they are, the key is looked up
at the A-labels of selector._domainkey.d, and i= is compared with d= in A-labels,
whichever form either is written in.

### V-25
**Closed** in [Vanaheimr/Hermod#295](https://github.com/Vanaheimr/Hermod/pull/295)
(`d03d2fd3`). **The policy of an author domain in U-labels was looked up in U-labels**
(`DNSVerifier.cs:1272`, "_dmarc." and the From domain as it is): the record at
"_dmarc.shop.xn--bcher-kva.test" is never found for "From: <ceo@shop.bücher.test>". Only
the organizational domain is asked for in A-labels (`:1281`, by way of the Public Suffix
List), so its policy applies instead: a subdomain's "p=reject" under an organizational
"p=none" lets the forged message through, and a domain's "adkim=s" is never seen. RFC
8616 §6: RFC 7489 §6.6.1 "is updated to say that all U-labels in the domain are converted
to A-labels before further processing." Tests:
`The_policy_of_an_author_domain_in_U_labels_is_the_record_of_its_A_labels`,
`Strict_alignment_compares_an_author_domain_in_U_labels_by_its_A_labels`;
`The_organizational_policy_applies_to_an_author_domain_in_U_labels` is the guard.

## ARC

RFC 8617 as `ArcValidator` checks the chain of every unauthenticated message and the
server writes `arc=` into Authentication-Results (`ArcValidationTests`), and as
`ArcSealer` seals (`ArcSealerTests`) - Hermod's server never calls the sealer; a
forwarder built on Hermod would. The chains are sealed, and Hermod's seals validated, by
the suite's own ARC implementation (`TestArc`), which `ArcToolingTests` checks. Covered
without a finding: one and two sets pass; a changed body, a gap in the instances, an
instance twice, cv=pass at instance 1 and cv=fail fail; Hermod's first seal and a seal on
a passing chain validate, with cv=none and cv=pass, no v= in the AMS, no h= in the AS.

Fixed: `VerifyDmarcAsync` takes the From domain in A-labels from the start, and alignment
compares A-labels on both sides.

### A-1
**Closed** in [Vanaheimr/Hermod#260](https://github.com/Vanaheimr/Hermod/pull/260) (`63fcf3cd`).
**No limit of 50 ARC sets - and an instance that kept the validator counting
forever** (`Arc/ArcChain.cs:70` and `:75`): `n` is the highest i= of any ARC header field,
and `for (var i = 1; i <= n; i++)` counts up to it. A chain of 51 sets passes; RFC 8617
§5.2 step 1: "The maximum number of ARC Sets that can be attached to a message is 50. If
more than the maximum exist, the Chain Validation Status is "fail"", and §4.2.1:
"Instance tag values can range from 1-50 (inclusive)". With `i=2147483647`, `i++` wraps
to a negative number before it gets past `n`, and the loop never ends: the session hangs
in a loop that keeps a core busy, for one header line in one message from anyone - the
validation runs on every message from a client that did not sign in. Tests:
`More_than_50_ARC_sets_fail`, `An_instance_number_beyond_50_is_answered_at_once` (on a
fixture of its own; against `287d1c43`, its session was still counting when the test ended).

Fixed: a chain whose highest instance is above 50 fails before any loop runs, and
`MaxInstance` is the highest instance found (§5.1). The sealer does not seal past 50,
and a set sealed with cv=fail signs only its own set (§5.1.2).

### A-2
**Closed** in [Vanaheimr/Hermod#260](https://github.com/Vanaheimr/Hermod/pull/260) (`ebf94993`).
**An ARC-Seal with an h= tag was accepted** (`Arc/ArcValidator.cs:145`,
`VerifySealAsync`): nothing looks for it. RFC 8617 §4.1.3: "the DKIM "h" tag is NOT
allowed and, if found, MUST result in a cv status of "fail"". Test:
`An_ARC_Seal_with_an_h_tag_fails`.

Fixed: an h= tag in an ARC-Seal fails the chain.

### A-3
**Closed** in [Vanaheimr/Hermod#260](https://github.com/Vanaheimr/Hermod/pull/260) (`c6aecb17`).
**A tag twice in a tag-list: the last one counted** (`Arc/ArcChain.cs:148`,
`tags[name] = value`): `cv=fail; ...; cv=pass` reads as pass. RFC 6376 §3.2, whose
tag-lists ARC uses: "Tags with duplicate names MUST NOT occur within a single tag-list;
if a tag name does occur more than once, the entire tag-list is invalid". Test:
`An_ARC_Seal_naming_cv_twice_fails`.

Fixed: the tag-list is invalid and the chain fails; an ARC header field without a valid
instance makes the chain malformed.

### A-4
**Closed** in [Vanaheimr/Hermod#260](https://github.com/Vanaheimr/Hermod/pull/260) (`480f58d4`).
**The sealer sealed a failed chain once more** (`Arc/ArcSealer.cs:68` and `:72`):
it adds a set with cv=fail on top of one whose seal already says cv=fail. RFC 8617 §5.1
step 2: with "the most recent AS reporting "cv=fail", there is no need to proceed and the
algorithm stops here". Test: `A_chain_that_failed_is_not_sealed_again`.

Fixed: a message whose newest seal says cv=fail is returned unchanged.

### A-5
**Closed** in [Vanaheimr/Hermod#260](https://github.com/Vanaheimr/Hermod/pull/260) (`67932b32`).
**The AMS signed ARC header fields if the configuration named them**
(`Arc/ArcSealer.cs:86`, `_config.SignedHeaders.Split(':')`): the list is taken as it is.
RFC 8617 §4.1.2: "ARC-related header fields (ARC-Authentication-Results,
ARC-Message-Signature, and ARC-Seal) MUST NOT be included". Test:
`The_AMS_signs_no_ARC_header_field`.

Fixed: ARC header fields are never in the AMS h=, whatever the configuration lists.

## DMARC reports

RFC 7489 §7 as `DmarcReportService` writes the aggregate report and the failure report
(`DmarcReportTests`, through the service directly; the server feeds it the same
evaluations). Covered without a finding: the report goes to the rua address as a gzipped
`application/gzip` attachment named receiver!policy-domain!begin!end.xml.gz; the subject
names the report domain and the submitter; the XML has feedback, version 1.0, the
metadata, the published policy and one record for two messages alike with their count;
an outside destination receives reports only with its `_report._dmarc` record; a DMARC
failure goes to ruf in the ARF (`Feedback-Type: auth-failure`, `Auth-Failure: dmarc`);
with fo=0 a message that passed is not reported; p=quarantine marks a failing message
(`MessageAuthenticationTests`).

### R-1
**Closed** in [Vanaheimr/Hermod#261](https://github.com/Vanaheimr/Hermod/pull/261) (`631f6a92`).
**The aggregate XML lacked elements Appendix C requires**
(`Reporting/DmarcReportXml.cs:49` to `:87`): `sp` only when published, never `fo`, never
`envelope_from`, never the SPF `scope`. RFC 7489 Appendix C: in `PolicyPublishedType`,
`sp` and `fo` have no minOccurs, so one; in `IdentifierType`, `envelope_from` has
`minOccurs="1"`; in `SPFAuthResultType`, `scope` has `minOccurs="1"`. A reader that
validates against the schema refuses the report; one that does not cannot tell a MAIL
FROM result from a HELO one - a null sender is checked on the HELO identity (V-2). Tests:
`The_XML_has_every_element_the_schema_requires`, four cases.

Fixed: `sp` is always written (p when none is published), and so is `fo` (default "0");
each row carries `envelope_from` (empty for a null sender) and the SPF `scope` (mfrom or
helo). Rows that differ in these are no longer merged into one.

### R-2
**Closed** in [Vanaheimr/Hermod#261](https://github.com/Vanaheimr/Hermod/pull/261) (`ccf11f89`).
**The size limit of a report URI was ignored** (`Reporting/DmarcReportService.cs:278`,
`u.IndexOf('!')`): `!10m` is cut off and not compared. RFC 7489 §7.2.1: "Any reporting URI
that includes a size limitation exceeded by the generated report ... MUST NOT be used";
if none can take it, a short report SHOULD say so (§7.2.2). Test:
`A_destination_whose_size_limit_the_report_exceeds_receives_none`.

Fixed: limits are parsed, k, m, g and t as powers of two. A rua report is measured as
its gzipped, base64-encoded attachment, a ruf report as the whole message; a destination
whose limit it exceeds is not used, and when none can take it, a short report (§7.2.2)
goes to each destination whose limit that fits.

### R-3
**Closed** in [Vanaheimr/Hermod#261](https://github.com/Vanaheimr/Hermod/pull/261) (`9a092e7e`).
**The Report-ID of the subject was no msg-id** (`Reporting/DmarcReportService.cs:114`
and `:164`): `Report-ID: mx.hermod.test!policy.test!1795115900!94c3...`. RFC 7489
§7.2.1.1 makes it a `msg-id`, from RFC 5322: `"<" id-left "@" id-right ">"`. Test:
`The_Report_ID_of_the_subject_is_a_msg_id`.

Fixed: `Report-ID: <…@reporting-domain>`; the XML `report_id` is the same id without the
angle brackets.

### R-4
**Closed** in [Vanaheimr/Hermod#261](https://github.com/Vanaheimr/Hermod/pull/261) (`ccf11f89`).
**The rua of the destination's own record did not replace the policy domain's**
(`DNSVerifications/DNSVerifier.cs:891` to `:892`): the `_report._dmarc` record is looked
for, and only that it begins with v=DMARC1 counts. RFC 7489 §7.1: "If a "rua" or "ruf"
tag is thus discovered, replace the corresponding value extracted from the domain's
DMARC policy record with the one found in this record", on the same host. Test:
`The_destinations_own_rua_replaces_the_policy_domains`.

Fixed: the rua and ruf of the `_report._dmarc` record replace the policy domain's; if
the replacement names another host, neither address is used.

### R-5
**Closed** in [Vanaheimr/Hermod#261](https://github.com/Vanaheimr/Hermod/pull/261) (`2e007a1d`).
**Failure reports lacked fields RFC 7489 requires** (`Reporting/ArfReport.cs:77` to
`:87`): Feedback-Type, Version, Original-Mail-From, Arrival-Date, Source-IP,
Reported-Domain, Auth-Failure and a `Delivered-To` that RFC 5965 does not define - no
Identity-Alignment, no SPF-DNS. RFC 7489 §7.3.1: "Identity-Alignment (REQUIRED ...)",
"SPF-DNS (REQUIRED)", and DKIM-Domain, DKIM-Identity, DKIM-Selector "REQUIRED if the
message was signed by DKIM". Tests: `The_failure_report_has_the_fields_RFC_7489_requires`,
two cases.

Fixed: the reports have Identity-Alignment, SPF-DNS (`txt : domain : "record"`), and
DKIM-Domain, DKIM-Identity and DKIM-Selector when the message was signed. `Delivered-To`
is gone.

### R-6
**Closed** in [Vanaheimr/Hermod#261](https://github.com/Vanaheimr/Hermod/pull/261) (`3c2c40ad`).
**fo= was read and not used** (`Reporting/DmarcReportService.cs:207` and `:212`):
only a message that failed DMARC is reported. RFC 7489 §6.3: fo=1 - "Generate a DMARC
failure report if any underlying authentication mechanism produced something other
than an aligned "pass" result"; d and s for DKIM and SPF failures whatever the
alignment. Test: `With_fo_1_a_failing_SPF_is_reported_although_DMARC_passed`.

Fixed: fo=0 and fo=1 produce DMARC failure reports, fo=d DKIM reports (`Auth-Failure:
signature`), fo=s SPF reports (`Auth-Failure: spf`). The session hands every evaluation
that has a ruf to the reporter, which decides by fo.

### R-7
**Closed** in [Vanaheimr/Hermod#261](https://github.com/Vanaheimr/Hermod/pull/261) (`c88f40a6`).
**p=reject with pct=0 was p=none** (`DNSVerifications/DNSVerifier.cs:855`,
`if (percent <= 0) return "none";`): a failing message is neither refused nor
quarantined. RFC 7489 §6.6.4: under p=reject, for a message pct= does not select, "the
Mail Receiver SHOULD treat the email as though the "quarantine" policy applies" - pct=0
selects none, so every failing message is quarantined. Domains moving to p=reject start
with pct=0 for exactly that. Test: `Under_p_reject_with_pct_0_a_failing_message_is_quarantined`.

Fixed: pct=0 demotes p=reject to quarantine, as it does for every share pct= does not
select.

### R-8
**Closed** in [Vanaheimr/Hermod#316](https://github.com/Vanaheimr/Hermod/pull/316) (`d8df40e6`). **A line break in a report URI went into the report's header and its recipient**
(`Reporting/DmarcReportService.cs:419`: the address of a mailto URI is what follows
"mailto:", as it stands; `:203`: it is the recipient of the report, and `:219`, `:170` and
`ArfReport.cs:65`: its To field; `DNSVerifications/DNSVerifier.cs:1538` keeps a line break
inside a tag value). RFC 7489 §6.4: `dmarc-uri = URI [ "!" 1*DIGIT [ "k" / "m" / "g" / "t"
] ]`, a URI as RFC 3986 has it, which has no CR and no LF; RFC 5322 §2.2: "A field body
MUST NOT include CR and LF except when used in 'folding' and 'unfolding'". The DMARC record
is the policy domain's to publish: `rua=mailto:dmarc@policy.test<CR><LF>Bcc:
victim@policy.test` makes a Bcc field of the report, and a recipient with a line break in
it, which the relay writes into RCPT TO as it is (`SMTPOutboundClient.cs:889`) - the line
break ends the command there, and what follows is a command of its own to the next hop.
Tests: `A_line_break_in_a_report_URI_makes_no_recipient_and_no_header_field` - rua with CR
LF, ruf with CR LF and with LF.

Fixed: the reporter reads a report URI as RFC 6068 §2 has it (`MailtoUri.Addresses`). A
URI with a character RFC 3986 has in none - a line break, a space, a control or a non-ASCII
character - names no address, nor does what decodes to no addr-spec, a percent-encoded
line break among it; the report goes to no such recipient, and no header field comes of it.

### R-9
**Closed** in [Vanaheimr/Hermod#316](https://github.com/Vanaheimr/Hermod/pull/316) (`d8df40e6`). **A mailto URI was taken for an address** (`Reporting/DmarcReportService.cs:419`:
what follows "mailto:", percent-encoding, header fields and all). RFC 7489 §6.2: a comma or
an exclamation point that is part of a DMARC URI "MUST be encoded per Section 2.1 of
[URI]", and a Mail Receiver "MUST implement support for a "mailto:" URI"; RFC 6068 §2:
`mailtoURI = "mailto:" [ to ] [ hfields ]`, `to = addr-spec *("," addr-spec )`, and "A
number of characters that can appear in <addr-spec> MUST be percent-encoded".
`mailto:dmarc%21reports@policy.test` names dmarc!reports@policy.test - the report went to
"dmarc%21reports@policy.test"; `mailto:dmarc@policy.test?subject=DMARC%20report` names
dmarc@policy.test - the report went nowhere, its host taken for
"policy.test?subject=dmarc%20report", outside the policy domain and without its consent.
Tests: `A_report_goes_to_the_address_its_URI_names`, two cases; guard:
`A_report_URI_of_the_usual_kind_names_its_address`.

Fixed: the address is percent-decoded in UTF-8, the URI's header fields are no part of it,
and a `to` header field names addresses too. The error report's Submitting-URI is the
address percent-encoded again (`MailtoUri.Of`).

### R-10
**Closed** in [Vanaheimr/Hermod#316](https://github.com/Vanaheimr/Hermod/pull/316) (`d8df40e6`). **The SPF record went into the failure report as DNS gave it**
(`Reporting/ArfReport.cs:177` to `:180`: SPF-DNS writes the record in quotes, `\` and `"`
escaped, and nothing else; the record as in S-48, `DNSVerifications/DNSVerifier.cs:643`).
RFC 6591 §4: `spf-dns = "SPF-DNS:" [CFWS] ( "txt" / "spf" ) [CFWS] ":" [CFWS] domain [CFWS]
":" [CFWS] quoted-string [CFWS] CRLF`, and a quoted-string (RFC 5322 §3.2.4) has no CR and
no LF but in folding. The SPF record is the sender's to publish: `v=spf1 -all<CR><LF>
Identity-Alignment: dkim, spf` makes a second Identity-Alignment field of the report, one
that says both identities aligned - the escaped quote it ends with notwithstanding; a bare
LF or CR does the same for a reader that takes it for a line end. Tests:
`A_line_break_in_the_SPF_record_makes_no_field_of_the_failure_report` - CR LF, LF, CR;
guard: `An_SPF_record_of_the_usual_kind_is_the_quoted_string_of_SPF_DNS`.

Fixed: SPF-DNS, the DKIM fields and Reported-Domain go through `HeaderField.Of`, the
store's field of S-48, moved for both to share: each run of control characters is one space,
and a line longer than 998 octets is folded before white space.

### R-11
**Closed** in [Vanaheimr/Hermod#316](https://github.com/Vanaheimr/Hermod/pull/316) (`d8df40e6`). **Original-Mail-From was no reverse-path** (`Reporting/ArfReport.cs:88`: the
address of MAIL FROM without its angle brackets). RFC 5965 §3.2: "The format of this field
is defined in section 4.1.2 of [SMTP] as "Reverse-path"", and §3.5: `original-mail-from =
"Original-Mail-From:" [CFWS] reverse-path [CFWS] CRLF`; RFC 5321 §4.1.2: `Reverse-path =
Path / "<>"`, `Path = "<" [ A-d-l ":" ] Mailbox ">"`. The report says
`Original-Mail-From: news@policy.test`; the null reverse-path was `<>` already. Test:
`Original_Mail_From_is_a_reverse_path`; guard:
`For_a_null_reverse_path_Original_Mail_From_is_empty_angle_brackets`.

Fixed: Original-Mail-From is the reverse-path, the mailbox in angle brackets, `<>` for the
null one.

### R-12
**Closed** in [Vanaheimr/Hermod#316](https://github.com/Vanaheimr/Hermod/pull/316) (`d8df40e6`). **An IPv6 Source-IP was no IPv6 address literal** (`Reporting/ArfReport.cs:90`:
the address as .NET writes it). RFC 5965 §3.5: `source-ip = "Source-IP:" [CFWS] (
IPv4-address-literal / IPv6-address-literal ) [CFWS] CRLF`; RFC 5321 §4.1.3:
`IPv6-address-literal = "IPv6:" IPv6-addr`. The failure report for a message from
2001:db8::25 says `Source-IP: 2001:db8::25`. Test:
`An_IPv6_Source_IP_is_an_IPv6_address_literal`; guard: `An_IPv4_Source_IP_is_its_dotted_quad`.

Fixed: Source-IP is an address literal: "IPv6:" before an IPv6 address, an IPv4 address
mapped into IPv6 the IPv4 address, and a scope dropped.

### R-13
**Closed** in [Vanaheimr/Hermod#332](https://github.com/Vanaheimr/Hermod/pull/332) (`b5141d6c`). **A failure report was sent in answer to an ARF report** (`SMTPSession.cs:1353`:
every message DMARC evaluated under a policy with ruf= goes to the reporter;
`Reporting/DmarcReportService.cs:260` to `:271`: fo= and the hourly budget decide, not what
the message is). RFC 6650 §6, for reports "of messages that fail particular message
authentication checks" that automation sends: "If the message under evaluation by the
Verifier is an ARF [RFC5965] message, a report MUST NOT be automatically generated"; RFC
5965 §2: an ARF message is a multipart/report of report-type "feedback-report"; RFC 7489
§7.3: a DMARC failure report is one (RFC 6591). A failure report from another receiver, or
an abuse report, that fails DMARC at a domain whose policy asks for failure reports is
answered with a failure report - and two reporters that answer reports so send them back
and forth. Tests: `No_failure_report_is_sent_in_answer_to_an_ARF_report` - a DMARC failure
report, an abuse report, the media type in capitals with report-type quoted; guard:
`A_DSN_that_fails_DMARC_is_reported`.

Fixed: `ArfReport.IsArfMessage` says whether a message is an ARF report - multipart/report,
report-type "feedback-report", case-insensitive -, and `SendForensicAsync` asks it before
anything else: no DMARC, DKIM or SPF failure report in answer to one, and nothing taken from
the budget. A DSN, an MDN, a message that is no report are reported as before.

### R-14
**Closed** in [Vanaheimr/Hermod#332](https://github.com/Vanaheimr/Hermod/pull/332) (`b5141d6c`). **A failure report was labelled Auto-Submitted: auto-generated**
(`Reporting/ArfReport.cs:69`). RFC 3834 §5.2: auto-generated "MUST NOT be used on a message
issued in direct response to another message", nor "to label [...] other reports of message
(non)receipt or (non)delivery"; auto-replied "SHOULD be used on messages sent in direct
response to another message by an automatic process". A failure report is about one
message, "generated and sent almost immediately after the Mail Receiver detects a DMARC
failure" (RFC 7489 §7.3) - the DMARC, the DKIM and the SPF failure report alike. The
aggregate report, sent once a day about all of them, is auto-generated, as it should be.
Tests: `A_failure_report_is_auto_replied` - fo=0, d, s; guard:
`The_aggregate_report_is_auto_generated`.

Fixed: the failure report - DMARC, DKIM and SPF - says `Auto-Submitted: auto-replied`; the
aggregate report stays auto-generated.

## TLS reporting

RFC 8460 as `TlsRptReportService` reports (`TlsRptTests`, through the service directly;
the outbound client feeds it the same events) and as `SMTPOutboundClient` records
sessions (`OutboundClientTests.TlsRpt.cs`). Covered without a finding: the report goes
to the record's mailto address, with https URIs and unknown fields beside it; no record,
no report; the mail is multipart/report; report-type="tlsrpt" with an
application/tlsrpt+gzip part, TLS-Report-Domain and TLS-Report-Submitter, the subject of
§5.3 and the filename of §5.1; the JSON has the fields of §4.4 with RFC 3339 dates and
the counts; under an enforced MTA-STS policy an untrusted certificate is a reported
failure, and the delivery waits.

### T-1
**Closed** in [Vanaheimr/Hermod#262](https://github.com/Vanaheimr/Hermod/pull/262) (`88f26f73`).
**A domain without exactly one valid record still got reports**
(`Reporting/TlsRptResolver.cs:77`, the first record that contains "v=TLSRPTv1" in any
case, and `:107`): two records, `rua=...; v=TLSRPTv1`, or `v=tlsrptv1` each name a
destination. RFC 8460 §3: "records that do not begin with "v=TLSRPTv1;" are discarded"
(`%s`, case-sensitive), and "If the number of resulting records is not one, senders MUST
assume the recipient domain does not implement TLSRPT". Tests:
`A_domain_without_exactly_one_valid_record_gets_no_report`, three cases.

Fixed: only records that begin with `v=TLSRPTv1` and `;`, whitespace before the `;`
allowed, count, and only if exactly one does; `rua=` must be lower case.

### T-2
**Closed** in [Vanaheimr/Hermod#262](https://github.com/Vanaheimr/Hermod/pull/262) (`7807bf38`).
**No policy-string in the JSON** (`Reporting/TlsRptReportJson.cs:66` to `:74`):
policy-type, mx-host and policy-domain only. RFC 8460 §4.4 lists policy-type,
policy-string, policy-domain and mx-host for the policy object, none marked optional;
policy-string is the policy applied, as a JSON array of strings - the receiver sees
which policy version the sender had. Test: `Each_policy_says_which_policy_was_applied`.

Fixed: every policy has `policy-string`: the lines of the MTA-STS policy, the TLSA
records as "usage selector matching HEX", or an empty array for no-policy-found.
Policies with different strings are reported in separate blocks; state files from before
load as they did.

### T-3
**Closed** in [Vanaheimr/Hermod#262](https://github.com/Vanaheimr/Hermod/pull/262) (`28252dc9`).
**In MTA-STS testing mode a failed policy was reported as a success**
(`SMTPOutboundClient.cs:445`, `validateStrict = mustEnforceTls || ...`, and `:490`,
`RecordTls(true, null)`): testing mode delivers over TLS whatever the certificate - as
it should - and then records the session as one that went well. RFC 8461 §5: in
testing mode "Sending MTAs that also implement the TLSRPT specification [RFC8460] send
a report indicating policy application failures"; testing mode is there for that
report. Test: `In_testing_mode_an_untrusted_certificate_is_reported_as_a_failure`.

Fixed: delivery is unchanged; the report records `certificate-expired`,
`certificate-host-mismatch`, `certificate-not-trusted`, `starttls-not-supported`, or
`validation-failure` for an MX host the policy does not name. In testing mode STARTTLS
is tried even with `PreferStartTls` off, and under enforce the failure, too, says what
failed.

### T-4
**Closed** in [Vanaheimr/Hermod#262](https://github.com/Vanaheimr/Hermod/pull/262) (`4430e687`).
**Through a smart host the session was reported to the recipient's domain**
(`SMTPOutboundClient.cs:223`, `targetDomain` where `TrySendToMxAsync` takes the policy
domain, `:285`): the MTA-STS policy is the smart host's (`:136`, RFC 8461 §3.4), the
event names the recipient's domain - whose rua then receives a report on a policy it did
not publish. RFC 8460 §4.4: policy-domain is "The Policy Domain against which the
MTA-STS or DANE policy is defined". Test:
`Through_a_smart_host_the_session_is_reported_to_the_smart_hosts_domain`.

Fixed: `TrySendToMxAsync` takes the next-hop domain, for the DANE reference identifiers,
and the policy domain, for TLS-RPT, separately.

### T-5
**Closed** in [Vanaheimr/Hermod#316](https://github.com/Vanaheimr/Hermod/pull/316) (`d8df40e6`). **A line break in an rua URI went into the report's header and its recipient**
(`Reporting/TlsRptResolver.cs:130`: the address of a mailto URI is what follows "mailto:",
as it stands; `TlsRptReportService.cs:136`: it is the recipient of the report, `:159`: its
To field). RFC 8460 §3: `tlsrpt-uri = URI`, "imported from [RFC3986]", which has no CR and
no LF; RFC 5322 §2.2: "A field body MUST NOT include CR and LF except when used in
'folding' and 'unfolding'". The TLSRPT record is the recipient domain's to publish:
`rua=mailto:tlsrpt@policy.test<CR><LF>Bcc: victim@policy.test` makes a Bcc field of the
report, and a recipient with a line break in it, which the relay writes into RCPT TO as it
is (`SMTPOutboundClient.cs:889`), a command of its own after it. Tests:
`A_line_break_in_an_rua_URI_makes_no_recipient_and_no_header_field` - CR LF, LF.

Fixed: as R-8 - the resolver reads an rua URI with `MailtoUri.Addresses`, and one with a
line break in it names no recipient.

### T-6
**Closed** in [Vanaheimr/Hermod#316](https://github.com/Vanaheimr/Hermod/pull/316) (`d8df40e6`). **A mailto URI was taken for an address** (`Reporting/TlsRptResolver.cs:130`).
RFC 8460 §3: "In the case of "mailto", reports should be submitted to the specified email
address [RFC6068]", and of a tlsrpt-uri: "commas (ASCII 0x2C), exclamation points (ASCII
0x21), and semicolons (ASCII 0x3B) MUST be encoded"; RFC 6068 §2 as in R-9.
`mailto:tls%21reports@policy.test` - the report went to "tls%21reports@policy.test";
`mailto:tlsrpt@policy.test?subject=TLS%20report` - to
"tlsrpt@policy.test?subject=TLS%20report". Tests:
`A_report_goes_to_the_address_its_rua_URI_names`, two cases.

Fixed: as R-9 - percent-decoded, its header fields no part of the address, and one address
named twice reported to once.

## Priorities and limits

RFC 6710 MT-PRIORITY on the server (`PriorityTests`), and the connection and recipient
limits (`LimitTests.cs`). Covered without a finding: EHLO announces MT-PRIORITY; -9 to 9
are taken, 10, -10, a word and nothing refused with 501; the relay queue carries the
priority a client that signed in asked for; 100 recipients are taken in one message and
the 101st refused with 452 4.5.3; a connection over the limit per address gets 421 and
is closed.

### Q-1
**Closed** in [Vanaheimr/Hermod#263](https://github.com/Vanaheimr/Hermod/pull/263) (`625d1094`).
**Values the grammar does not produce were taken** (`ESMTPParameters.cs:149`,
`Int32.TryParse(value, ...) && priority is >= -9 and <= 9 && value.Length <= 2`): `+3`,
`-0` and `05` are 250. RFC 6710 §7: `priority-value = (["-"] NZDIGIT) / "0"`; §4.1: the
server MUST return an error for a syntactically invalid value. Tests:
`A_value_the_grammar_does_not_produce_is_refused`, three cases.

Fixed: only values the grammar produces are taken; anything else is 501 5.5.4.

### Q-2
**Closed** in [Vanaheimr/Hermod#263](https://github.com/Vanaheimr/Hermod/pull/263) (`625d1094`).
**MT-PRIORITY twice was taken** (`ESMTPParameters.cs:95`): a second parameter with
the same value passes. RFC 6710 §4.1: the server MUST return an error "if there is more
than one MT-PRIORITY parameter". Test: `MT_PRIORITY_twice_is_refused`.

Fixed: 501 5.5.4. For other parameters an identical repeat is still tolerated -
CPython's smtplib repeats SMTPUTF8.

### Q-3
**Closed** in [Vanaheimr/Hermod#263](https://github.com/Vanaheimr/Hermod/pull/263) (`bc71f855`).
**A client nobody vouched for raised its own priority** (`SMTPSession.cs:725`,
`_mtPriority = MtPriority.ParseFromMailParams(parameters)`, and `:1444`): the value is
kept whoever asks, and goes into the relay queue - whose retries `FileMailQueue` hands out
by it, and on to the next hop.
RFC 6710 §4.1: the server "MUST NOT allow "upgraded" (positive) priorities from
untrusted" senders; it may let them lower their own. It matters where a client may relay
without AUTH. Test: `A_client_nobody_vouches_for_does_not_raise_its_priority`.

Fixed: a session that signed in is trusted, any other is not. A positive priority from
an untrusted client becomes 0, and MAIL answers `250 2.3.6 0 Priority lowered: …`, the
new priority first; such a client may still lower its priority (§4.1 MAY).

### Q-4
**Closed** in [Vanaheimr/Hermod#263](https://github.com/Vanaheimr/Hermod/pull/263) (`bc71f855`).
**No PRIORITY clause in Received** (`SMTPSession.cs:1562`, `BuildReceivedHeaderAsync`):
RFC 6710 §4.1: an MTA SHOULD record the priority in the Received field,
`Pri = CFWS "PRIORITY" FWS priority-value`. Test: `The_Received_field_names_the_priority`.

Fixed: when MAIL carried MT-PRIORITY, Received has `PRIORITY n` after the for-clause,
where RFC 5321 §4.4 places additional clauses; n is the priority the message is relayed
with.

### L-1
**Closed** in [Vanaheimr/Hermod#264](https://github.com/Vanaheimr/Hermod/pull/264) (`25b05a7c`).
**100 recipients per session, not per message** (`SMTPSession.cs:770` and `:772`,
`_counters.Recipients >= rateLimitConfig.MaxRcptPerSession`, the counter never reset):
after 60 recipients in a first message, a second message in the same session is refused
its 41st with `452 4.5.3 Too many recipients in this session`. RFC 5321 §4.5.3.1.8: "The
minimum total number of recipients that MUST be buffered is 100 recipients" - for each
message. Test: `A_second_message_in_the_session_takes_its_own_recipients`.

Fixed: one message is limited by `MaxRecipients` (100, then 452 4.5.3) as before.
`MaxRcptPerSession` is checked at MAIL, the way `MaxMessagesPerSession` is: once it is
reached, the next MAIL gets 421 4.7.0 and the session ends, so a message is never cut
short. Its default is now 1000.

### L-2
**Closed** in [Vanaheimr/Hermod#264](https://github.com/Vanaheimr/Hermod/pull/264) (`8234c63f`).
**The reply to a connection refused at accept ended in a bare LF**
(`SMTPServer.cs:290` and `:299`, `new StreamWriter(...)` and `WriteLineAsync(message)`):
the platform's line end - CR LF on Windows, LF on Linux. RFC 5321 §2.3.8: lines are
"terminated by the sequence ASCII character "CR" (hex 0D) followed immediately by ASCII
character "LF" (hex 0A)". Test: `The_421_of_a_refused_connection_ends_in_CRLF` - it
passes on Windows and fails on Linux, where the nightly runs it.

Fixed: `WriteReplyAsync` writes CR LF; no other wire writer used the platform's line
end.

### L-3
**Closed** in [Vanaheimr/Hermod#264](https://github.com/Vanaheimr/Hermod/pull/264) (`dd8e2314`).
**After a 554 greeting the connection was closed at once** (`SMTPServer.cs:292` and
`:304`): RFC 5321 §3.1: a server that answers a connection with 554 "MUST still wait for
the client to send a QUIT ... before closing the connection and SHOULD respond to any
intervening commands with "503 bad sequence of commands"". Test:
`After_554_the_server_waits_for_QUIT`.

Fixed: the 554 connection is held beside the accept loop: QUIT gets 221, every other
line 503 5.5.1. The hold is bounded - 30 s in all, 10 commands, lines no longer than
`MaxCommandLineLength`, at most `MaxTotalConnections` refusals held at once; beyond that
the server sends the 554 and closes, as before. A 421 refusal still closes at once.

### L-4
**Closed** in [Vanaheimr/Hermod#264](https://github.com/Vanaheimr/Hermod/pull/264) (`c0aa1a1e`).
**After a 421 to AUTH the connection stayed open** (`SMTPSession.cs:282`): the
reply is sent, the session goes on, and answers the next command. RFC 5321 §3.8: 421
means the server is closing the transmission channel - the client stops, the server
holds a connection it said it would close. Test: `After_421_to_AUTH_the_connection_is_closed`.

Fixed: the session ends, as at every other 421.

## Outbound security

`SMTPOutboundClient` with `PublicAddressesOnly`, smart host credentials, and DKIM
signing (`OutboundClientTests.Security.cs`, `OutboundClientTests.Dkim.cs`). Covered
without a finding: loopback, private, shared, link-local, benchmarking, "this host",
ULA, IPv6 documentation, and the loopback inside mapped, NAT64 and 6to4 addresses are
not connected to; a smart host on the loopback is; the password goes to a smart host
only over TLS whose certificate is valid for its name - not across a network without
STARTTLS, not to a certificate for another name or one nobody vouches for. RSA and
Ed25519 signatures (RFC 8463), the key of the From: domain, and an 8-bit body verify with
the suite's own verifier. `FileMailQueueTests` open the queue after a crash at each place
it can come; `CertificateChainTests` see the intermediates of a fullchain.pem sent, and a
renewed certificate presented without a restart.

### P-1
**Closed** in [Vanaheimr/Hermod#257](https://github.com/Vanaheimr/Hermod/pull/257) (`106b61b7`).
**The IPv4 documentation ranges counted as public** (`Hermod/IP/PublicAddresses.cs:92`
to `:101`): the list leaves out 192.0.0.0/24 (`octets[2] == 0`), but not 192.0.2.0/24
beside it, nor 198.51.100.0/24 and 203.0.113.0/24 - while 2001:db8::/32, their IPv6
counterpart, is left out. RFC 6890 §2.2.2 lists all three with "Global:
False", and RFC 5737 §3: "Addresses within the TEST-NET-1, TEST-NET-2, and TEST-NET-3
blocks SHOULD NOT appear on the public Internet". With `PublicAddressesOnly`, an MX host
at such an address is connected to - the delivery waits for a timeout and is tried
again, instead of bouncing with 5.4.4 as for every other address that is not public.
Tests: `An_MX_host_without_a_public_address_is_not_connected_to`, three cases.

Fixed: 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 are not public, also mapped into
IPv6 or inside 6to4; such an MX bounces at once with 5.4.4.

The eighth round's key tests (`OutboundClientTests.DkimKeys.cs`) give `DkimSigner` a key of 512 bits and read what `DkimKeyGenerator` and `DkimKeyMaterial` make. Covered without a finding: both make keys of 2048 bits by default, and the generated record names the generated key.

### P-2
**Closed** in [Vanaheimr/Hermod#281](https://github.com/Vanaheimr/Hermod/pull/281)
(`f25adfbf`). **Hermod signed with, and made, RSA keys of fewer than 1024 bits**
(`DNSVerifications/DkimSigner.cs:63` and `:64`, `DNSVerifications/DkimKeyGenerator.cs:35`,
`DNSVerifications/DkimKeyMaterial.cs:51`): `DkimSigner` imports the RSA key it is given
whatever its size, and `DkimKeyGenerator.GenerateKeyPair` and `DkimKeyMaterial.NewRsaPem`
make a key of any size asked for. RFC 8301 §3.2: "Signers MUST use RSA keys of at least
1024 bits for all keys. Signers SHOULD use RSA keys of at least 2048 bits." The mail of a
domain that signs with 512 bits counts as unsigned at every verifier that keeps to RFC
8301, while anyone who factors the key can sign as the domain where one does not (V-14).
Tests: `The_signer_does_not_sign_with_a_key_of_512_bits`,
`The_key_generators_do_not_make_a_key_of_512_bits`;
`The_key_generators_make_keys_of_2048_bits_by_default` is the guard.

Fixed: `DkimKeyMaterial.MinimumRsaKeySize` is 1024: below it the generators throw an
`ArgumentOutOfRangeException`, and `DkimSigner` an `ArgumentException` for the RSA key.

### P-3
**Closed** in [Vanaheimr/Hermod#281](https://github.com/Vanaheimr/Hermod/pull/281)
(`f25adfbf`). **The generated key record was one character-string of 410 characters**
(`DNSVerifications/DkimKeyGenerator.cs:45`): the zone file line is
`selector._domainkey.domain. IN TXT "v=DKIM1; k=rsa; p=..."`, the p= of a 2048-bit key 392
base64 characters. RFC 1035 §3.3: "<character-string> is a single length octet followed by
that number of characters" - 255 at most, so a zone holding the line as it is written
cannot be loaded. RFC 6376 §3.6.2.2: "Strings in a TXT RR MUST be concatenated together
before use with no intervening whitespace" - a long record is written in several strings;
Hermod's own `TXT.PresentationOf` does that. Test:
`The_generated_key_record_is_written_in_strings_of_at_most_255_characters`;
`The_generated_key_record_names_the_generated_key` is the guard.

Fixed: the record is written with `TXT.PresentationOf`, in strings of at most 255 octets.

## MIME and the message format

RFC 2045, 2046, 2047, 2231, 5322 and 2919 as Hermod builds and reads mail:
`MimeMessageBuilder` and the older `TextEMailBuilder`/`HTMLEMailBuilder` (whose
`EMail.ToText()` `MailSender` sends), read back with the suite's own `MessageGrammar`;
`MimeMessage.Parse`, `MailboxAddress`, `MimeDate`, `EncodedWords`, `MimeContentType`,
`TransferEncodings`, `MailReplies` and the older `EMail.Parse` (which
`MdnGeneratingMailStorage` runs on every message it stores) fed what a foreign sender may
legally write, and hostile input with timeouts (`MimeEncodingTests`, `MimeHeaderTests`,
`MimeStructureTests`, `MessageBuilderTests`). Covered without a finding: quoted-printable
lines of at most 76 characters, no white space at a line end, every other octet escaped in
upper case, decoding to the text it encodes; base64 in lines of 76, decoded past line breaks
and stray characters; the encoded words of RFC 2047 §8 (comments, white space between
adjacent words ignored, `_` as a space, B and Q, two charsets in one subject) and the RFC
2231 §5 language suffix; encoded words Hermod writes at most 75 characters, on lines of at
most 76, only phrase-safe characters in a display name, no character split between two
words, reading back as written; RFC 2231 continuations, charset/language and the §4.1 mix, a
non-ASCII file name written as an extended-initial-value; unfolding and the obsolete white
space of A.6.3; the dates of Appendix A and the obsolete dates of §4.3 (two- and three-digit
years, UT/GMT/EST…/PDT, military zones) in `MimeMessage`, the current ones in `EMail`; the
mailboxes and groups of A.1, the empty group of A.5, the source route of A.6.1, a comment
after the angle-addr in RFC 2047 §8; msg-ids with CFWS and a no-fold-literal, In-Reply-To
and References with obsolete phrases, a reply's In-Reply-To and References from a parent
with References, one "Re: "; boundaries Hermod writes of the RFC 2046 grammar, absent from
the parts, no prefix of each other, parts split where written, `message/rfc822` in
7bit/8bit, non-ASCII text as quoted-printable UTF-8; the RFC 2046 §5.1.1 example (implicit
typing, preamble, epilogue, the CRLF before a delimiter), transport padding in
`MimeMessage`, the text/plain us-ascii default, `multipart/digest` parts as messages; Date
and From once and every singular field at most once, `MIME-Version: 1.0`, header fields of
printable ASCII in CRLF lines folded to 78, a date-time with the right weekday and zone,
msg-ids of the grammar, a built message reading back as built, header values with a line
break refused; and in time: a 4 MB encoded word, 400 000 unfinished ones, 200 000 parameter
sections, a Content-Type comment a million deep, multiparts and `message/rfc822` 5000 deep,
100 000 parts, a missing close delimiter.

### E-1
**Closed** in [Vanaheimr/Hermod#269](https://github.com/Vanaheimr/Hermod/pull/269) (`f627d5a3`).
**A comment after the address named the mailbox**
(`EMail/Mime/MailboxAddress.cs:107` and `:113`, used by
`DNSVerifications/DkimSigning.cs:58`): `Parse` takes the address from the *last* `<` outside
quotes - `var lt = LastTopLevel(Mailbox, '<')` - which does not skip comments, and keeps
whatever is between `<` and `>`: `Mailbox[(lt + 1)..gt]`, no comment removed; a bare
addr-spec keeps its obsolete white space too. RFC 5322 §3.4: `angle-addr = [CFWS] "<"
addr-spec ">" [CFWS]` - a comment after the address is CFWS, not a mailbox; Appendix A.5 and
A.6.3 read `<pete(his account)@silly.test(his host)>` as pete@silly.test and
`<jdoe@machine(comment).  example>` as jdoe@machine.example; §4: obsolete forms "MUST be
accepted and parsed by a conformant receiver". So `From: mallory@evil.example
(<ceo@company.example>)` - whose author is mallory@evil.example for every RFC 5322 reader
and for Hermod's own DMARC check (`MailAddressParser`) - is ceo@company.example in
`MimeMessage.From`, `EMail.From` and `DkimSigning.FromDomain`. An application shows and
answers a sender the DMARC check never saw, and the outbound relay signs with the DKIM key
of company.example, a domain the From does not name: on a relay with keys for several
domains, anyone who may submit gets a valid signature of another domain over a text of his
own. `Alice <alice@example.org> (sent via <mallory@evil.example>)` goes to mallory, display
name "Alice <alice@example.org>". Tests: `Comments_are_no_part_of_the_address` (six cases:
A.5 twice, A.6.1, A.6.3, two comments after the address),
`The_DKIM_signing_domain_is_the_From_domain_RFC_5322_reads`.

Fixed: the `<` and `>` of the angle-addr are looked for outside quotes and comments, and
the addr-spec is read by the new `MailAddressParser.NormalizeAddrSpec`: comments and the
white space around words, dots and `@` go. `mallory@evil.example
(<ceo@company.example>)` is mallory@evil.example in `MimeMessage`, `EMail`, the read
receipt and `DkimSigning`, as for the DMARC check. In the old form `addr (Name)` a
comment that holds an `@` names nobody.

### E-2
**Closed** in [Vanaheimr/Hermod#269](https://github.com/Vanaheimr/Hermod/pull/269) (`3cdea7d4`).
**A date with nested comments took quadratic time**
(`EMail/Mime/MimeDate.cs:76`): `while (Comment.IsMatch(text)) text = Comment.Replace(text, "
");` with `Comment` = `\([^()]*\)` removes one level per pass and copies the whole value
each time - a comment n deep costs n passes over 2n characters. RFC 5322 §3.2.2: `comment =
"(" *([FWS] ccontent) [FWS] ")"`, `ccontent = ctext / quoted-pair / comment` - nesting is
legal at any depth. A 16 KB Date takes 3.3 s in `MimeMessage.Parse`, 1 MB takes hours; the
sender writes the Date, and every application reading mail with `MimeMessage.Parse` hangs on
it (the server itself does not call it). Test:
`A_date_with_deeply_nested_comments_is_parsed_in_time` (no result after 2 s).

Fixed: one pass turns every comment, however deep, into a space; a Date with a comment
10 000 deep is read at once.

### E-3
**Closed** in [Vanaheimr/Hermod#270](https://github.com/Vanaheimr/Hermod/pull/270) (`c2c3d7b3`).
**Header lines of more than 998 characters** (`EMail/Mime/MimeEncoding.cs:218`,
`:253` and `:332`): `Fold` breaks only between the pieces it is given - for ASCII
`Text.Split(' ')` - so a piece longer than a line stays one line; `Parameter` writes a
non-ASCII value as one `name*=utf-8''…` without RFC 2231 continuations. RFC 5322 §2.1.1:
"Each line of characters MUST be no more than 998 characters". A subject holding a URL of
1200 characters is a line of 1221 (`MimeMessageBuilder` and `TextEMailBuilder`); an
`Autocrypt` header - which the builder names as what `Headers` is for - with 3000 characters
of key data a line of 3009; an attachment named in 120 Chinese characters a `filename*=`
line of 1102. Relays cut, wrap or refuse such lines; a cut breaks the DKIM signature.
Encoded words and RFC 2231 §3 continuations exist for this. Tests:
`No_line_is_longer_than_998_characters`, four cases.

Fixed: a piece too long for a line is broken where the field's grammar allows: free text
and a display name as encoded words, a parameter in RFC 2231 continuations, a long ASCII
word in a further header of `MimeMessageBuilder` folded inside; `Fold` refuses what has
no place to fold, such as a message id that long.

### E-4
**Closed** in [Vanaheimr/Hermod#270](https://github.com/Vanaheimr/Hermod/pull/270) (`789aab82`).
**The older builders' boundary held `<`**
(`EMail/Helpers/MailContentType.cs:235`): `MIMEBoundary = "-8<--" + ContentType… + "--8<--"
+ … + "--8<-"`. RFC 2046 §5.1.1: `boundary := 0*69<bchars> bcharsnospace`, `bcharsnospace :=
DIGIT / ALPHA / "'" / "(" / ")" / "+" / "_" / "," / "-" / "." / "/" / ":" / "=" / "?"` - "a
set of characters known to be very robust through mail gateways"; `<` is not among them.
Every multipart `TextEMailBuilder`/`HTMLEMailBuilder` write (text with HTML, attachments,
PGP/MIME) carries one; a reader holding to the grammar finds no parts. Test:
`The_older_builders_boundary_follows_the_grammar`.

Fixed: the older builders take the MIME writer's boundary, `=_` and 32 hex digits.

### E-5
**Closed** in [Vanaheimr/Hermod#269](https://github.com/Vanaheimr/Hermod/pull/269) (`d51d3a28`).
**`EMail.Parse` threw on transport padding and on a multipart without delimiters**
(`EMail/Helpers/EMailBodypart.cs:183` and `:195`): a delimiter is `line == "--"
+ boundary`, exactly, so one with spaces or a tab after it is none; with none found,
`this.MailBody = listOfList[0]` indexes an empty list - `ArgumentOutOfRangeException`. RFC
2046 §5.1.1: `transport-padding := *LWSP-char ; Composers MUST NOT generate non-zero length
transport padding, but receivers MUST be able to handle padding added by message
transports`; "If a boundary delimiter line appears to end with white space, the white space
must be presumed to have been added by a gateway, and must be deleted". A padded message, or
any multipart without delimiter lines, makes `EMail.Parse` throw -
`MdnGeneratingMailStorage` catches it and sends no read receipt; an application gets the
exception. Tests: `Delimiter_lines_with_transport_padding_are_read_by_EMail`,
`A_multipart_without_delimiters_is_read_by_EMail`.

Fixed: spaces and tabs at the end of a line are ignored when it is compared with the
delimiters, and a multipart without a delimiter line keeps its body and has no parts.

### E-6
**Closed** in [Vanaheimr/Hermod#269](https://github.com/Vanaheimr/Hermod/pull/269) (`3cdea7d4`).
**White space or a comment inside the time made it 00:00:00**
(`EMail/Mime/MimeDate.cs:79` and `:93`): the value is split into tokens at white space and
the time must be one token matching `^(\d{1,2}):(\d{2})(?::(\d{2}))?$`; `09 : 55 : 06` is
five tokens, none a time, and the date comes back without its time - silently wrong. RFC
5322 §4.3: `obs-hour = [CFWS] 2DIGIT [CFWS]`, `obs-minute`, `obs-second` alike; A.6.3 `Date
: Fri, 21 Nov 1997 09(comment):   55  :  06 -0600`; §4: "MUST be accepted and parsed by a
conformant receiver". Tests: `White_space_and_comments_inside_the_time_are_parsed`, two
cases.

Fixed: the white space around the colons of the time is removed after the comments, so
`09(comment):   55  :  06` is 09:55:06.

### E-7
**Closed** in [Vanaheimr/Hermod#269](https://github.com/Vanaheimr/Hermod/pull/269) (`da5e79b2`).
**`EMail.Parse` did not read obsolete zones or comments in the time**
(`EMail/EMail.cs:161`, `ParseDate`): only a trailing comment is removed, the rest goes to
`DateTimeOffset.TryParseExact`/`TryParse`, which know neither "EST" nor "UT" nor CFWS in the
time; Date is then `default` - 0001-01-01. RFC 5322 §4.3: `obs-zone = "UT" / "GMT" / "EST" /
"EDT" / "CST" / "CDT" / "MST" / "MDT" / "PST" / "PDT" / …`; `obs-hour = [CFWS] 2DIGIT
[CFWS]`; §4: "MUST be accepted and parsed". `MimeMessage` reads the zones, `EMail` does not.
Tests: `An_obsolete_date_is_parsed_by_EMail`, four cases.

Fixed: `EMail.ParseDate` asks `MimeDate` first, and the .NET parsers only for what it
does not read.

### E-8
**Closed** in [Vanaheimr/Hermod#269](https://github.com/Vanaheimr/Hermod/pull/269) (`b879bcb0`).
**An obsolete msg-id was kept as raw text** (`EMail/Mime/MimeMessage.cs:272` and
`:371`): `MessageIdPattern = <([^<>\s]+)>` allows no white space or comment inside the
brackets; without a match `MessageId` is the whole header value, brackets and blanks
included - which a reply cannot name (`MimeMessageBuilder` refuses it). RFC 5322 §4.5.4:
`obs-id-left = local-part`, `obs-id-right = domain`; A.6.3 `Message-ID  : <1234   @
local(blah)  .machine .example>` is 1234@local.machine.example; §4: "MUST be accepted and
parsed". Test: `An_obsolete_message_id_is_read`.

Fixed: msg-ids are read in one walk over the value that skips quoted phrases and
comments, and what is between `<` and `>` goes through `NormalizeAddrSpec`.

### E-9
**Closed** in [Vanaheimr/Hermod#270](https://github.com/Vanaheimr/Hermod/pull/270) (`54257198`).
**A reply to a parent without References forgot its In-Reply-To**
(`EMail/Mime/MailReplies.cs:123`): `var thread =
Original.References.Concat(Original.MessageId…)` - the parent's In-Reply-To is never looked
at. RFC 5322 §3.6.4: a reply "SHOULD have "In-Reply-To:" and "References:" fields as
appropriate", constructed so that "If the parent message does not contain a "References:"
field but does have an "In-Reply-To:" field containing a single message identifier, then the
"References:" field will contain the contents of the parent's "In-Reply-To:" field followed
by the contents of the parent's "Message-ID:" field". Replies to mail from programs that
write only In-Reply-To lose the thread's first message. Test:
`A_reply_to_a_parent_without_References_takes_its_In_Reply_To`.

Fixed: a parent without References but with one id in In-Reply-To gives that id followed
by its Message-ID.

### E-10
**Closed** in [Vanaheimr/Hermod#269](https://github.com/Vanaheimr/Hermod/pull/269) (`a2815740`).
**A part with an unknown Content-Transfer-Encoding was shown as text**
(`EMail/Mime/TransferEncodings.cs:48`, `EMail/Mime/MimeMessage.cs:685`): an encoding other
than base64/quoted-printable is taken as the octets themselves (`_ => Body.ToArray()`), and
the part stays `text/plain` - `TextBody`, not an attachment. RFC 2045 §6.4: "Any entity with
an unrecognized Content-Transfer-Encoding must be treated as if it has a Content-Type of
"application/octet-stream", regardless of what the Content-Type header field actually says".
Test: `A_part_with_an_unknown_transfer_encoding_is_no_text`.

Fixed: such a part is application/octet-stream, its parameters kept - an attachment.

### E-11
**Closed** in [Vanaheimr/Hermod#269](https://github.com/Vanaheimr/Hermod/pull/269) (`c9d139bb`).
**Quoted-printable decoding kept trailing white space**
(`EMail/Mime/TransferEncodings.cs:115`): every octet but "=" is copied. RFC 2045 §6.7 rule
3: "when decoding a Quoted-Printable body, any trailing white space on a line must be
deleted, as it will necessarily have been added by intermediate transport agents". Test:
`Trailing_white_space_is_deleted_when_decoding`.

Fixed: spaces and tabs before a line end or the end of the body are deleted; `=20`,
`=09` and the white space before a soft line break stay.

### E-12
**Closed** in [Vanaheimr/Hermod#270](https://github.com/Vanaheimr/Hermod/pull/270) (`e0181d57`).
**`MimeMessageBuilder` wrote a singular field twice**
(`EMail/Mime/MimeMessageBuilder.cs:163` to `:165`): the further `Headers` are checked only
for a valid name (`IsFieldName`) and written after the builder's own, so
`Headers.Add(("From", …))` gives two From fields - though the builder's remarks say refusing
line breaks is to stop "a second From:, a Bcc:" being smuggled in. RFC 5322 §3.6: orig-date
and from have a maximum of 1, as have sender, reply-to, to, cc, bcc, message-id,
in-reply-to, references, subject. Readers pick different ones (Hermod's `MimeMessage` the
first). Tests: `A_singular_field_among_the_further_headers_is_not_written_twice`, five
cases.

Fixed: a further header named like a field of maximum one is refused with an
`ArgumentException`; each of them is written from its own property only.

### E-13
**Closed** in [Vanaheimr/Hermod#270](https://github.com/Vanaheimr/Hermod/pull/270) (`a16dfd1a`).
**The older builders wrote the List-ID description raw** (`EMail/Builder.cs:448`,
`EMail/Helpers/ListId.cs:65`): `SetEMailHeader("List-ID", ListId.Value.ToString())`, `Value`
= `$"{Name} <{Identification}>"` with the decoded name - `List-ID: Grüße, Freunde
<friends.list.example.org>`: 8-bit in a 7bit message, a comma in what must be a phrase. RFC
2919 §3: "The list header fields are subject to the encoding and character restrictions for
mail headers", `list-id-header = "List-ID:" [phrase] "<" list-id ">" CRLF`; RFC 5322 §2.2:
field bodies of printable US-ASCII. Test:
`A_list_description_is_written_as_a_phrase_of_ASCII`.

Fixed: the description is written as a phrase (`MimeEncoding.Phrase`): atoms, a quoted
string or encoded words.

### E-14
**Closed** in [Vanaheimr/Hermod#276](https://github.com/Vanaheimr/Hermod/pull/276) (`76eb49e8`).
**`EMail.Parse` read the media type and the name `boundary` with case**
(`EMail/Helpers/MailContentType.cs:148`, `EMail/Helpers/EMailBodypart.cs:172`, `:66` and
`:72`): the media type is mapped to `MailContentTypes` with a case-sensitive
`Enum.TryParse`, so `Multipart/Mixed`, `MULTIPART/SIGNED` or `Multipart/Report` is
`unknown` and has no boundary; and the body is split only when the Content-Type text
`Contains("boundary=")`, with that case, so `Boundary=xyz` is read as the boundary and then
not used. RFC 2045 §5.1: "The type, subtype, and parameter names are not case sensitive."
The parts of such a multipart are lost: the whole body is one text. A `Multipart/Signed`
whose signature is valid is `IsPgpSigned` false, and `VerifyPgpSignature` says
`NoSignature`; a `Multipart/Encrypted` is `IsPgpEncrypted` false, and `DecryptPgp` throws
"This e-mail is not an OpenPGP/MIME encrypted message!" (`EMail.cs:512`). `MimeMessage`
reads all of these. Tests: `The_media_type_and_parameter_names_are_read_without_case_by_EMail`
(five spellings), `A_signed_message_verifies_whatever_the_case_of_its_type` and
`An_encrypted_message_decrypts_whatever_the_case_of_its_type` (two each).

Fixed: `MailContentType.TryParse` reads the value with `MimeContentType.Parse`, the parser
of the MIME reader, and maps the lower-cased type to `MailContentTypes`; the boundary is
read whatever the case of its name.

### E-15
**Closed** in [Vanaheimr/Hermod#276](https://github.com/Vanaheimr/Hermod/pull/276) (`76eb49e8`).
**`EMail.Parse` took white space around `=` and comments in the Content-Type
for part of the names and values** (`EMail/Helpers/MailContentType.cs:129` and `:174`): the
value is split at every `;` and each piece trimmed; the type is the first piece as it
stands, a parameter is found with `StartsWith("boundary=")`. So `boundary = xyz` is no
boundary, `boundary=xyz (a comment)` the boundary `xyz (a comment)`, and `multipart/mixed (a
comment)` an unknown type. RFC 2045 §1: the MIME header fields "are subject to the general
syntactic rules for header fields specified in RFC 822" - white space between the tokens of
a structured field - and "can include RFC 822 comments, which have no semantic content and
should be ignored during MIME processing". `MimeMessage` reads them. Test:
`White_space_and_comments_in_the_Content_Type_are_read_by_EMail` (three cases).

Fixed: the same parser drops comments and the white space between tokens, unquotes values
and joins RFC 2231 sections.

### E-16
**Closed** in [Vanaheimr/Hermod#276](https://github.com/Vanaheimr/Hermod/pull/276) (`76eb49e8`).
**`EMail.Parse` took a body for a multipart when its Content-Type held the text
`boundary=`** (`EMail/Helpers/EMailBodypart.cs:172`): whether a body is split into parts is
decided by `ContentType.Text.Contains("boundary=")`, not by the type. A multipart of a
subtype `MailContentTypes` does not list - multipart/related, multipart/digest - is
`unknown`, its boundary is not read, and it has no parts; RFC 2046 §5.1.7: "MIME
implementations must in general treat unrecognized subtypes of "multipart" as being
equivalent to "multipart/mixed"". A text/plain with a parameter `x-boundary=xyz` is split
at the delimiter `"--" + null`, a line `--`: the text after it is gone. RFC 2045 §5.1:
"Parameters are modifiers of the media subtype"; RFC 2046 §5.1.1 defines `boundary` for
multipart. Tests: `An_unrecognised_multipart_subtype_is_read_as_mixed_by_EMail`,
`A_text_with_a_parameter_ending_in_boundary_is_not_split_by_EMail`.

Fixed: the new `MailContentType.IsMultipart` is true for every multipart subtype, also one
the enum does not list; `EMailBodypart` splits a body when it is a multipart with a
boundary, and the boundary is read for multiparts only.

### E-17
**Closed** in [Vanaheimr/Hermod#317](https://github.com/Vanaheimr/Hermod/pull/317) (`3d2d3e03`). **A Content-ID with a comment was not read as a msg-id**
(`EMail/Mime/MimeMessage.cs:176`: the field body trimmed of white space and of `<` and `>`
at its ends, nothing else; `:786`: `FindByContentId` compares with that; `:692`, `:693`: the
root of a multipart/related is the part whose Content-ID is start= so read). RFC 2045 §7:
`id := "Content-ID" ":" msg-id`; RFC 5322 §3.6.4: `msg-id = [CFWS] "<" id-left "@" id-right
">" [CFWS]` - a comment before or after the brackets is no part of the id, as the reader
already knows for Message-ID, In-Reply-To and References (`:792` and on). `Content-ID:
<logo@example.org> (the logo)` is read as "logo@example.org> (the logo)": the cid: URL the
HTML names the image by finds no part (RFC 2392 §2), and the root start= names is not
found - the HTML of the message is lost when the root is not the first part. Tests:
`A_Content_ID_with_a_comment_names_its_part` - a comment after it, before it;
`The_root_start_names_is_found_by_a_Content_ID_with_a_comment`; guard:
`A_Content_ID_of_the_usual_kind_names_its_part`.

Fixed: a Content-ID is read as the msg-id it is, as Message-ID is - the comments around it
no part of it - and so is start=; `FindByContentId` takes a Content-ID either way. One that
is no msg-id is read as before.

### E-18
**Closed** in [Vanaheimr/Hermod#317](https://github.com/Vanaheimr/Hermod/pull/317) (`3d2d3e03`). **A part of a disposition type the reader does not know was lost**
(`EMail/Mime/MimeContentType.cs:505`: `IsAttachment` is "attachment" and nothing else;
`EMail/Mime/MimeMessage.cs:146` to `:148`: a text is an attachment only with a file name).
RFC 2183 §2.8: "Unrecognized disposition types should be treated as `attachment'". A
text/plain marked `Content-Disposition: x-archive` beside the body is neither the body -
the first text is - nor an attachment: the reader lists it nowhere. Test:
`A_part_of_an_unknown_disposition_type_is_an_attachment`; guard:
`A_text_marked_attachment_is_an_attachment`.

Fixed: `MimeContentDisposition.IsAttachment` is every disposition but inline, and the new
`IsInline` is inline: a part of a type the reader does not know is an attachment.

### E-19
**Closed** in [Vanaheimr/Hermod#317](https://github.com/Vanaheimr/Hermod/pull/317) (`3d2d3e03`). **A text marked inline with a file name was taken for an attachment**
(`EMail/Mime/MimeMessage.cs:146` to `:148`: a text/plain or text/html with a file name is an
attachment, whatever its Content-Disposition says; `:721`: an attachment is no body). RFC
2183 §2.1: "A bodypart should be marked `inline' if it is intended to be displayed
automatically upon display of the message", and §2.3: the filename parameter is one of
either disposition. A message whose one text is `Content-Disposition: inline;
filename="notes.txt"` has no body, and its text is listed as an attachment. The file name
decides where the sender said nothing; where the sender said inline, inline decides. Test:
`A_text_marked_inline_with_a_file_name_is_the_body`; guards:
`Inline_is_shown_and_attachment_is_not` - inline, attachment with a file name.

Fixed: a text marked inline is not an attachment, a file name or not - the body, where it is
the first; a second such text of a multipart/mixed, not the body, is listed beside it as
before.

### E-20
**Closed** in [Vanaheimr/Hermod#317](https://github.com/Vanaheimr/Hermod/pull/317) (`3d2d3e03`). **A Content-ID was written whether it was a msg-id or not**
(`EMail/Mime/MimeEntity.cs:222`: the Content-ID given, trimmed of `<`, `>` and spaces,
refused only for a line break or a NUL; `:236`: written in angle brackets; `:92`: the header
line written as US-ASCII, a character outside it a "?"). RFC 2045 §7: `id := "Content-ID"
":" msg-id`; RFC 5322 §3.6.4: `msg-id = "<" id-left "@" id-right ">"`, `id-left =
dot-atom-text`, printable US-ASCII. `ContentId: "logo"` is written `Content-ID: <logo>`,
`"my logo@example.org"` with its space; `"bild-ä@example.org"` is written
`<bild-?@example.org>` - another id than the one the HTML refers to by `cid:`, so the
picture is not shown. Tests: `A_Content_ID_that_is_no_msg_id_is_not_written` - no @, a
space, a non-ASCII character; either refused or written as the msg-id it is; guard:
`A_Content_ID_that_is_a_msg_id_is_written`.

Fixed: a Content-ID that is no msg-id - id-left "@" id-right, printable US-ASCII, no white
space - is refused with an ArgumentException, as a line break in it was.

### E-21
**Closed** in [Vanaheimr/Hermod#317](https://github.com/Vanaheimr/Hermod/pull/317) (`3d2d3e03`). **A multipart/related was written without its type parameter**
(`EMail/Mime/MimeEntity.cs:296` to `:300`: the parameters the caller gave, and the
boundary). RFC 2387 §3.1: "The type parameter must be specified and its value is the MIME
media type of the "root" body part", and §3.2: without start, the root is the first part.
`new MimeMultipart("related", [ html, image ])` is written `Content-Type:
multipart/related; boundary=...`; the writer knows the root and its type. Test:
`A_multipart_related_has_the_type_of_its_root`; guard:
`A_multipart_related_keeps_the_type_it_is_given`.

Fixed: a multipart/related given no type has the media type of its root - the part start
names, the first without; a type given is kept.

### E-22
**Closed** in [Vanaheimr/Hermod#318](https://github.com/Vanaheimr/Hermod/pull/318) (`5395acc9`). **The subject of a reply to a list's post had two "Re: "**
(`EMail/Mime/MailReplies.cs:71`: the prefixes taken away are those at the beginning of the
subject; `:92`, `:98`: "Re: " before what is left). RFC 5322 §3.6.5: the subject of a reply
"MAY start with the string "Re: " [...] followed by the contents of the "Subject:" field
body of the original message. If this is done, only one instance of the literal string
"Re: " ought to be used since use of other strings or more than one instance can lead to
undesirable consequences." A list puts its tag before the subject - "[dev] Re: Hello" -
and the reply is "Re: [dev] Re: Hello"; the reply to that is the same, with two "Re: " in
it still. Tests: `The_subject_of_a_reply_has_one_Re` - "[dev] Re: Hello", "Re: [dev] Re:
Hello"; guards: `The_subject_of_a_reply_is_Re_and_the_original` - "[dev] Hello", "Re: Re:
Hello".

Fixed: the prefixes are taken away where a list's tag stands among them too, and the tag is
kept, once, before the subject: the reply to "[dev] Re: Hello" is "Re: [dev] Hello", and
the reply to that the same. Brackets that are no list's tag - "[PATCH 1/3]" - stay.

### E-23
**Closed** in [Vanaheimr/Hermod#318](https://github.com/Vanaheimr/Hermod/pull/318) (`5395acc9`). **White space inside the angle brackets of List-Post lost the list**
(`EMail/Mime/MailReplies.cs:74`: `<mailto:` without white space, the address up to `>` or
`?`; `:161`: an address with a space in it is none). RFC 2369 §2: "The contents of the list
header fields mostly consist of angle-bracket ('<', '>') enclosed URLs, with internal
whitespace being ignored. MTAs MUST NOT insert whitespace within the brackets, but client
applications should treat any whitespace, that might be inserted by poorly behaved MTAs,
as characters to ignore." `List-Post: <mailto:list@` folded before `example.org>`, or `<
mailto:list@example.org >`, names no list: the reply to the list goes to the sender.
Tests: `White_space_inside_the_angle_brackets_of_List_Post_is_ignored` - folded inside the
URL, around it; guard: `List_Post_names_the_list_its_mailto_URL_names`.

Fixed: white space inside the angle brackets is taken away before the URL is read, so a
folded List-Post names its list.

### E-24
**Closed** in [Vanaheimr/Hermod#318](https://github.com/Vanaheimr/Hermod/pull/318) (`5395acc9`). **List-Post was read for the first mailto anywhere in it**
(`EMail/Mime/MailReplies.cs:74`, `:159`: the first `<mailto:` in the field, in a comment
or after what is to be ignored). RFC 2369 §2: "client applications MUST follow the
following guidelines for handling the contents of the header fields": a field that,
"following any leading whitespace, including comments", begins with no `<` SHOULD be
ignored; "Any characters following an angle bracket enclosed URL SHOULD be ignored, unless
a comma is the first non-whitespace/comment character after the closing angle bracket";
and "If a sub-item (comma-separated item) within the field is not an angle-bracket
enclosed URL, the remainder of the field [...] SHOULD be ignored." `(not
<mailto:wrong@example.org>) <mailto:list@example.org>` posted to wrong@example.org;
`<https://example.org/post> (moderated) <mailto:other@example.org>` and
`<https://example.org/post>, by mail: <mailto:other@example.org>` to other@example.org,
which the field does not name. Tests: `List_Post_is_read_as_RFC_2369_says` - those three;
guards: `List_Post_names_the_list_its_mailto_URL_names` - a mailto URL, one after another
and a comma, a comment after it, NO.

Fixed: List-Post is read as RFC 2369 §2 has it - leading comments skipped, nested ones
too; a field beginning with anything else but `<` names no list; after a URL, only a comma
leads to the next - and the first mailto URL among them names the list, through
`MailtoUri`.

### E-25
**Closed** in [Vanaheimr/Hermod#318](https://github.com/Vanaheimr/Hermod/pull/318) (`5395acc9`). **The older builder wrote List-Post's mailto URL with the address as it is**
(`EMail/Builder.cs:458`: `<mailto:` + the address + `>`). RFC 2369 §2: the list header
fields hold URLs; RFC 6068 §2: "A number of characters that can appear in <addr-spec> MUST
be percent-encoded: these are the characters that cannot appear in a URI according to
[STD66] as well as "%" (because it is used for percent-encoding) and all the characters in
gen-delims except "@" and ":" (i.e., "/", "?", "#", "[", and "]")." The list
`dev?announce@lists.example.org` is written `<mailto:dev?announce@lists.example.org>` - a
URL whose address is "dev", the rest a header field; `list#1@` begins a fragment, `list%1@`
a percent-encoding that is none, and `dev/announce@` a path. Hermod has `MailtoUri.Of` for
this since #316. Tests: `List_Post_names_the_lists_address` - a slash, a question mark, a
number sign, a percent sign; guard: `List_Post_of_an_address_of_the_usual_kind`.

Fixed: the older builder writes `MailtoUri.Of` the address - "/", "?", "#" and "%"
percent-encoded - so the URL names the list's address.

### E-26
**Closed** in [Vanaheimr/Hermod#326](https://github.com/Vanaheimr/Hermod/pull/326) (`c97be4d5`). **A text of a subtype the reader does not know was an attachment**
(`EMail/Mime/MimeMessage.cs:157`: text/plain and text/html are the texts to show; `:164`,
`:165`: every other type is an attachment; `:738`, `:741`: only text/plain and text/html are
the body). RFC 2046 §4.1.4: "Unrecognized subtypes of "text" should be treated as subtype
"plain" as long as the MIME implementation knows how to handle the charset." A mail that is
text/markdown, or text/x-log, in UTF-8 or US-ASCII has no body: its text is listed as an
attachment, the only one; the first part of a multipart/mixed alike. Tests:
`A_text_of_an_unknown_subtype_is_text` - text/markdown and text/x-log the message,
text/markdown the first part of a multipart/mixed; guard:
`A_text_marked_attachment_is_listed_whatever_its_subtype` - a text/calendar marked
attachment, with a file name.

Fixed: a text of another subtype, in a charset the reader knows, not marked attachment nor
given a file name but inline, is the body where there is no text/plain; beside one it stays
an attachment - the text/calendar of an invitation. In a charset the reader does not know it
is an attachment, as §4.1.4 says.

### E-27
**Closed** in [Vanaheimr/Hermod#326](https://github.com/Vanaheimr/Hermod/pull/326) (`c97be4d5`). **A message part of a subtype the reader does not know was lost**
(`EMail/Mime/MimeMessage.cs:161`: every message/* but rfc822 and global is no attachment -
"the report parts of a bounce or a read receipt" - and no text either). RFC 2046 §5.2.4:
"MIME implementations must in general treat unrecognized subtypes of "message" as being
equivalent to "application/octet-stream"" - which the reader lists as an attachment. A message/http, a
message/sipfrag (RFC 3420), a message/x-example in a multipart/mixed is neither the text nor
an attachment: the reader shows no trace of it. Tests:
`A_message_part_of_an_unknown_subtype_is_an_attachment` - those three; guards:
`A_forwarded_message_is_an_attachment`, `The_report_parts_of_a_bounce_are_no_attachments` -
message/delivery-status and text/rfc822-headers of a multipart/report.

Fixed: the parts of a report are named - delivery-status, disposition-notification and
their global forms, feedback-report, tracking-status, global-headers, text/rfc822-headers -
and a message of any other subtype is an attachment.

### E-28
**Closed** in [Vanaheimr/Hermod#326](https://github.com/Vanaheimr/Hermod/pull/326) (`c97be4d5`). **An attached message with UTF-8 in its header was written message/rfc822**
(`EMail/Mime/MimeEntity.cs:468`, `:486`: `MimeAttachedMessage` is message/rfc822 whatever
it carries). RFC 6532 §3.7: a message is a "message/global message" if "it contains 8-bit
UTF-8 header values", and message/global is the media type for one - "otherwise identical
to that of a message/rfc822 part"; RFC 2046 §5.2.1: message/rfc822 "indicates that the body
contains an encapsulated message, with the syntax of an RFC 822 message", whose header is
US-ASCII (RFC 5322 §2.2). A forwarded message with "Grüße" in its subject, or "Jürgen Müller"
or `jürgen@bücher.example` in From, is attached as message/rfc822: a reader that is no
SMTPUTF8 reader is promised a header it can read. Tests:
`An_attached_message_with_UTF_8_in_its_header_is_message_global` - the subject, the name of
From, its address; guards: `An_attached_message_with_an_ASCII_header_is_message_rfc822` - a
UTF-8 body; `A_message_global_part_is_read_as_its_message`.

Fixed: an attached message with 8-bit in a header of its own or of one of its parts is
message/global.

### E-29
**Closed** in [Vanaheimr/Hermod#326](https://github.com/Vanaheimr/Hermod/pull/326) (`c97be4d5`). **An attached message with a line over 998 octets or a NUL was written 7bit or 8bit**
(`EMail/Mime/MimeEntity.cs:473` to `:487`: 7bit when no octet is above 127 and none is NUL,
8bit otherwise - the lengths of the lines never looked at). RFC 2045 §2.7 and §2.8: 7bit and
8bit data are "relatively short lines with 998 octets or less between CRLF line separation
sequences", and "no NULs are allowed"; §2.9: binary data is data "where any sequence of
octets whatsoever is allowed"; §6.2: "7bit", "8bit", and "binary" "all mean that the
identity (i.e. NO) encoding transformation has been performed. As such, they serve simply
as indicators of the domain of the body data" - and RFC 2046 §5.2.1: "No encoding other
than "7bit", "8bit", or "binary" is permitted for the body of a "message/rfc822" entity". A message with a line of 1000 US-ASCII octets is written 7bit;
one of 1000 octets with "Grüße" in it 8bit, and one with a NUL 8bit too: what is no 7bit and
no 8bit data is said to be, and a relay that keeps to the 1000 octets of a line (RFC 5321
§4.5.3.1.6) breaks it. Tests: `An_attached_message_that_is_no_7bit_and_no_8bit_data_is_binary`
- a line of 1000 US-ASCII octets, of 1000 octets 8-bit, a NUL; guard:
`An_attached_message_of_short_US_ASCII_lines_is_7bit` - a line of 998.

Fixed: the lines are measured, after their line ends are made CRLF; a line over 998 octets
or a NUL is binary. The message is still attached octet for octet - a mail that carries a
binary one is binary, and needs BDAT with BODY=BINARYMIME (RFC 3030) to be sent.

## Reports that arrive

The reading side of the reports: what Hermod does with the reports other systems send it.
The server reads TLS reports (RFC 8460) when `EnableTlsRptIngestion` is on: `SMTPSession`
hands every locally delivered message with a `TLS-Report-Domain` header or "tlsrpt" in its
Content-Type to `TlsRptIngestor.Ingest` (`SMTPSession.cs:1431`), before it replies to DATA.
`IncomingTlsRptTests` sends the reports over the wire and reads the result from the server's
log and from the reports it keeps. Hermod's server never calls `DmarcReportReader`; an
application that reads its rua mailbox does, so `IncomingDmarcReportTests` calls it the same
way. A test that may overflow the stack runs in a child process of the test assembly
(`IsolatedProcess`, the project's entry point). Hermod has no reader for incoming DSNs -
`BounceInfo` and `BounceType` are used nowhere - so `IncomingDsnTests` tests what the server
does with a DSN that arrives, reads the DSN Hermod writes with the suite's own strict RFC
3464 reader, and tests what `DsnGenerator.StatusOf` takes from a foreign reply.

Covered without a finding: the aggregate report of RFC 7489 Appendix C is read field by
field, plain, gzipped (application/gzip) or in a ZIP; the report Hermod's
`DmarcReportService` writes reads back record for record; a DTD with nested entities
("billion laughs") and an external entity (XXE) are refused and no file is read; a gzip bomb
and a ZIP bomb (256 MiB) stop at the 20 MiB limit, with less than 128 MiB allocated; plain
XML over the limit, truncated gzip, ZIP or XML, a ZIP without .xml and a report without
policy_published are no report, and reading them throws nothing. The TLS-RPT mail of §5.3.1
(multipart/report, a folded Content-Type, base64 application/tlsrpt+gzip) and an
uncompressed application/tlsrpt+json report are read; the JSON fields of §4.4 are read one
by one, and the report Hermod's `TlsRptReportService` writes reads back; JSON nested 100000
deep, broken gzip, broken base64 and truncated JSON are no report - DATA is still answered
with 250 and the session goes on; 20000 failure-details are read in time. A DSN from `MAIL
FROM:<>` is taken and stored as it arrived; with NOTIFY=SUCCESS,FAILURE it gets no DSN back
(RFC 3461 §6); relayed, it keeps the null reverse-path (RFC 5321 §4.5.5); 3000 recipient
groups are taken in time. The DSN Hermod writes follows RFC 6522 §3 and RFC 3464 §2.2 and
§2.3 to the strict reader, field by field: the order of the parts, Reporting-MTA, typed
values, the Status grammar, dates, Original-Recipient only with ORCPT. `StatusOf` takes
5.1.1 from `550 5.1.1`, and refuses a code of another class, class 6 and a four-digit
detail.

### I-1
**Closed** in [Vanaheimr/Hermod#271](https://github.com/Vanaheimr/Hermod/pull/271) (`a3270801`).
**A gzip bomb was inflated whole, in memory and onto disk, before the reply to DATA**
(`Reporting/TlsRptIngestor.cs:203` to `:210`, `Gunzip`: `gz.CopyTo(output)` into a
`MemoryStream` with no limit, then `:155`, `Encoding.UTF8.GetString(bytes)`, and `:341`,
`File.WriteAllText(..., json)`): 175 KiB of mail whose application/tlsrpt+gzip part inflates
to 128 MiB of valid JSON make the server allocate 1430 MiB and keep the 128 MiB on disk
under `tls-reports-received`. RFC 8460 §6.5, application/tlsrpt+gzip: "Security
considerations related to gzip compression are discussed in RFC 6713"; RFC 6713 §4:
"Applications should treat any data with due skepticism"; RFC 8460 §7: "An attacker could
inject malicious code into the report, exploiting any vulnerabilities in the report-handling
systems of the receiving domain". Anyone can send such a report, without signing in: it
needs a local recipient and a `TLS-Report-Domain` header (`:47`) - the recipient does not
have to be the rua mailbox. The work is done inside the session, before the 250
(`SMTPSession.cs:1432`, reply at `:1507`). At the default `MaxMessageSize` of 25 MB one
message inflates until the `MemoryStream` gives up at 2 GiB, every parallel session costs
that again, and a JSON string under 1 GiB is written to disk once per message.
`DmarcReportReader` has the limit this code lacks (`ReadAtMost`, 20 MiB). Test:
`A_gzip_bomb_is_not_unpacked_whole`.

Fixed: a report is unpacked in blocks and given up once it would pass a limit, the new
`SMTPServerConfig.MaxTlsRptReportSize` (default 10 MiB); anything larger is no report -
nothing parsed, kept or written. Ingestion is still not limited to the rua mailbox, as
Hermod has no setting that names it.

### I-2
**Closed** in [Vanaheimr/Hermod#271](https://github.com/Vanaheimr/Hermod/pull/271) (`376946a8`).
**Deeply nested XML overflowed the stack and ended the process**
(`Reporting/DmarcReportReader.cs:284`, `Text`: `Child(Parent, Name)?.Value`): the
`XmlReader` at `:212` sets no limit on depth, so `XDocument.Load` builds a tree of any
depth, and `XElement.Value` collects the text of an element through `XContainer.AppendText`,
which calls itself once per level. 50000 elements nested inside `<domain>` - 350 KiB of XML,
well within the 20 MiB the reader allows, a few KiB gzipped - overflow a thread with a 1.5
MiB stack ("Repeated 24283 times: at System.Xml.Linq.XContainer.AppendText"). A stack
overflow cannot be caught: the whole process ends. RFC 7489 §7.2.1.1: aggregate reports come
by mail from receivers - input from strangers; the reader's own remarks say "a report is
something a stranger sends". `<count>` and every other value are read the same way. Hermod's
server does not call the reader, but any application reading its rua mailbox with it dies on
one report. Test: `Deep_nesting_is_read_or_refused` ("Nesting 50000 deep does not end the
process", in a child process; the 1000-deep case passes).

Fixed: `Parse` reads the document once first and returns null for anything nested deeper
than `DmarcReportReader.MaxDepth` = 32; only then is the tree built.

### I-3
**Closed** in [Vanaheimr/Hermod#271](https://github.com/Vanaheimr/Hermod/pull/271) (`22aa8de3`).
**A quoted-printable report part was not decoded, so the report was lost**
(`Reporting/TlsRptIngestor.cs:191` to `:200`, `DecodeBody`: only base64 is decoded -
"quoted-printable(best-effort as-is): treat as raw text bytes"): soft line breaks and `=3D`
stay in the JSON, which does not parse. RFC 2049 §2: "A mail user agent that is
MIME-conformant MUST: ... Recognize the Content-Transfer-Encoding header field and decode
all received data encoded by either quoted-printable or base64 implementations". An
uncompressed application/tlsrpt+json report (RFC 8460 §5.3) is usually one JSON line longer
than the 998 octets RFC 5322 §2.1.1 allows, so the sender has to encode it, and
quoted-printable is one of the two ways. Test: `A_quoted_printable_report_is_read`.

Fixed: `DecodeBody` decodes quoted-printable.

### I-4
**Closed** in [Vanaheimr/Hermod#271](https://github.com/Vanaheimr/Hermod/pull/271) (`f853d998`).
**XML in UTF-16, or in UTF-8 with a byte order mark, was no report**
(`Reporting/DmarcReportReader.cs:165`, `Encoding.UTF8.GetString(xml)`, then `:212`, an
`XmlReader` over a `StringReader`): the octets are decoded as UTF-8 whatever they are. With
a UTF-8 BOM the string starts with U+FEFF and the XmlReader refuses the declaration after
it; UTF-16 becomes text that holds no `<feedback`. `Parse` returns null and the report is
gone. XML 1.0 §4.3.3: "All XML processors MUST be able to read entities in both the UTF-8
and UTF-16 encodings", and "Entities encoded in UTF-16 MUST and entities encoded in UTF-8
MAY begin with the Byte Order Mark"; RFC 7489 §7.2.1.1: "The aggregate data MUST be an XML
file". Handing the octets to `XmlReader` as a stream would let it detect the encoding - and
honour an `encoding="ISO-8859-1"` declaration, which today turns "Müller" into "M�ller" (no
finding: XML does not require that encoding). Tests:
`A_report_in_either_encoding_XML_requires_is_read`, three cases (UTF-8 with BOM, the same
gzipped, UTF-16).

Fixed: the encoding is found from the octets - byte order mark or declaration, UTF-8 if
neither - and a leading byte order mark in decoded text is dropped.

### I-5
**Closed** in [Vanaheimr/Hermod#271](https://github.com/Vanaheimr/Hermod/pull/271) (`febac950`).
**A date_range outside years 1 to 9999 threw `ArgumentOutOfRangeException`**
(`Reporting/DmarcReportReader.cs:287` to `:290`, `Seconds`:
`DateTimeOffset.FromUnixTimeSeconds(seconds)` for any Int64, while only `XmlException` is
caught, at `:265`): `<begin>99999999999999</begin>` does not make `Parse` return null, as
its documentation says ("or null when it holds none") - the call throws. RFC 7489 Appendix
C: `<xs:element name="begin" type="xs:integer"/>`, and `end` alike - any integer is valid in
the schema. A reader that throws on a value a stranger writes loses that report and whatever
its caller was doing, the loop over a mailbox for one. Tests:
`A_date_range_out_of_range_does_not_throw`, two cases.

Fixed: such a date is none, and the rest of the report is read.

### I-6
**Closed** in [Vanaheimr/Hermod#271](https://github.com/Vanaheimr/Hermod/pull/271) (`ea4f3004`).
**A next hop's status code with leading zeros went into the DSN as it was**
(`DsnGenerator.cs:338`, `^(?:\d{3}[ -])?([245]\.\d{1,3}\.\d{1,3})(?:\s|$)`, and `:307`,
`return match.Groups[1].Value`): `\d{1,3}` matches `01` and `007`, so `StatusOf(550, "550
5.01.1 ...")` returns `5.01.1`, which `BounceHandler.cs:278` writes into the `Status:` field
of the bounce. RFC 3463 §2: "Each numeric sub-code within the status-code MUST be expressed
without leading zero digits"; RFC 3464 §2.3.4 takes its Status from there. A reply with
`5.01.1` has no RFC 3463 status code, so the DSN should carry the reply class (`5.0.0`), as
it already does for `5.1.1000`. Tests:
`A_status_code_with_leading_zeros_does_not_go_into_a_DSN`, three cases.

Fixed: a sub-code with a leading zero falls back to the reply class, 5.0.0 or 4.0.0.

### I-7
**Closed** in [Vanaheimr/Hermod#271](https://github.com/Vanaheimr/Hermod/pull/271) (`0b96e51c`).
**The preamble of the multipart was read as a report part**
(`Reporting/TlsRptIngestor.cs:169` to `:186`, `SplitMultipart`: `body.Split(delimiter)`, and
every segment but the closing one is a candidate, the preamble included; the delimiter is
found anywhere, not only at the start of a line): a preamble with a header block naming
application/tlsrpt+json is read as the report, and the report part after it is not read at
all. RFC 2046 §5.1.1: `multipart-body := [preamble CRLF] dash-boundary ...`, `preamble :=
discard-text`, and "implementations must ignore anything that appears before the first
boundary delimiter line or after the last one"; "The boundary delimiter MUST occur at the
beginning of a line". Little harm - the sender of the preamble wrote the report too - but
what is logged and kept is not the report that was sent. Test:
`The_preamble_is_not_read_as_a_report`.

Fixed: the multipart is split line by line at delimiter lines; the preamble is skipped,
and reading stops at the close delimiter.

## Message disposition notifications

RFC 8098 as Hermod's server answers a read receipt request on its own (`EnableAutoMdn`,
`MailStorage/MdnGeneratingMailStorage.cs`; `DispositionNotificationTests`, over the wire: a
message with Disposition-Notification-To delivered to a local mailbox, the MDN read from the
relay queue with the suite's `ReportMail`), and as an application meets it in the API for
mail user agents - `DispositionNotification.RequestedBy`, `GoesElsewhere`, `Build` and
`EMail.CreateReadReceipt` (`DispositionNotificationApiTests`). Hermod parses no MDN it
receives, so there is nothing to test there. Covered without a finding: a request to the
reverse-path's own address is answered, also with a display name or the domain in capitals;
no request, no MDN; two local recipients give two MDNs, one each; the MDN is a
multipart/report with report-type=disposition-notification, a text part first and
message/disposition-notification second; it goes to the requester in envelope and To: and
comes From: the recipient; it asks for no MDN itself and has a Message-ID of its own;
Final-Recipient keeps the recipient's capitals; Original-Message-ID is there exactly when
the message had a Message-ID; the Disposition field follows the grammar,
automatic-action/MDN-sent-automatically; processed (not displayed); Reporting-UA follows the
grammar and the report is US-ASCII; a request without a mailbox is delivered and not
answered; 5000 addresses and 20000 nested comments in the request are parsed in time;
`Build` writes a receipt after §3 with manual-action/MDN-sent-manually; `GoesElsewhere` says
so for a third party and not for the domain in capitals. Line numbers refer to `72c2366d`,
under `libs/Hermod/Hermod/SMTP/`.

### K-1
**Closed** in [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272) (`16812647`).
**Read receipts were sent automatically to any address a message named**
(`MailStorage/MdnGeneratingMailStorage.cs:91`, `await GenerateReadReceiptsAsync(message,
envelopeTo, ct);` - the reverse-path is not passed on - and `:110` to `:123`, which answer
every `IsReadReceiptRequested` with `sender.SendAsync(mdn, ...)`). Whatever
Disposition-Notification-To says, an MDN goes there: to a third party
(`victim@elsewhere.example` for MAIL FROM:<sender@client.example>), for a message from the
null reverse-path, to `Sender@client.example` for `sender@client.example`, and to every
address of a list - 5000 of them, if the header names 5000. RFC 8098 §2.1: "MDNs MUST NOT be
sent automatically if the address in the Disposition-Notification-To header field differs
from the address in the Return-Path header field ... If obtaining consent is not possible
(e.g., ... the client is not an interactive email client), then an MDN MUST NOT be sent", the
local-part compared "case sensitive", and "Confirmation from the user MUST be obtained (or no
MDN sent) if ... there is more than one distinct address in the Disposition-Notification-To
header field". §6.4: "It is possible for an attacking agent to send a potentially large set
of messages to otherwise unsuspecting third party recipients with a false
Disposition-Notification-To address" - one message to a server with `EnableAutoMdn` is a
mail bomb with as many targets as the header holds, each MDN confirming that the local
address is read. Tests:
`No_MDN_is_sent_automatically_to_an_address_the_reverse_path_does_not_vouch_for`, four cases.

Fixed: the storage gets the reverse-path and sends a receipt automatically only when
there is exactly one requester and it is the reverse-path; for a null or unknown one,
none.

### K-2
**Closed** in [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272) (`d1a3203a`).
**A field folded onto many lines kept the session busy for a time that grew with the square
of their number** (`MailStorage/MdnGeneratingMailStorage.cs:108`,
`EMail.Parse(message.RawMessage.Split(...))`, through `EMail/EMail.cs:193`,
`AggregateIndentedLines()`, which is Styx's
`CurrentLine = CurrentLine + Enumerator.Current.TrimStart();` -
`libs/Styx/Styx/Illias/ExtensionMethods/StringExtensions.cs:1305`): every continuation line
copies the whole field so far. 30000 lines take 0.5 s, 60000 1.6 s, 120000 7.6 s, 240000
34 s; under the default 25 MB limit a message can have 6 million. The parse runs on every
stored message when `EnableAutoMdn` is on, whether or not it asks for a receipt, after the
message is stored and before the end of data is answered: the session hangs with a core
busy, the client gives up and sends the message again - stored twice. Without
`EnableAutoMdn` the same message is answered in 0.6 s. RFC 5322 §2.2.3 lets a field be
folded onto any number of lines; a parser that loops on input any sender controls is a
remote denial of service. Test: `A_field_folded_onto_240000_lines_does_not_hold_up_delivery`
(against `72c2366d` its session keeps counting for half a minute after the test ends).

Fixed: `EMail.Parse` unfolds each field with a `StringBuilder` (Styx's
`AggregateIndentedLines` is no longer used there), and the storage parses nothing
without a Disposition-Notification-To at the start of a header line.

### K-3
**Closed** in [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272) (`16812647`).
**The MDN was sent from the recipient's address, not from the null reverse-path**
(`MailStorage/MdnGeneratingMailStorage.cs:123`, `sender.SendAsync(mdn, ...)`, the
`SendAsync(EMail)` overload of `MailSender.cs:219`, whose `EMailEnvelop(EMail)` takes the
reverse-path from From: - `EMail/EMailEnvelop.cs:112`,
`this.MailFrom = EMailAddressList.Create(EMail.From);`): the MDN about a message to
alice@hermod.test is queued with MAIL FROM:<alice@hermod.test>. RFC 8098 §3: "The envelope
sender address (i.e., SMTP "MAIL FROM") of the MDN MUST be null (<>), specifying that no
Delivery Status Notification messages nor other messages indicating successful or
unsuccessful delivery are to be sent in response to an MDN." An MDN to an address that does
not exist - with K-1, any address a sender writes into the header - bounces into the local
user's mailbox, and auto-responders answer it. Hermod's own `MdnStorageTests` asserts the
recipient as reverse-path. Test: `The_MDN_is_sent_from_the_null_reverse_path`.

Fixed: the MDN is queued with MAIL FROM:<>.

### K-4
**Closed** in [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272) (`76d88464`).
**An MDN was answered with an MDN** (`MailStorage/MdnGeneratingMailStorage.cs:110`,
`if (!mail.IsReadReceiptRequested) return;` - nothing else is looked at): a
multipart/report; report-type=disposition-notification that carries
Disposition-Notification-To is answered with an MDN of its own. RFC 8098 §2.1: "An MDN MUST
NOT itself have a Disposition-Notification-To header field. An MDN MUST NOT be generated in
response to an MDN." The first sentence binds the sender, the second the receiver - Hermod's
own MDNs ask for none, but a peer's MDN that does (by mistake or on purpose) starts a loop
between two servers that answer automatically. Test: `No_MDN_is_sent_in_answer_to_an_MDN`.

Fixed: `CreateReadReceipt` returns null for a multipart/report with
report-type=disposition-notification.

### K-5
**Closed** in [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272) (`615b309f`).
**No Original-Recipient field, from the message's header or from ORCPT**
(`EMail/EMail.cs:561`, `$"Final-Recipient: rfc822; {reporter}"`, followed by
Original-Message-ID and Disposition only; `EMail/Mime/DispositionNotification.cs:119`
alike): a message with `Original-Recipient: rfc822;alias@hermod.test`, or delivered with
`RCPT TO:<alice@hermod.test> ORCPT=rfc822;alias@hermod.test`, gets an MDN without the
field. RFC 8098 §3.2.3: "If there is an Original-Recipient header field in the message, or
if information about the original recipient is reliably available some other way, then the
Original-Recipient field MUST be included"; §5 names the ORCPT of RFC 3461 as that way. The
sender correlates MDNs with the address it wrote (§2.3: "to permit automatic correlation of
MDNs with the original message on a per-recipient basis"); after an alias it cannot. Tests:
`Original_Recipient_is_taken_from_the_message`, `Original_Recipient_is_taken_from_ORCPT`,
`A_confirmed_receipt_returns_the_Original_Recipient`.

Fixed: `CreateReadReceipt` and `Build` write Original-Recipient before Final-Recipient,
from a new optional parameter or from the message's header, which the server now writes
from ORCPT ([K-9](#k-9)).

### K-6
**Closed** in [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272) (`9ff2c72f`).
**`Build` addressed the receipt to the first of several requesters only**
(`EMail/Mime/DispositionNotification.cs:57`, `RequestedBy` is
`MailboxAddress.ParseList(...).FirstOrDefault(...)`, and `:108`, `builder.To.Add(to);`):
`Disposition-Notification-To: bernd@example.net, Carla <carla@example.org>` gives a receipt
to bernd@example.net alone. RFC 8098 §3: "The MDN MUST be addressed (in both the message
header field and the transport envelope) to the address(es) from the
Disposition-Notification-To header field". `Build` is the receipt a reader confirmed - the
confirmation §2.1 asks for when there are several addresses - and the others never get it.
Test: `A_confirmed_receipt_goes_to_every_address_that_asked`.

Fixed: the receipt is addressed to every distinct requester.

### K-7
**Closed** in [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272) (`9ff2c72f`).
**`GoesElsewhere` compared the local-part without case and saw nothing to confirm without a
Return-Path, with a null one, or with several requesters**
(`EMail/Mime/DispositionNotification.cs:72` and `:73`,
`from.Address.Equals(To.Address, StringComparison.OrdinalIgnoreCase)` and
`EnvelopeFrom is { Length: > 0 } envelopeFrom && !envelopeFrom.Equals(To.Address,
StringComparison.OrdinalIgnoreCase)`): `Bernd@example.net` for a message from
`bernd@example.net`, a reverse-path of null (unknown) or "" (<>), and a second requester
next to the sender all give false - "nothing to ask". RFC 8098 §2.1: "the comparison is case
sensitive for the local-part", and "Confirmation from the user MUST be obtained (or no MDN
sent) if there is no Return-Path header field in the message or if there is more than one
distinct address in the Disposition-Notification-To header field". The method is the API's
answer to whether the reader has to be asked; an application that trusts it sends receipts
without consent where the RFC requires it. Tests:
`A_request_the_RFC_wants_confirmed_goes_elsewhere`, four cases.

Fixed: the local-part is compared with case, and each of those cases asks first.

### K-8
**Closed** in [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272) (`4be61b67`).
**`CreateReadReceipt` defaulted to automatic-action/MDN-sent-automatically**
(`EMail/EMail.cs:529`, `var disposition = Disposition ??
MessageDisposition.DisplayedAutomatically;`): the method a mail client calls "when the user
displays (or otherwise disposes of) the message", given no disposition, writes
`Disposition: automatic-action/MDN-sent-automatically; displayed`. RFC 8098 §3.2.6.1:
"manual-action ... Unless prescribed otherwise in a particular mail environment, in order to
preserve the user's privacy, this MUST be the default for MUAs", and the same for
"MDN-sent-manually". §6.2: the disposition mode "can leak information about recipient's MUA
configuration". Test: `CreateReadReceipt_defaults_to_manual_action_and_MDN_sent_manually`.

Fixed: the default is manual-action/MDN-sent-manually.

### K-9
**Closed** in [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272) (`615b309f`).
**The delivering server wrote no Original-Recipient header field from ORCPT**
(`SMTPSession.cs:1413`, `storage.StoreAsync(stampedMessage, ...)` - the stamped message gets
Authentication-Results and Received, nothing from the recipients' ORCPT): `RCPT
TO:<alice@hermod.test> ORCPT=rfc822;alias@hermod.test` is accepted and the stored message
has no Original-Recipient. RFC 8098 §2.3: "if the ORCPT information is available, the
delivering MTA SHOULD insert an Original-Recipient header field at the beginning of the
message (along with the Return-Path header field)" - the only way the mail client learns the
address it is to return in its MDN (K-5). Test:
`The_delivering_server_writes_Original_Recipient_from_ORCPT`.

Fixed: the session groups local recipients by ORCPT and stores one copy per group, with
`Original-Recipient: type;address` on top; recipients without ORCPT are stored together
as before (`2b12e7da` keeps `FileMailStorage` from overwriting copies written in the
same millisecond). When storing a later group fails, the client gets 451 although an
earlier group is stored, and its retry stores that group again. An ORCPT of the
recipient's own address - Postfix and Hermod's own client send one with every RCPT -
counts as none since
[Vanaheimr/Hermod#274](https://github.com/Vanaheimr/Hermod/pull/274) (`e28f36b5`):
before, it split every message from Postfix into one copy per recipient, which the
interop test `Postfix_delivers_one_message_to_two_recipients` caught.

### K-10
**Closed** in [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272) (`5e37c756`).
**The returned header lost all but the first of repeated fields and the white space of
folded ones** (`EMail/EMail.cs:577`, `lines.AddRange(ToText().TakeWhile(...))`, from
the fields `EMail.Parse` kept: `:119`, `headers.TryAdd(kvp.Key, kvp.Value);` into a
dictionary, and `:193`, `AggregateIndentedLines()`, which drops the white space with the
line break): the text/rfc822-headers part of the MDN has Hermod's Received field but not the
one the message came with, and `Comments: x first<CRLF> second` comes back as
`x firstsecond` - Hermod's own Authentication-Results as `mx.hermod.test;spf=none`, its
Received as `[127.0.0.1])by mx.hermod.test ... id 51F6A1011A61for <alice@hermod.test>;Fri`.
RFC 6522 §4: "The text/rfc822-headers body part SHOULD contain all the mail header fields
from the message that caused the report" - "useful ... for diagnostics based on the Received
header fields"; RFC 5322 §2.2.3: "Unfolding is accomplished by simply removing any CRLF that
is immediately followed by WSP" - the WSP stays. The MDN's own Subject is built the same way.
Tests: `The_returned_header_has_every_Received_field`,
`A_folded_field_is_returned_with_its_white_space`.

Fixed: `EMail.Parse` keeps the raw header lines, and `CreateReadReceipt` returns them.

### K-11
**Closed** in [Vanaheimr/Hermod#332](https://github.com/Vanaheimr/Hermod/pull/332) (`b5141d6c`). **A recipient named twice was sent two MDNs** (`SMTPSession.cs:1005`: a RCPT adds
its recipient as it comes, a second time too; `MailStorage/MdnGeneratingMailStorage.cs:181`:
one MDN for each recipient of the envelope). RFC 8098 §2.1: "A user agent MUST NOT issue more
than one MDN on behalf of each particular recipient. That is, once an MDN has been issued on
behalf of a recipient, no further MDNs may be issued on behalf of that recipient by the same
user agent". A message to `<alice@hermod.test>` in two RCPT commands - RFC 5321 forbids it
nowhere -, asking for a receipt to its own reverse-path, is answered with two MDNs for alice.
Test: `A_recipient_named_twice_gives_one_MDN`; `Two_local_recipients_give_two_MDNs_one_for_each`
stays the guard.

Fixed: `MdnGeneratingMailStorage` skips a recipient it has already reported for, compared as
RFC 8098 §2.1 compares addresses - the local-part case-sensitive and without its quotes, the
domain case-insensitive.

## PGP/MIME and the Public Suffix List

RFC 3156 (MIME Security with OpenPGP) on the framework of RFC 1847, as the e-mail builders
sign (`EMailSecurity.sign`, multipart/signed, §5) and encrypt (`EMailSecurity.encrypt`, the
combined method of §6.2 in multipart/encrypted, §4), as `PgpMime` wraps a signature or a
ciphertext made elsewhere, and as `EMail.VerifyPgpSignature`, `DecryptPgp` and
`DecryptAndVerifyPgp` take a message from someone else - with RFC 9580 where RFC 3156 hands
over to OpenPGP (`PgpMimeTests`). The suite reads the MIME with a reader of its own and makes,
checks and opens signatures and ciphertexts with BouncyCastle directly, not through Hermod's
`OpenPGP` class. And the Public Suffix List algorithm (publicsuffix.org, "Formal algorithm")
over Hermod's embedded copy of the list, with the list's own test vectors, and RFC 7489 §3.2
as `DNSVerifier` uses it for DMARC (`PublicSuffixTests`). Line numbers refer to `72c2366d`.

Covered without a finding: multipart/signed with `protocol="application/pgp-signature"`
quoted, exactly two parts, the second `application/pgp-signature`; `micalg` for SHA-1,
RIPEMD-160 and SHA-224 to SHA-512 is `pgp-` and the RFC 9580 text name and is the hash the
signature was made with; the signature holds over the first part as sent, headers included,
for ASCII, non-ASCII, trailing white space, a "From " line, a 120-character line and a
multipart/mixed with an attachment - the text is quoted-printable where it has to be, 7 bit,
no trailing white space, no line over 998; multipart/encrypted with
`protocol="application/pgp-encrypted"` quoted, a `Version: 1` part and an
`application/octet-stream` part; the ciphertext opens to a MIME entity in CRLF, signed by the
sender, in a SEIPD packet whose MDC holds, and its plaintext is canonical as §6.2 requires;
`PgpMime.Signed` writes the signed part octet for octet (with or without a final line break),
takes `micalg` from the signature and refuses 8 bit and bare LF; `PgpMime.Encrypted` as §4
has it. On receipt: binary and canonical-text signatures made elsewhere verify, so does a
part signed with its final CRLF; a changed body, a changed content header or one added space
does not; a signature by another key, an unsigned mail and an S/MIME multipart/signed are not
valid (and the last does not throw); an encrypted message signed by the sender is found
valid, one unsigned or signed by someone else is not; a signed-then-encrypted message (§6.1)
decrypts to a multipart/signed that verifies. The Public Suffix List: the list is embedded
(`DNSVerifications/public_suffix_list.dat`, VERSION 2026-07-15, both divisions), and all 78
test vectors of `tests/test_psl.txt` pass - case, leading dot, unlisted TLDs, wildcards
(`*.mm`, `*.kobe.jp`), exceptions (`!www.ck`, `!city.kobe.jp`), IDN and punycode (Hermod
answers in A-labels); `!pref.hokkaido.jp`, `!city.kawasaki.jp` and the PRIVATE division apply
(two tenants of github.io are two organizations); case and a trailing dot do not change the
Organizational Domain. DMARC: news.example.co.uk is relaxed-aligned with a signature of
example.co.uk and finds the record at `_dmarc.example.co.uk` (never `_dmarc.co.uk`); two
registrants under co.uk, under test.ck or under github.io do not align; `adkim=s` does not use
the Organizational Domain; the Organizational Domain under `*.ck` is found three labels deep;
an author domain in U-labels aligns with its A-label signature and record (RFC 8616 §6).

### G-1
**Closed** in [Vanaheimr/Hermod#273](https://github.com/Vanaheimr/Hermod/pull/273) (`fd87ea38`).
**A ciphertext was decrypted whether or not its integrity held**
(`../BouncyCastle/OpenPGP.cs:440` to `:516`, `DecryptAndVerify`, which `EMail.DecryptPgp`
and `EMail.DecryptAndVerifyPgp` call): `var clearFactory = new
PgpObjectFactory(encrypted.GetDataStream(privateKey));` reads the literal data and `return
(plaintext, signature);` hands it out - `encrypted.Verify()`, the MDC check, is never
called, and `IsIntegrityProtected()` never asked. A SEIPD packet whose ciphertext was
changed in transit decrypts to the changed plaintext: one flipped bit turns "account 4711 as
agreed" into "account 4711!as agre" followed by a block of garbage, and `DecryptPgp` returns
it. A message in the obsolete SED packet, which has no MDC at all, decrypts without a word.
RFC 9580 §5.13.1: "A mismatch of the hash indicates that the message has been modified and
MUST be treated as a security problem"; §5.7 on the SED packet: "An implementation SHOULD
reject such a packet and stop processing the message. If an implementation chooses to
process the packet anyway, it MUST return a clear warning that a non-integrity-protected
packet has been processed" - `PgpDecryptionResult` has no place for one; §13.7: "it SHOULD
NOT attempt to parse nor release decrypted data to the user". This is the malleability EFAIL
exploits in PGP/MIME: a CFB gadget changes the plaintext of a captured message, and a mail
client that renders what Hermod released sends it to the attacker. `DecryptAndVerifyPgp`
reports a changed signed message as `Invalid` - but releases its plaintext all the same, and
an unsigned one is not protected by anything. Tests:
`A_ciphertext_changed_in_transit_is_refused`,
`A_ciphertext_without_integrity_protection_is_refused`.

Fixed: a packet without integrity protection (SED) is refused before anything is
decrypted, and an MDC that does not hold throws `PgpException`; no plaintext is
released.

### G-2
**Closed** in [Vanaheimr/Hermod#273](https://github.com/Vanaheimr/Hermod/pull/273) (`56d719bf`).
**A multipart/signed with a third part verified as valid** (`EMail/EMail.cs:320`
to `:325`): `var parts = Body.NestedBodyparts.ToList(); if (parts.Count < 2) ...` takes
`parts[0]` and `parts[1]` and never looks at how many there are. RFC 3156 §5: "The
multipart/signed body MUST consist of exactly two parts"; RFC 1847 §2.1: "The
multipart/signed content type contains exactly two body parts." Anyone holding one genuinely
signed message of Alice's can add a part ("P.S.: No, pay the invoice to account 666
instead.") and `VerifyPgpSignature` still says `Valid` - for a message whose body now
carries text no signature covers. Test: `A_multipart_signed_with_a_third_part_is_not_valid`.

Fixed: more than two parts are `Invalid`.

### G-3
**Closed** in [Vanaheimr/Hermod#273](https://github.com/Vanaheimr/Hermod/pull/273) (`fde0662d`).
**A part the application attached was signed as it was not sent**
(`EMail/Builder.cs:731` and `:737`): the signed material is
`bodypartToBeSecured.ToText().Select(line => line.TrimEnd())`, and `//ToDo: Apply
Content-Transfer-Encoding`. The trimming applies to what is signed only; the part goes out
as it was. The builder's own text is quoted-printable where it would have trailing white
space or 8 bit, so it is not hurt - but an `EMailBodypart` added with `AddAttachment` is
taken as it is: a 7bit text attachment with "Item 1   " is signed as "Item 1" and sent as
"Item 1   ", and the signature does not verify at the recipient; an 8bit attachment is
signed and sent in 8 bit. RFC 3156 §3: "all data signed according to this protocol MUST be
constrained to 7 bits (8-bit data MUST be encoded using either Quoted-Printable or Base64)"
... "implementations MUST make sure that no trailing whitespace is present after the MIME
encoding has been applied"; §5: "(signed message and transmitted message MUST be
identical)". Tests: `An_attached_text_part_with_trailing_white_space_is_signed_as_sent`,
`An_attached_8bit_text_part_is_signed_in_7bit`.

Fixed: a part that needs it is encoded as quoted-printable or base64 before signing,
signed untrimmed and sent as signed; the application's part is not changed.

### G-4
**Closed** in [Vanaheimr/Hermod#273](https://github.com/Vanaheimr/Hermod/pull/273) (`56d719bf`).
**A broken signature part threw instead of failing verification**
(`EMail/EMail.cs:342` and `:344`, into `../BouncyCastle/OpenPGP.cs:337` to `:340`):
`PgpUtilities.GetDecoderStream(ArmoredSignature)` and `factory.NextPgpObject()` are not
guarded. An armor header around a broken packet throws `IOException: invalid header
encountered`, armor around no base64 throws `ArmoredInputException: invalid armor` - out of
`VerifyPgpSignature`, into the application that checks incoming mail. RFC 3156 §5: "The
second body MUST contain the OpenPGP digital signature" - a part that holds none is a failed
verification, a result the sender of the message controls; plain text without armor already
gives `NoSignature`. Test: `A_signature_part_without_a_signature_is_not_valid` (two of its
three cases).

Fixed: a signature part that does not read is `Invalid`.

### G-5
**Closed** in [Vanaheimr/Hermod#273](https://github.com/Vanaheimr/Hermod/pull/273) (`7be69186`).
**`PgpMime.Signed` took a signed part with trailing white space**
(`EMail/Mime/PgpMime.cs:52`, `CheckSignedPart`, `:151` to `:180`): it refuses 8 bit, bare CR
and LF and lines over 998 octets - "anything else some relay on the way would change, and the
signature with it" - but not white space at the end of a line, which relays change as well.
RFC 3156 §3: "implementations MUST make sure that no trailing whitespace is present after the
MIME encoding has been applied", and the note: "The restrictions on whitespace are necessary
in order to make the hash calculated invariant under the text and binary mode signature
mechanisms". Test: `PgpMime_Signed_refuses_a_part_with_trailing_white_space`.

Fixed: a space or tab before CR LF or at the very end is refused.

### G-6
**Closed** in [Vanaheimr/Hermod#273](https://github.com/Vanaheimr/Hermod/pull/273) (`fde0662d`).
**micalg for SHA3 was `pgp-sha3_256`, not `pgp-sha3-256`**
(`EMail/Builder.cs:745`): `MicAlg = "pgp-" + HashAlgorithm.ToString().ToLowerInvariant()`
spells the BouncyCastle enum, `Sha3_256`. RFC 3156 §5: "Hash-symbols are constructed from the
text names registered in [1] or according to the mechanism defined in that document by
converting the text name to lower case and prefixing it with the four characters "pgp-"";
RFC 9580 §9.5 registers "SHA3-256" and "SHA3-512". The signature itself is made with SHA3,
so a reader that takes micalg at its word hashes for an algorithm that does not exist.
(`PgpMime.MicAlg` refuses SHA3 rather than misname it.) Test:
`The_micalg_of_a_SHA3_signature_is_its_registered_text_name` (SHA3-256, SHA3-512).

Fixed: the new `PgpMime.MicAlg(HashAlgorithmTag)` names hashes as RFC 9580 does.

## Observations without a test yet

None left. Of those the first round noted:

- **`VerifySpf` / `VerifyDkim` / `VerifyDmarc` had no effect** - fixed in Hermod
  `0eb11d09` ("The verification switches and session limits are applied"), outside
  this suite's PRs.
- **Unbounded line reads** - fixed with S-1 ([Vanaheimr/Hermod#95](https://github.com/Vanaheimr/Hermod/pull/95)):
  `SMTPLineReader` enforces the limit while reading, so a peer that never sends CR LF
  cannot grow the buffer past it.
- The others became S-18, S-19, C-8, C-9 and C-10 above, all closed.
