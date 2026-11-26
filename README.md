# SMTP Conformance Tests for Vanaheimr Hermod

[![CI](https://github.com/Vanaheimr/SMTPConformanceTests/actions/workflows/ci.yml/badge.svg)](https://github.com/Vanaheimr/SMTPConformanceTests/actions/workflows/ci.yml)
[![Nightly](https://github.com/Vanaheimr/SMTPConformanceTests/actions/workflows/nightly.yml/badge.svg)](https://github.com/Vanaheimr/SMTPConformanceTests/actions/workflows/nightly.yml)

Conformance and interoperability tests for the SMTP stack of
[Vanaheimr Hermod](https://github.com/Vanaheimr/Hermod) — the inbound
`SMTPServer`/`SMTPSession` (MTA, submission and implicit-TLS ports) and the
`SMTPSubmissionClient` — judged against the RFCs, not against Hermod itself.

Same shape as the sibling suites (DNS, NTS, SSH, HTTP/1…3): Hermod and Styx
are git submodules under `libs/`, the tests build against exactly the pinned
revisions, and every check is either an RFC requirement with its section in the
test description, or an interop result against an independent implementation.

**State (2026-11-26, Hermod `83b63bb0`):** 1232 tests, **all pass**. A twenty-fourth round tested binary data on the wire - a line of more than 998
octets, a NUL - and BODY=BINARYMIME over BDAT (RFC 3030 §3) - 14 tests, 4 findings: the
submission client sent binary data declared BODY=8BITMIME to a server that offers BINARYMIME
([C-25](FINDINGS.md#c-25)), and to a server without BINARYMIME at all
([C-26](FINDINGS.md#c-26)); the relay sent it to a next hop without BINARYMIME
([O-32](FINDINGS.md#o-32)), and as DATA to one that offers it ([O-33](FINDINGS.md#o-33)). All
four fixed in [#331](https://github.com/Vanaheimr/Hermod/pull/331).
A twenty-third round tested when the relay tries again, and how many copies it
sends (RFC 5321 §4.5.4.1) - 12 tests, 4 findings: a next hop that refused the session for now
was tried again at once for the next message to it ([O-28](FINDINGS.md#o-28)); the retry
intervals and the give-up time could not be configured ([O-29](FINDINGS.md#o-29)); a message
refused for now could be tried again after 27 minutes ([O-30](FINDINGS.md#o-30)); and
recipients at one domain written two ways got a copy each ([O-31](FINDINGS.md#o-31)). All
four fixed in [#329](https://github.com/Vanaheimr/Hermod/pull/329).
A twenty-second round tested what a part is when the reader does not know its
subtype, and the message a message carries - 18 tests, 4 findings: a text of a subtype the
reader does not know was an attachment, so a text/markdown mail had no body
([E-26](FINDINGS.md#e-26)); a message part of a subtype it does not know was lost
([E-27](FINDINGS.md#e-27)); an attached message with UTF-8 in its header was written
message/rfc822, not message/global ([E-28](FINDINGS.md#e-28)); and one with a line over 998
octets or a NUL was written 7bit or 8bit, not binary ([E-29](FINDINGS.md#e-29)). All four
fixed in [#326](https://github.com/Vanaheimr/Hermod/pull/326).
A twenty-first round tested what an answer takes from the message it answers and
the list it came through - 18 tests, 4 findings: the subject of a reply to a list's post had
two "Re: " ([E-22](FINDINGS.md#e-22)); white space inside the angle brackets of List-Post
lost the list ([E-23](FINDINGS.md#e-23)); List-Post was read for the first mailto anywhere
in it, a comment's too ([E-24](FINDINGS.md#e-24)); and the older builder wrote List-Post's
mailto URL with "?", "#", "%" and "/" as they are ([E-25](FINDINGS.md#e-25)). All four
fixed in [#318](https://github.com/Vanaheimr/Hermod/pull/318).
A twentieth round tested the parts an HTML mail refers to, and what a part is
for - 15 tests, 5 findings: a Content-ID with a comment was not read as a msg-id, so the
part a cid: URL names, and the root of a multipart/related, were not found
([E-17](FINDINGS.md#e-17)); a part of a disposition type the reader does not know was lost
([E-18](FINDINGS.md#e-18)); a text marked inline with a file name was taken for an
attachment ([E-19](FINDINGS.md#e-19)); a Content-ID was written whether it was a msg-id or
not, a non-ASCII character as "?" ([E-20](FINDINGS.md#e-20)); and a multipart/related was
written without its type parameter ([E-21](FINDINGS.md#e-21)). All five fixed in
[#317](https://github.com/Vanaheimr/Hermod/pull/317).
A nineteenth round tested where the DMARC and the TLS-RPT reporter send a report
and what the DMARC failure report says of the message - 17 tests, 7 findings: a line break
in a rua, ruf or TLS-RPT rua URI went into the report as a header field of its own and
into its recipient, and from there into RCPT TO ([R-8](FINDINGS.md#r-8),
[T-5](FINDINGS.md#t-5)); a mailto URI was taken for an address, percent-encoding and
header fields and all ([R-9](FINDINGS.md#r-9), [T-6](FINDINGS.md#t-6)); a line break in
the SPF record made a field of the failure report of its own ([R-10](FINDINGS.md#r-10));
Original-Mail-From was no reverse-path ([R-11](FINDINGS.md#r-11)); and an IPv6 Source-IP
no IPv6 address literal ([R-12](FINDINGS.md#r-12)). All seven fixed in
[#316](https://github.com/Vanaheimr/Hermod/pull/316).
An eighteenth round
tested the store a server keeps local mail in when it is given
none of its own - 10 tests, 3 findings: the SPF record of the sender's domain went into the
stored header as DNS gave it, so a line break in it made a header field of its own -
"X-DMARC-Result: Pass" - and an empty line ended the header ([S-48](FINDINGS.md#s-48)); the
store's own fields went before the Return-Path ([S-49](FINDINGS.md#s-49)); and a message
whose Message-ID was too long for a file name could not be stored ([S-50](FINDINGS.md#s-50)).
All three fixed in [#312](https://github.com/Vanaheimr/Hermod/pull/312).
A seventeenth round
tested DSN as the submission client and the relay ask for it when an application hands them
a message - 15 tests, 3 findings: ENVID went on MAIL as the caller gave it, not as xtext, so
a line break in it made a command of its own - a recipient the sender did not name
([C-22](FINDINGS.md#c-22)); RET without NOTIFY and ENVID was left out
([C-23](FINDINGS.md#c-23)); and NOTIFY=NEVER could not be asked for
([C-24](FINDINGS.md#c-24)). All three fixed in [#311](https://github.com/Vanaheimr/Hermod/pull/311).
A sixteenth round
tested SMTPUTF8 as the submission client uses it - 7 tests, 2 findings: the client sent an
internationalized message - UTF-8 addresses in MAIL and RCPT, UTF-8 in the header - to a
server that does not offer SMTPUTF8 ([C-20](FINDINGS.md#c-20)), and asked for SMTPUTF8 for
a message whose only non-ASCII octets are in an 8-bit body ([C-21](FINDINGS.md#c-21)).
Both fixed in [#309](https://github.com/Vanaheimr/Hermod/pull/309).
A fifteenth round
tested the header fields the server writes into a message - Authentication-Results, and
the Received field of an SMTPUTF8 transaction - 9 tests, 5 findings. The heaviest: an
Authentication-Results field with the server's own authserv-id, written into the message
by its sender, was kept, so a sender wrote "dmarc=pass" for the reader's filters itself
([S-43](FINDINGS.md#s-43)); and the SPF result named the local-part of the reverse-path,
which SPF did not authenticate ([S-45](FINDINGS.md#s-45)). All 5 fixed in
[#308](https://github.com/Vanaheimr/Hermod/pull/308).
A fourteenth round
tested REQUIRETLS (RFC 8689) beyond the option itself - which MX hosts a message that
requires TLS may go to, what follows when one cannot take it, the bounces of such a
message, "TLS-Required: No", and the option as the submission client gives it - 18 tests,
8 findings. The heaviest: a REQUIRETLS message went to an MX host that neither DNSSEC nor
an MTA-STS policy vouched for, so whoever forged the MX record got it
([O-23](FINDINGS.md#o-23)); an MX host without REQUIRETLS bounced the message though the
next one offered it ([O-24](FINDINGS.md#o-24)); the bounce of a REQUIRETLS message
returned its body ([D-14](FINDINGS.md#d-14)); and the submission client gave a REQUIRETLS
message to a server without REQUIRETLS, and left the option out
([C-19](FINDINGS.md#c-19)). All 8 fixed in
[#304](https://github.com/Vanaheimr/Hermod/pull/304) and
[#305](https://github.com/Vanaheimr/Hermod/pull/305).
A thirteenth round
tested the edges of a session - what a server says when it is stopped, a parameter that
may be given once given twice, a next hop that refuses the session at the first of its MX
hosts or at one of its addresses - 15 tests, 4 findings. The heaviest: a 554 or 521
greeting of the first MX host bounced the message, and the other MX hosts of the domain
were never tried ([O-21](FINDINGS.md#o-21)); a multihomed next hop whose first address
refused the session was given up on, its other addresses never tried
([O-22](FINDINGS.md#o-22)); and a server that was stopped closed every session without
the 421 RFC 5321 §3.8 asks for ([S-41](FINDINGS.md#s-41)). All 4 fixed in
[#301](https://github.com/Vanaheimr/Hermod/pull/301) and
[#302](https://github.com/Vanaheimr/Hermod/pull/302).
A twelfth round
tested SMTP AUTH beyond its dialogue - how long a SASL response may be, the base64 it is
written in, how an exchange ends, a user store that cannot be asked, the AUTH parameter
the relay owes a smart host it signed in to, the initial response and the challenges of
the two clients - 20 tests, 8 findings. The heaviest: the relay signed in to its smart
host and left AUTH=<> out of MAIL FROM, so the smart host took every relayed message for
one its account submitted ([O-19](FINDINGS.md#o-19)); a user store that could not be
asked was 535, and every client was told its password is wrong
([S-40](FINDINGS.md#s-40)); the longest PLAIN response RFC 4616 has the server take was
"500 Line too long" ([S-37](FINDINGS.md#s-37)); and a line too long in an AUTH exchange
left it open, so the next command was taken for a SASL response
([S-39](FINDINGS.md#s-39)). All 8 fixed in
[#297](https://github.com/Vanaheimr/Hermod/pull/297) and
[#298](https://github.com/Vanaheimr/Hermod/pull/298).
An eleventh round
tested how the two clients read a reply code, and internationalized domain names wherever
Hermod meets one - the DNS lookups of the relay, of SPF, DKIM and DMARC, the local domains
of the server, the names the server and the clients give themselves - 38 tests, 11
findings. The heaviest: a 252 to MAIL - a positive reply, to be read by its first digit -
left the relay's transaction, and the message was reported delivered unsent
([O-15](FINDINGS.md#o-15)); an envelope sender in U-labels had its SPF record looked up in
U-labels, so a domain's "-all" was "none" ([V-23](FINDINGS.md#v-23)); the DMARC policy of
an author domain in U-labels was never found, and its organizational domain's applied
instead ([V-25](FINDINGS.md#v-25)); mail to a domain in U-labels was never delivered, its
MX lookup failing for five days ([O-17](FINDINGS.md#o-17)); and mail for the server's own
domain, written in the other form, was refused as relaying ([S-35](FINDINGS.md#s-35)). All
11 fixed in [#293](https://github.com/Vanaheimr/Hermod/pull/293) to
[#295](https://github.com/Vanaheimr/Hermod/pull/295).
A tenth round tested
what RFC 5321 asks of a server beyond its commands, and of a client beyond its dialogue -
the trace fields and final delivery, loop detection, the paths of MAIL and RCPT as the
grammar has them, HELP, EXPN and VRFY, the timeouts of the clients, SMTPUTF8 in ORCPT and
in bounces - 31 tests, 10 findings, and O-14 seen on the way. The heaviest: nothing
detected a loop, a message that had been through 150 hops was delivered and relayed on
([S-28](FINDINGS.md#s-28)); a delivered message got no Return-Path, so one the client
wrote into it was the only one the mailbox saw ([S-29](FINDINGS.md#s-29)); the EHLO
argument went into the Received field unchecked, and a client wrote the TCP-info it liked
in front of the true one ([S-30](FINDINGS.md#s-30)); the relay waited 60 seconds for the
reply to the end of data, not the 10 minutes of §4.5.3.2.6, and a slow next hop got the
message again ([O-13](FINDINGS.md#o-13)); and the ORCPT the relay wrote was no xtext, so a
recipient with a "+" was refused by a next hop that checks it - Postfix does - and the
message bounced ([O-14](FINDINGS.md#o-14)). All 11 fixed in
[#287](https://github.com/Vanaheimr/Hermod/pull/287) to
[#290](https://github.com/Vanaheimr/Hermod/pull/290).
A ninth round tested
when a DMARC policy is applied at all and SASL in its details - 33 tests, 15 findings. The
heaviest: a temporary error of SPF, with no signature passing, failed DMARC and applied
p=reject ([V-18](FINDINGS.md#v-18)); the SCRAM server-final-message travelled in the 235
reply, which SMTP has no room for ([S-20](FINDINGS.md#s-20)), and Hermod's client took a
235 without it as success - a server that never proved it knows the password got the
message ([C-12](FINDINGS.md#c-12)); the TLS handshake never asked for a client
certificate, so SASL EXTERNAL never worked ([S-27](FINDINGS.md#s-27)). All 15 fixed in
[#282](https://github.com/Vanaheimr/Hermod/pull/282),
[#284](https://github.com/Vanaheimr/Hermod/pull/284) and
[#285](https://github.com/Vanaheimr/Hermod/pull/285). An eighth round
tested what of SPF, DKIM and the way to the next hop the earlier rounds took for granted -
59 tests, 19 findings. The heaviest: a DNS error - a SERVFAIL, a timeout - turned an SPF
check into `none`, or into `fail` under `-all`, never `temperror` ([V-5](FINDINGS.md#v-5));
a DKIM signature that did not sign From verified, and DMARC passed on it whatever From was
put in ([V-13](FINDINGS.md#v-13)); signatures with RSA keys of 512 bits verified
([V-14](FINDINGS.md#v-14)); and a temporary error of the MX lookup sent the message to the
domain's own address ([O-9](FINDINGS.md#o-9)). All 19 fixed in
[#277](https://github.com/Vanaheimr/Hermod/pull/277),
[#279](https://github.com/Vanaheimr/Hermod/pull/279),
[#280](https://github.com/Vanaheimr/Hermod/pull/280) and
[#281](https://github.com/Vanaheimr/Hermod/pull/281). The older
`EMail.Parse` read a Content-Type with case, against RFC 2045 §5.1: a `Multipart/Signed`
whose signature was valid was reported as unsigned, a `Multipart/Encrypted` was not
decrypted ([E-14](FINDINGS.md#e-14)); white space and comments in it broke the boundary
([E-15](FINDINGS.md#e-15)); and the text `boundary=`, not the type, made a body a multipart
([E-16](FINDINGS.md#e-16)). All three fixed in
[#276](https://github.com/Vanaheimr/Hermod/pull/276). A seventh round tested what of Hermod's mail code no round had touched, none of
it changed since - MIME and the message format as Hermod builds and reads mail (RFC 2045
to 2047, 2231, 5322), the reports that arrive (DSN, DMARC, TLS-RPT), read receipts (RFC
8098), PGP/MIME (RFC 3156) and the Public Suffix List under DMARC - with 380 tests, the
MIME read back by the suite's own grammar and the signatures checked with BouncyCastle
directly. Six of its 36 findings were high: a comment after the address named the
mailbox, so `From: mallory@evil.example (<ceo@company.example>)` was ceo@company.example
to an application and to the DKIM signer, while DMARC checked evil.example
([E-1](FINDINGS.md#e-1)); a gzipped TLS report of 175 KiB was inflated to 128 MiB before
the reply to DATA, by anyone ([I-1](FINDINGS.md#i-1)); nested XML in a DMARC report ended
the process ([I-2](FINDINGS.md#i-2)); read receipts went automatically to any address a
message named ([K-1](FINDINGS.md#k-1)), and a header folded onto many lines held the
session for a time that grew with their square ([K-2](FINDINGS.md#k-2)); decryption
ignored the integrity check, the EFAIL weakness ([G-1](FINDINGS.md#g-1)). All 36 fixed in
[#269](https://github.com/Vanaheimr/Hermod/pull/269) to
[#274](https://github.com/Vanaheimr/Hermod/pull/274). The Public
Suffix List passes all 78 of its official test vectors. A sixth round tested the parts of Hermod's
SMTP no round had tested - ARC (RFC 8617), the DMARC reports (RFC 7489 §7), TLS
reporting (RFC 8460), MT-PRIORITY (RFC 6710), the connection and recipient limits - with
78 tests, the ARC chains sealed and Hermod's seals validated by the suite's own code.
The heaviest of its 26 findings: an ARC instance number of 2147483647 in one header line
kept the validator counting forever, on every message from a client that did not sign
in, and there was no limit of 50 sets ([A-1](FINDINGS.md#a-1)). Also: rsa-sha1 verified,
and a signature whose b= came first never did, in DKIM and ARC alike
([V-3](FINDINGS.md#v-3), [V-4](FINDINGS.md#v-4)); the aggregate XML lacked elements
Appendix C requires, and size limits of report URIs were ignored
([R-1](FINDINGS.md#r-1), [R-2](FINDINGS.md#r-2)); MTA-STS testing mode reported failed
sessions as successes ([T-3](FINDINGS.md#t-3)); a client nobody vouched for raised its
own priority ([Q-3](FINDINGS.md#q-3)); 100 recipients per session, not per message
([L-1](FINDINGS.md#l-1)). All 26 fixed in
[#260](https://github.com/Vanaheimr/Hermod/pull/260) to
[#264](https://github.com/Vanaheimr/Hermod/pull/264). A fifth round tested what Hermod's SMTP gained between `bbbf88b6` and
`4b8be28a` - SPF, DKIM and DMARC on inbound mail, DNS blocklists, recipient checks,
the AUTH configuration, submission to the application (RFC 6409), outbound mail to
public addresses only, smart host credentials, DKIM signing with RSA and Ed25519, the
file queue after a crash, the certificate chain - with 72 tests, DKIM signed and
verified by the suite's own code. Three findings: a DKIM key record without its
optional `v=DKIM1` was not found, so the signature failed ([V-1](FINDINGS.md#v-1));
the Authentication-Results of a bounce said `smtp.mailfrom=<>` instead of the HELO
identity SPF checked ([V-2](FINDINGS.md#v-2)); `PublicAddressesOnly` took the IPv4
documentation ranges for public ([P-1](FINDINGS.md#p-1)). All three fixed in
[#257](https://github.com/Vanaheimr/Hermod/pull/257) to
[#259](https://github.com/Vanaheimr/Hermod/pull/259). A fourth round
tested what the relay owes beyond delivery: the reports to the sender (DSN, D-1 to
D-12), MTA-STS (M-1 to M-6) and DANE (N-1 to N-5) - 23 findings, among them bounces
with CR CR LF line ends and one Message-ID for all, a message lost without a bounce
because it mentioned "multipart/report", an MTA-STS wildcard matching any depth,
DANE-TA accepting a certificate for any name, and DANE turned off by a stripped or
failed TLSA lookup. All fixed in [#134](https://github.com/Vanaheimr/Hermod/pull/134),
[#135](https://github.com/Vanaheimr/Hermod/pull/135),
[#136](https://github.com/Vanaheimr/Hermod/pull/136),
[#144](https://github.com/Vanaheimr/Hermod/pull/144) and [#149](https://github.com/Vanaheimr/Hermod/pull/149) - the last after three DNS fixes a
live probe called for (#139 to #141). A third round tested `SMTPOutboundClient`, the relay side - against a
scripted next hop and against Postfix in both directions - and found eight findings
(O-1 to O-8), with partial delivery in the submission client (C-11) all fixed in
[#130](https://github.com/Vanaheimr/Hermod/pull/130) and [#131](https://github.com/Vanaheimr/Hermod/pull/131). A second round
made five more findings (S-18, S-19, C-8 to C-10) from the observations the first left
without a test - all five fixed too ([#124](https://github.com/Vanaheimr/Hermod/pull/124)
to [#127](https://github.com/Vanaheimr/Hermod/pull/127)). The first run, against Hermod `8af03484`,
found 24 findings with 52 failing tests; all 24
are fixed in Hermod since ([Vanaheimr/Hermod#95](https://github.com/Vanaheimr/Hermod/pull/95)
to [#123](https://github.com/Vanaheimr/Hermod/pull/123)), each with regression tests
of its own in `HermodTests`, and [FINDINGS.md](FINDINGS.md) keeps RFC quote, cause
and fix for every one. Those that mattered beyond conformance:
[SMTP smuggling](FINDINGS.md#s-1) (S-1), [BDAT chunks executed as commands](FINDINGS.md#s-2) (S-2),
a [STARTTLS downgrade in the submission client](FINDINGS.md#c-1) (C-1), the client
[sending bare LFs](FINDINGS.md#c-5) - the smuggling primitive from the other side (C-5),
[AUTH inside a transaction](FINDINGS.md#s-15) (S-15) and
[`RequireStartTls` leaving AUTH in cleartext](FINDINGS.md#s-13) (S-13). A new finding
gets a test tagged `KnownIssue`, which keeps the merge gate green while it is red.

## Layout

```
src/SMTPConformance.Core/          shared infrastructure, no tests
  RawSmtp/SmtpWire.cs              byte-exact line reader: LF-split, reports bare LF / bare CR
  RawSmtp/RawSmtpClient.cs         independent SMTP client (replies parsed without Hermod)
  RawSmtp/SmtpReply.cs             RFC 5321 §4.2 reply grammar, RFC 3463 enhanced codes
  Scripted/ScriptedSmtpServer.cs   loopback server running a script per connection
  Scripted/SmtpServerScript.cs     configurable well-behaved server dialogue (client tests)
  Fixtures/HermodSmtpServerFixture real SMTPServer on port 0 (asks where it landed), in-memory
                                   storage/queue/users, stub DNS, self-signed cert
  Wsl.cs, TestEnvironment.cs       WSL / native-Linux bridge and capability gating

conformance/                       hermetic: no network, no external tools
  SMTPConformance.Server.Tests     RFC 5321 core, 2920, 1870, 3030, 6152, 6531, 2034, 3461, smuggling,
                                   reports that arrive, RFC 8098 MDN
  SMTPConformance.Tls.Tests        RFC 3207 STARTTLS, RFC 8314 implicit TLS, RFC 8689 REQUIRETLS
  SMTPConformance.Auth.Tests       RFC 4954, 4616, LOGIN, RFC 5802/7677 SCRAM (own oracle), RFC 6409
  SMTPConformance.Client.Tests     SMTPSubmissionClient against scripted servers
  SMTPConformance.MessageFormat.Tests  RFC 5322 App. A addresses, RFC 6376 §3.4.5 DKIM, RFC 7208 §7.4 SPF macros,
                                   MIME (RFC 2045-2047, 2231, 5322), RFC 3156 PGP/MIME, Public Suffix List

interop/                           category WSL: real tools, WSL on Windows, native on Linux
  SMTPInterop.LinuxTools.Tests     swaks, CPython smtplib, openssl s_client, Postfix smtp-sink
```

## Running

Clone with submodules, then build and run the hermetic gate (what CI runs):

```bash
git clone --recurse-submodules https://github.com/Vanaheimr/SMTPConformanceTests.git
```

```bash
dotnet test SMTPConformanceTests.slnx --filter "TestCategory!=Online&TestCategory!=WSL&TestCategory!=Docker&TestCategory!=KnownIssue"
```

The open findings — every one of these is expected to fail:

```bash
dotnet test SMTPConformanceTests.slnx --filter "TestCategory=KnownIssue"
```

The interop lane needs the tools inside WSL (Debian 13 here) or on the Linux host:

```bash
wsl -u root apt-get install -y swaks libnet-ssleay-perl libio-socket-ssl-perl libauthen-sasl-perl openssl python3 postfix
```

```bash
dotnet test SMTPConformanceTests.slnx --filter "TestCategory=WSL"
```

Install postfix with "No configuration" (or preseed
`postfix postfix/main_mailer_type select No configuration`): only `smtp-sink` is
used, no mail system is set up. Under WSL's NAT networking the tools reach the
server through the Windows host address; if the Windows firewall blocks that,
the tests skip with a message saying so rather than fail.

### Categories

| Category | Meaning | In CI gate |
|---|---|---|
| *(none)* | hermetic conformance test | yes |
| `KnownIssue` | asserts an RFC requirement Hermod currently violates — see FINDINGS.md | no (nightly report) |
| `WSL` | drives a Linux tool | no (nightly, native in `debian:13`) |
| `Online` / `Docker` | reserved | no |

Each `KnownIssue` test also carries `[Property("Finding", "S-…")]`.

## How the tests see the wire

Every server-side test talks to Hermod through `RawSmtpClient`, which shares no
code with Hermod: it writes exactly the bytes asked for and parses replies with
its own RFC 5321 grammar, recording violations (bare LF, wrong separators, code
mismatch across lines) instead of throwing. Its line reader splits on LF only
and reports whether a CR preceded it — a `StreamReader` would accept CR, LF and
CRLF alike, which is precisely the ambiguity smuggling exploits, and a test peer
built on one could neither produce nor notice it.

The client-side tests run `SMTPSubmissionClient` against `ScriptedSmtpServer`,
whose default dialogue is strict where RFC 5321 is (end of data is
`CRLF.CRLF` and nothing else) and configurable where real servers differ
(no EHLO, no 8BITMIME, 454 to STARTTLS, lower-case keywords, …).

Independent oracles in the suite: the SCRAM-SHA-256 client in
`SMTPConformance.Auth.Tests` (pinned to the RFC 7677 §3 example before it is
trusted), the RFC 5322 Appendix A, RFC 6376 §3.4.5 and RFC 7208 §7.4 example
vectors, and the four Linux tools.

## Coverage

| Specification | Tests | Failing | Open findings |
|---|---:|---:|---|
| RFC 5321 SMTP — greeting, EHLO/HELO, command syntax, state machine, DATA, transparency, trace, relay, postmaster | 55 | 0 | ~~S-6~~, ~~S-8~~, ~~S-9~~, ~~S-10~~, ~~S-18~~, ~~S-19~~ fixed |
| RFC 5321 §2.3.8 line terminators / SMTP smuggling | 9 | 0 | ~~S-1~~ fixed |
| RFC 2920 PIPELINING | 4 | 0 | — |
| RFC 1870 SIZE | 5 | 0 | ~~S-6~~, ~~S-7~~ fixed |
| RFC 3030 CHUNKING / BDAT | 8 | 0 | ~~S-2~~, ~~S-3~~ fixed |
| RFC 6152 8BITMIME, RFC 6531 SMTPUTF8 | 6 | 0 | ~~S-6~~, ~~S-11~~, ~~S-12~~ fixed |
| RFC 2034 / 3463 enhanced status codes | 16 | 0 | ~~S-4~~, ~~S-5~~ fixed |
| RFC 3461 DSN parameters | 5 | 0 | ~~S-6~~ fixed |
| RFC 3207 STARTTLS, RFC 8314 implicit TLS, RFC 8689 REQUIRETLS, RFC 8446 §4.4.2 certificate chain | 24 | 0 | ~~S-8~~, ~~S-13~~, ~~S-14~~ fixed |
| RFC 4954 AUTH, RFC 4616 PLAIN, LOGIN, RFC 5802/7677 SCRAM, RFC 6409 submission, RFC 3461 relay | 32 | 0 | ~~S-5~~, ~~S-14~~, ~~S-15~~, ~~S-16~~, ~~S-17~~ fixed |
| RFC 5802 SCRAM in detail (RFC 4422 §3, the GS2 header, c=, a=, saslname, m=, SASLprep), RFC 4422 Appendix A EXTERNAL | 14 | 0 | ~~S-20~~ to ~~S-27~~ fixed |
| Submission client (RFC 5321, 1870, 2920, 3030, 3207, 4954, 6152, 5802) | 35 | 0 | ~~C-1~~ to ~~C-13~~ fixed |
| Outbound client (RFC 5321, 3461, 6152, 6531, 8689) | 22 | 0 | ~~O-1~~ to ~~O-8~~ fixed |
| RFC 5321 §5.1 the next hop: the MX lookup, the order of the MX hosts, the relay among them | 9 | 0 | ~~O-9~~ to ~~O-12~~ fixed |
| Relay reports (RFC 3461, 3464, 6522) | 25 | 0 | ~~D-1~~ to ~~D-12~~ fixed |
| MTA-STS (RFC 8461), DANE (RFC 7672) | 41 | 0 | ~~M-1~~ to ~~M-6~~, ~~N-1~~ to ~~N-5~~ fixed |
| Inbound RFC 7208 SPF, RFC 6376 DKIM, RFC 8301, RFC 7489 DMARC, RFC 8601 Authentication-Results; RFC 5782 DNS blocklists | 17 | 0 | ~~V-1~~ to ~~V-4~~, ~~R-7~~ fixed |
| RFC 7208 §4 to §6 SPF evaluation: DNS errors, the record set, syntax, modifiers, ptr, limits | 27 | 0 | ~~V-5~~ to ~~V-12~~ fixed |
| RFC 6376 §6.1, RFC 8301 §3.2 DKIM verification: required tags, From, i=, key size, key record | 18 | 0 | ~~V-13~~ to ~~V-17~~ fixed |
| RFC 7489 §6.6.2, §6.6.3 DMARC policy discovery: temporary errors, the record set, the version, p= and sp= | 15 | 0 | ~~V-18~~ to ~~V-22~~ fixed |
| RFC 8617 ARC: validation on inbound mail, the sealer | 17 | 0 | ~~A-1~~ to ~~A-5~~, ~~V-3~~, ~~V-4~~ fixed |
| RFC 7489 §7 DMARC aggregate and failure reports, RFC 6591 | 16 | 0 | ~~R-1~~ to ~~R-6~~ fixed |
| RFC 8460 TLS reporting | 12 | 0 | ~~T-1~~ to ~~T-4~~ fixed |
| RFC 6710 MT-PRIORITY | 18 | 0 | ~~Q-1~~ to ~~Q-4~~ fixed |
| RFC 5321 §3.1, §3.8, §4.5.3.1.8 connection and recipient limits | 6 | 0 | ~~L-1~~ to ~~L-4~~ fixed |
| RFC 5321 §3.3, §4.5.1, §6.1 recipient checks and storage failures; RFC 6409 submission to the application | 12 | 0 | — |
| Outbound: RFC 6890 public addresses only, smart host credentials, DKIM signing and keys (RFC 6376, RFC 8463, RFC 8301) | 31 | 0 | ~~P-1~~ to ~~P-3~~ fixed |
| RFC 5321 §6.1 the file queue after a crash | 5 | 0 | — |
| RFC 5322 addresses, RFC 6376 DKIM canonicalization, the suite's DKIM signer/verifier and ARC sealer/validator, RFC 7208 SPF macros | 44 | 0 | — |
| RFC 2045, 2046, 2047, 2231, 5322, 2919: MIME and the message format, built and read | 141 | 0 | ~~E-1~~ to ~~E-16~~ fixed |
| Reports that arrive: RFC 3464 DSN, RFC 7489 Appendix C, RFC 8460; hostile input | 51 | 0 | ~~I-1~~ to ~~I-7~~ fixed |
| RFC 8098 message disposition notifications | 41 | 0 | ~~K-1~~ to ~~K-10~~ fixed |
| RFC 3156 PGP/MIME, RFC 9580 | 64 | 0 | ~~G-1~~ to ~~G-6~~, ~~E-14~~ fixed |
| Public Suffix List (its 78 test vectors), RFC 7489 §3.2 Organizational Domain | 99 | 0 | — |
| RFC 5321 §4.4 trace fields and final delivery: Return-Path, Received; §6.3 loop detection | 12 | 0 | ~~S-28~~ to ~~S-30~~ fixed |
| RFC 5321 §4.1.2 paths: source routes, quoted local parts; RFC 6533 §3 the UTF-8 address type in ORCPT | 11 | 0 | ~~S-31~~, ~~S-32~~, ~~S-34~~ fixed |
| RFC 5321 §3.5, §4.1.1.6 to §4.1.1.8, §4.2.4, §7.3 HELP, EXPN and VRFY | 4 | 0 | ~~S-33~~ fixed |
| RFC 5321 §4.5.3.2 the timeouts of the relay and of the submission client | 2 | 0 | ~~O-13~~, ~~C-14~~ fixed |
| RFC 6533 §4, RFC 6532 §3.7 the bounce of an SMTPUTF8 message | 2 | 0 | ~~D-13~~ fixed |
| RFC 3461 §4.2, §5.2.1 the ORCPT the relay writes | 4 | 0 | ~~O-14~~ fixed |
| RFC 5321 §4.2.1 reply codes by their first digit, §4.5.3.1.10 552 to RCPT - relay and submission client | 20 | 0 | ~~O-15~~, ~~O-16~~, ~~C-15~~ fixed |
| RFC 6531 §3.2, §3.7 internationalized domain names: the relay's lookups, local domains, EHLO and the greeting | 9 | 0 | ~~O-17~~, ~~O-18~~, ~~S-35~~, ~~S-36~~, ~~C-16~~ fixed |
| RFC 8616 SPF, DKIM and DMARC of internationalized domains | 9 | 0 | ~~V-23~~ to ~~V-25~~ fixed |
| Interop: swaks, smtplib, openssl s_client, smtp-sink, Postfix | 27 | 0 | ~~S-11~~, ~~C-2~~, ~~C-4~~, ~~O-3~~, ~~O-14~~ fixed |
| RFC 4954 §4 to §6 SMTP AUTH in detail: the length of a response (RFC 4616 §2), base64, the end of an exchange, temporary failures, AUTH=<> to a smart host, the clients' initial response and challenges | 20 | 0 | ~~S-37~~ to ~~S-40~~, ~~O-19~~, ~~O-20~~, ~~C-17~~, ~~C-18~~ fixed |
| RFC 5321 §3.8 a server that shuts down, §3.1, §5.1, RFC 7504 §3 a next hop that refuses the session; RFC 3461 §4.5, RFC 1870 §6 parameters given twice | 15 | 0 | ~~S-41~~, ~~S-42~~, ~~O-21~~, ~~O-22~~ fixed |
| RFC 8689 REQUIRETLS: the MX hosts a message that requires TLS goes to, 5.7.30 and 5.7.10, its bounces, "TLS-Required: No", the submission client | 18 | 0 | ~~O-23~~ to ~~O-27~~, ~~D-14~~, ~~D-15~~, ~~C-19~~ fixed |
| RFC 8601 §2.7.2, §5 Authentication-Results; RFC 6531 §3.7.3 the Received field of an SMTPUTF8 transaction | 9 | 0 | ~~S-43~~ to ~~S-47~~ fixed |
| RFC 6531 §3.2, §3.4, §3.5 SMTPUTF8 in the submission client | 7 | 0 | ~~C-20~~, ~~C-21~~ fixed |
| RFC 3461 §4, §4.1, §4.3, §4.4 the DSN parameters the submission client and the relay give for an application | 15 | 0 | ~~C-22~~ to ~~C-24~~ fixed |
| RFC 5322 §2.2, §3.6, §3.6.4, RFC 5321 §4.4 the server's default mail store | 10 | 0 | ~~S-48~~ to ~~S-50~~ fixed |
| RFC 7489 §6.2, §6.4, RFC 8460 §3, RFC 6068 §2 the report URIs; RFC 6591 §4, RFC 5965 §3.5 the fields of the DMARC failure report | 17 | 0 | ~~R-8~~ to ~~R-12~~, ~~T-5~~, ~~T-6~~ fixed |
| RFC 2045 §7, RFC 2392 Content-ID and cid:; RFC 2387 multipart/related; RFC 2183 Content-Disposition - written and read | 15 | 0 | ~~E-17~~ to ~~E-21~~ fixed |
| RFC 5322 §3.6.5 the subject of a reply; RFC 2369 §2, §3.4 List-Post, read and written; RFC 6068 §2 its mailto URL | 18 | 0 | ~~E-22~~ to ~~E-25~~ fixed |
| RFC 2046 §4.1.4, §5.2.4 a text and a message of an unknown subtype; §5.2.1, RFC 6532 §3.7 message/rfc822 and message/global; RFC 2045 §2.7 to §2.9, §6.2 7bit, 8bit, binary | 18 | 0 | ~~E-26~~ to ~~E-29~~ fixed |
| RFC 5321 §4.5.4.1 the sending strategy: the delay before a destination that failed is tried again, the retry interval, the parameters of the retry algorithm, one copy for one domain (§2.4, RFC 5890 §2.3.2.1) | 12 | 0 | ~~O-28~~ to ~~O-31~~ fixed |
| RFC 3030 §3 BINARYMIME, RFC 6152 §3, RFC 2045 §2.7 to §2.9: binary data - a line of more than 998 octets, a NUL - from the submission client and the relay | 14 | 0 | ~~C-25~~, ~~C-26~~, ~~O-32~~, ~~O-33~~ fixed |
| **Total** | **1232** | **0** | |

## External test partners

What is wired up today, and what is worth adding next — chosen for what each
one can tell us that the others cannot.

### In use

| Tool | Direction | What it contributes |
|---|---|---|
| **swaks** | client → Hermod | the postmaster's standard probe: plain, `--pipeline`, STARTTLS, implicit TLS, AUTH PLAIN/LOGIN |
| **CPython `smtplib`** | client → Hermod | an independent client stack in the standard library: `send_message`, `starttls`, `login`, `SMTP_SSL`, `SMTPUTF8` |
| **OpenSSL `s_client -starttls smtp`** | client → Hermod | the STARTTLS reference most TLS scanners build on; TLS 1.2/1.3 accepted, 1.1 refused |
| **Postfix `smtp-sink`** | Hermod client → server | a server whose quirks are switches: `-e` (no ESMTP), `-8` (no 8BITMIME), `-Q DATA` (421 mid-transaction), message dumps |
| **Postfix `smtpd` and `smtp`** | both | a private instance per test (`postfix -c`, its own `main.cf`, queue and log): Postfix delivering to Hermod as next hop - plain, two recipients, SMTPUTF8, enforced STARTTLS - and Hermod's outbound client relaying through a strict Postfix (no bare LFs, FQDN HELO, RFC 821 envelopes) to smtp-sink, whose dump shows the DSN parameters as forwarded |

### Recommended next, by value

1. **SEC Consult `smtp-smuggling-tools`.** The scanner published with the
   smuggling research. A second, independent opinion on S-1, and a standing
   regression check for its fix.
2. **`pyspf` with the OpenSPF test suite (`rfc7208-tests.yml`).** Hundreds of
   SPF cases, each with its own DNS zone data. Hermod's `DNSVerifier` already
   takes an `IDNSClient`, so the suite's zones can be fed through
   `StubDnsClient` and every case run offline — the largest gain in coverage per
   line of glue code.
3. **`dkimpy` and `authheaders`.** `dkimsign`/`dkimverify` and
   `arcsign`/`arcverify` in both directions against Hermod's `DkimSigner`,
   `ArcSealer`, `ArcValidator` (Hermod's README reports one-off checks against
   dkimpy; this makes them a standing test), and `authheaders` as an oracle for
   the `Authentication-Results:` field Hermod writes.
4. **`testssl.sh --starttls smtp`.** Protocols, cipher order, certificate
   handling and the known TLS vulnerability checks on ports 25/587/465 — a TLS
   audit rather than a handshake test.
5. **`aiosmtpd`.** A scriptable SMTP server in Python with STARTTLS, AUTH and
   SMTPUTF8 — a second independent server for the client tests, cheap to run in
   CI next to `ScriptedSmtpServer`.

Further out: **Exim** (a second MTA family with its own reading of the
grammar), **OpenSMTPD** (a third), **GnuTLS `gnutls-cli --starttls-proto=smtp`**
(a second TLS stack next to OpenSSL), **`posttls-finger`** from Postfix
together with Hermod's DNS server from the DNS suite (DANE/TLSA end to end),
**`smtp-source`** for concurrency and the rate limiter, and **SharpFuzz** or
**boofuzz** for the parsers that Hermod's own README notes have never been
fuzzed. Capture servers like Mailpit or GreenMail add little here: they are
lenient by design.

## License

Apache 2.0, like Hermod. See [LICENSE](LICENSE).
