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

**State (2026-11-22, Hermod `1e2e04d9`):** 1006 tests, 977 pass, 29 fail on 11 open
findings. A tenth round tested what RFC 5321 asks of a server beyond its commands, and of
a client beyond its dialogue - the trace fields and final delivery, loop detection, the
paths of MAIL and RCPT as the grammar has them, HELP, EXPN and VRFY, the timeouts of the
clients, SMTPUTF8 in ORCPT and in bounces - 31 tests, 10 findings, and O-14 seen on the way. The heaviest: nothing
detects a loop, a message that has been through 150 hops is delivered and relayed on
([S-28](FINDINGS.md#s-28)); a delivered message gets no Return-Path, so one the client
wrote into it is the only one the mailbox sees ([S-29](FINDINGS.md#s-29)); the EHLO
argument goes into the Received field unchecked, and a client writes the TCP-info it likes
in front of the true one ([S-30](FINDINGS.md#s-30)); the relay waits 60 seconds for the
reply to the end of data, not the 10 minutes of §4.5.3.2.6, and a slow next hop gets the
message again ([O-13](FINDINGS.md#o-13)); and the ORCPT the relay writes is no xtext, so a
recipient with a "+" is refused by a next hop that checks it - Postfix does - and the
message bounces ([O-14](FINDINGS.md#o-14)).
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
| RFC 5321 §4.4 trace fields and final delivery: Return-Path, Received; §6.3 loop detection | 12 | 9 | S-28, S-29, S-30 |
| RFC 5321 §4.1.2 paths: source routes, quoted local parts; RFC 6533 §3 the UTF-8 address type in ORCPT | 11 | 9 | S-31, S-32, S-34 |
| RFC 5321 §3.5, §4.1.1.6 to §4.1.1.8, §4.2.4, §7.3 HELP, EXPN and VRFY | 4 | 3 | S-33 |
| RFC 5321 §4.5.3.2 the timeouts of the relay and of the submission client | 2 | 2 | O-13, C-14 |
| RFC 6533 §4, RFC 6532 §3.7 the bounce of an SMTPUTF8 message | 2 | 2 | D-13 |
| RFC 3461 §4.2, §5.2.1 the ORCPT the relay writes | 4 | 3 | O-14 |
| Interop: swaks, smtplib, openssl s_client, smtp-sink, Postfix | 27 | 1 | ~~S-11~~, ~~C-2~~, ~~C-4~~, ~~O-3~~ fixed; O-14 |
| **Total** | **1006** | **29** | |

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
