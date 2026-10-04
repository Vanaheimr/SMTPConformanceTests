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

**State (2026-10-04, Hermod `d2d608d2`):** 264 tests — 244 pass, **20 are open
findings** of a third round: `SMTPOutboundClient`, the relay side, which the suite now
tests too (O-1 to O-8, against a scripted next hop and against Postfix), and partial
delivery in the submission client (C-11). A second round
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
  SMTPConformance.Server.Tests     RFC 5321 core, 2920, 1870, 3030, 6152, 6531, 2034, 3461, smuggling
  SMTPConformance.Tls.Tests        RFC 3207 STARTTLS, RFC 8314 implicit TLS, RFC 8689 REQUIRETLS
  SMTPConformance.Auth.Tests       RFC 4954, 4616, LOGIN, RFC 5802/7677 SCRAM (own oracle), RFC 6409
  SMTPConformance.Client.Tests     SMTPSubmissionClient against scripted servers
  SMTPConformance.MessageFormat.Tests  RFC 5322 App. A addresses, RFC 6376 §3.4.5 DKIM, RFC 7208 §7.4 SPF macros

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
| RFC 3207 STARTTLS, RFC 8314 implicit TLS, RFC 8689 REQUIRETLS | 22 | 0 | ~~S-8~~, ~~S-13~~, ~~S-14~~ fixed |
| RFC 4954 AUTH, RFC 4616 PLAIN, LOGIN, RFC 5802/7677 SCRAM, RFC 6409 submission, RFC 3461 relay | 22 | 0 | ~~S-5~~, ~~S-14~~, ~~S-15~~, ~~S-16~~, ~~S-17~~ fixed |
| Submission client (RFC 5321, 1870, 2920, 3030, 3207, 4954, 6152) | 31 | 1 | C-11 (~~C-1~~ to ~~C-10~~ fixed) |
| Outbound client (RFC 5321, 3461, 6152, 6531) | 20 | 17 | O-1, O-2, O-3, O-5, O-6, O-7, O-8 |
| RFC 5322 addresses, RFC 6376 DKIM canonicalization, RFC 7208 SPF macros | 35 | 0 | — |
| Interop: swaks, smtplib, openssl s_client, smtp-sink, Postfix | 26 | 2 | O-3 (~~S-11~~, ~~C-2~~, ~~C-4~~ fixed) |
| **Total** | **264** | **20** | |

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
   smuggling research. A second, independent opinion on S-1, and the regression
   check once it is fixed.
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
