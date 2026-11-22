# Findings

Every finding below is pinned by at least one test that asserts what the RFC
says. Those tests carry `[Category("KnownIssue")]` and a `Finding` property with
the ID, so the merge gate stays green while they stay red. When a fix lands,
the test turns green, the nightly reports it as "now passing", and the tag
comes off — the `Finding` property stays, so the test still says which finding
it guards.

First measured against **Hermod `8af03484`** (Styx `fc2aeddb`), 2026-10-03; line numbers
refer to that revision, under `libs/Hermod/Hermod/SMTP/`. Pinned to **Hermod
`1e2e04d9`** (Styx `a6b9f9fb`), which closes every finding of the first nine rounds and
of the follow-up E-14 to E-16; the tenth round's are open. The second round (S-18 and
on, C-8 and on) comes from the observations the first one left without a test; its line
numbers refer to `96a8048d`. The third (O-1 and on, C-11) tests `SMTPOutboundClient`,
the relay side, which the first two did not test at all; its line numbers refer to
`d2d608d2`. The fourth (D-, M- and N-) tests what the relay owes beyond delivery: the
reports to the sender (DSN), MTA-STS and DANE; its line numbers refer to `306f2d59`. The
fifth (V- and P-) tests what Hermod's SMTP gained between `bbbf88b6` and `4b8be28a` -
SPF, DKIM and DMARC on inbound mail, DNS blocklists, recipient checks, the AUTH
configuration, submission to the application, outbound mail to public addresses only,
smart host credentials, DKIM signing, the file queue after a crash and the certificate
chain; its line numbers refer to `4b8be28a`. The sixth (A-, R-, T-, Q-, L-, V-3 and V-4)
tests the parts of Hermod's SMTP no round had tested: ARC (RFC 8617), the DMARC reports
(RFC 7489 §7), TLS reporting (RFC 8460), MT-PRIORITY (RFC 6710) and the connection and
recipient limits; its line numbers refer to `287d1c43`, under
`libs/Hermod/Hermod/SMTP/`. The seventh (E-, I-, K- and G-) tests what of Hermod's mail
code no round had tested, none of it changed since: MIME and the message format as
Hermod builds and reads mail (RFC 2045 to 2047, 2231, 5322), the reports that arrive
(DSN, DMARC, TLS-RPT), message disposition notifications (RFC 8098), PGP/MIME (RFC 3156)
and the Public Suffix List under DMARC; its line numbers refer to `72c2366d`. E-14 to
E-16 follow it up: what the older `EMail.Parse` makes of a Content-Type that is not
written in lower case, as the MIME reader would read it, seen while fixing the MDN
findings; their line numbers refer to `0504586f`. The eighth (V-5 and on, O-9 and on,
P-2 and P-3) tests what of SPF, DKIM and the way to the next hop the earlier rounds took
for granted: how check_host() comes to its result (RFC 7208 §4 to §6), what a DKIM
verifier checks of a signature and its key record before it hashes anything (RFC 6376
§6.1, RFC 8301), how the relay finds its MX hosts (RFC 5321 §5.1), and the DKIM keys
Hermod makes; its line numbers refer to `887a8795`. The ninth (V-18 and on, S-20 and on,
C-12 and C-13) tests when a DMARC policy is applied at all (RFC 7489 §6.6.2, §6.6.3) and
SASL in its details: SCRAM-SHA-256 on both sides (RFC 5802, RFC 7677, RFC 4422 §3) and
EXTERNAL (RFC 4422 Appendix A); its line numbers refer to `a687f198`. The tenth (S-28
and on, O-13, C-14, D-13) tests what RFC 5321 asks of a server beyond its commands, and
of a client beyond its dialogue: the trace fields and final delivery (§4.4), loop
detection (§6.3), the paths of MAIL and RCPT as the grammar of §4.1.2 has them - source
routes, quoted local parts -, HELP, EXPN and VRFY, the timeouts of the clients
(§4.5.3.2), and SMTPUTF8 in ORCPT and in bounces (RFC 6533); its line numbers refer to
`1e2e04d9`.

```powershell
dotnet test SMTPConformanceTests.slnx --filter "TestCategory=KnownIssue"
```

### Open

| ID | Severity | Area | Summary | Tests |
|---|---|---|---|---|
| [S-28](#s-28) | medium | trace | No loop detection: a message with 150 Received fields is delivered, and relayed on | 2 |
| [S-29](#s-29) | medium | trace | No Return-Path at final delivery; one the client wrote into the message is the only one the mailbox sees | 4 |
| [S-30](#s-30) | medium | trace | The EHLO argument goes into Received unchecked: a client writes the TCP-info it likes in front of the true one | 3 |
| [O-13](#o-13) | medium | outbound | The relay waits 60 seconds for the reply to the end of data, not 10 minutes: a slow next hop gets the message again | 1 |
| [S-31](#s-31) | low | paths | A source route is taken as part of the mailbox: a local recipient behind one is a relay request | 4 |
| [S-32](#s-32) | low | paths | A quoted local part with "@" or ">" in it is cut at the wrong place | 4 |
| [S-33](#s-33) | low | commands | HELP and EXPN are unknown commands (500), VRFY without an argument is 252 | 3 |
| [S-34](#s-34) | low | SMTPUTF8 | An ORCPT of the UTF-8 address type, in UTF-8, is refused | 1 |
| [C-14](#c-14) | low | client | The submission client waits 30 seconds for the reply to the end of data: a slow server gets the message twice | 1 |
| [D-13](#d-13) | low | reports | The bounce of an SMTPUTF8 message has UTF-8 in message/delivery-status and in message/rfc822 | 2 |

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
| [S-21](#s-21) | low | SCRAM | The channel binding flag "y" was refused, though Hermod offers no -PLUS | 1 | [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284) |
| [S-22](#s-22) | low | SCRAM | The c= attribute was not compared with the GS2 header | 1 | [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284) |
| [S-23](#s-23) | low | SCRAM | A requested authorization identity (a=) was ignored: alice asking to act as bob was alice | 1 | [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284) |
| [S-24](#s-24) | low | SCRAM | "=2C" and "=3D" in the user name were not decoded, and a bare "=" was not refused | 3 | [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284) |
| [S-25](#s-25) | low | SCRAM | A mandatory extension (m=) did not fail the authentication | 1 | [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284) |
| [S-26](#s-26) | low | SCRAM | Passwords were not normalized (SASLprep) before they were hashed | 1 | [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284) |
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
| [C-11](#c-11) | low | client | One refused recipient stopped the message for all | 1 | [Vanaheimr/Hermod#131](https://github.com/Vanaheimr/Hermod/pull/131) |
| [C-12](#c-12) | medium | SCRAM client | A 235 without the server-final-message was taken as success: the server never proved it knows the password | 1 | [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284) |
| [C-13](#c-13) | low | SCRAM client | The client did not normalize the password (SASLprep) | 1 | [Vanaheimr/Hermod#284](https://github.com/Vanaheimr/Hermod/pull/284) |
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
| [T-1](#t-1) | medium | TLS-RPT | Two records, a record not beginning with `v=TLSRPTv1;`, or `v=tlsrptv1` still named destinations | 3 | [Vanaheimr/Hermod#262](https://github.com/Vanaheimr/Hermod/pull/262) |
| [T-2](#t-2) | low | TLS-RPT | No policy-string in the JSON | 1 | [Vanaheimr/Hermod#262](https://github.com/Vanaheimr/Hermod/pull/262) |
| [T-3](#t-3) | medium | TLS-RPT | Under an MTA-STS policy in testing mode, a certificate that failed the policy was reported as a success | 1 | [Vanaheimr/Hermod#262](https://github.com/Vanaheimr/Hermod/pull/262) |
| [T-4](#t-4) | low | TLS-RPT | Through a smart host, the session was reported to the recipient's domain, under the smart host's policy | 1 | [Vanaheimr/Hermod#262](https://github.com/Vanaheimr/Hermod/pull/262) |
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
| [I-5](#i-5) | low | DMARC reader | A date_range outside years 1 to 9999 threw `ArgumentOutOfRangeException` | 2 | [Vanaheimr/Hermod#271](https://github.com/Vanaheimr/Hermod/pull/271) |
| [I-6](#i-6) | low | DSN | A next hop's status code with leading zeros went into the DSN as it was | 3 | [Vanaheimr/Hermod#271](https://github.com/Vanaheimr/Hermod/pull/271) |
| [I-7](#i-7) | low | TLS-RPT ingest | The preamble of the multipart was read as a report part | 1 | [Vanaheimr/Hermod#271](https://github.com/Vanaheimr/Hermod/pull/271) |
| [K-6](#k-6) | low | MDN | `Build` addressed the receipt to the first of several requesters only | 1 | [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272) |
| [K-7](#k-7) | low | MDN | `GoesElsewhere` compared the local-part without case and saw nothing to confirm without a Return-Path, with a null one, or with several requesters | 4 | [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272) |
| [K-8](#k-8) | low | MDN | `CreateReadReceipt` defaulted to automatic-action/MDN-sent-automatically | 1 | [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272) |
| [K-9](#k-9) | low | MDN | The delivering server wrote no Original-Recipient header field from ORCPT | 1 | [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272), [#274](https://github.com/Vanaheimr/Hermod/pull/274) |
| [K-10](#k-10) | low | MDN | The returned header lost all but the first of repeated fields and the white space of folded ones | 2 | [Vanaheimr/Hermod#272](https://github.com/Vanaheimr/Hermod/pull/272) |
| [G-4](#g-4) | low | PGP/MIME | A broken signature part threw out of `VerifyPgpSignature` | 2 | [Vanaheimr/Hermod#273](https://github.com/Vanaheimr/Hermod/pull/273) |
| [G-5](#g-5) | low | PGP/MIME | `PgpMime.Signed` took a signed part with trailing white space | 1 | [Vanaheimr/Hermod#273](https://github.com/Vanaheimr/Hermod/pull/273) |
| [G-6](#g-6) | low | PGP/MIME | micalg `pgp-sha3_256` instead of `pgp-sha3-256` | 2 | [Vanaheimr/Hermod#273](https://github.com/Vanaheimr/Hermod/pull/273) |

The 344 tests for these are part of the merge gate now; the observations the first
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
**Open.** **No loop detection** (`SMTPSession.cs:1195`, `ProcessReceivedMessageAsync`):
nothing counts the Received fields of a message, or looks at them at all; a message that
has been through 150 hops is delivered, and relayed on. RFC 5321 §6.3: "Simple counting of
the number of "Received:" header fields in a message has proven to be an effective,
although rarely optimal, method of detecting loops in mail systems. SMTP servers using
this technique SHOULD use a large rejection threshold, normally at least 100 Received
entries. Whatever mechanisms are used, servers MUST contain provisions for detecting and
stopping trivial loops." Two servers that forward to each other - an alias, a smart host
or an MX pointing back - pass the message back and forth until it outgrows the size limit,
a copy queued at every turn. RFC 3463 §3.5 has X.4.6, "Routing loop detected", for the
refusal. Tests: `A_message_with_150_Received_fields_is_refused`,
`A_message_with_150_Received_fields_is_not_relayed`;
`A_message_with_50_Received_fields_is_delivered_and_relayed` is the guard.

### S-29
**Open.** **No Return-Path at final delivery** (`SMTPSession.cs:1435`): the message goes
to the storage with this hop's trace fields on top and nothing above them; the envelope
sender reaches the storage as an argument only, and `FileMailStorage` writes it as
`X-Envelope-From` (`MailStorage/FileMailStorage.cs:47`). RFC 5321 §4.4: "When the delivery
SMTP server makes the "final delivery" of a message, it inserts a return-path line at the
beginning of the mail data. This use of return-path is required; mail systems MUST support
it." A Return-Path the client wrote into the message stays, and is the only one the
mailbox has: what reads it - a mail program answering with an MDN (RFC 8098 §2.1:
"Confirmation from the user MUST be obtained (or no MDN sent) if there is no Return-Path
header field"), a filter, a forwarder - takes the sender's word for where errors go. §4.4:
"exactly one return path SHOULD be present when the message is delivered", and "SMTP
servers making final delivery MAY remove Return-path header fields before adding their
own". Tests: `A_delivered_message_begins_with_the_Return_Path`,
`A_delivered_bounce_begins_with_an_empty_Return_Path`,
`A_Return_Path_in_the_message_is_not_the_one_delivered`,
`A_copy_with_an_Original_Recipient_begins_with_the_Return_Path`;
`A_relayed_message_gets_no_Return_Path` is the guard.

### S-30
**Open.** **The EHLO argument goes into Received unchecked** (`SMTPSession.cs:343`,
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

### S-31
**Open.** **A source route is taken as part of the mailbox** (`SMTPSession.cs:686`,
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

### S-32
**Open.** **A quoted local part is cut at the wrong place** (`SMTPSession.cs:686`, `:800`,
`:1731`): the path ends at the first ">", the domain begins after the first "@". RFC 5321
§4.1.2: Local-part = Dot-string / Quoted-string, and qtextSMTP: "within a quoted string,
any ASCII graphic or space is permitted without blackslash-quoting except double-quote and
the backslash itself" - "@" and ">" among them. `RCPT TO:<"alice@home"@hermod.test>` is a
recipient at `home"@hermod.test`, a relay request; in `RCPT TO:<"a>b"@hermod.test>` the
path is `"a`, and the rest is taken for a parameter: "501 5.5.4 Invalid parameter". A MAIL
with such a reverse-path likewise. Tests: `A_quoted_local_part_is_one_local_part` (an "@",
a ">"), `A_quoted_local_part_with_an_angle_bracket_is_a_reverse_path`,
`A_quoted_local_part_with_an_at_sign_is_relayed_to_its_domain`;
`A_quoted_local_part_with_a_space_is_a_local_recipient` is the guard.

### S-33
**Open.** **HELP and EXPN are unknown commands, VRFY without an argument is 252**
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

### S-34
**Open.** **An ORCPT of the UTF-8 address type, in UTF-8, is refused**
(`ESMTPParameters.cs:217` to `:220`): ORCPT has to be xtext, ASCII only, also after "MAIL
FROM:<...> SMTPUTF8". RFC 6533 §3: "An SMTP server that advertises both the SMTPUTF8
extension [RFC6531] and the DSN extension [RFC3461] MUST accept a UTF-8 address type in
the ORCPT parameter including 8-bit UTF-8 characters" - utf-8-addr-unitext. Hermod
advertises both; "RCPT TO:<jörg@hermod.test> ORCPT=utf-8;jörg@hermod.test" is 501, and a
client that does as RFC 6533 says loses the recipient. Test:
`An_ORCPT_of_the_UTF_8_address_type_in_UTF_8_is_accepted`;
`An_ORCPT_of_the_UTF_8_address_type_in_ASCII_is_accepted` - utf-8-addr-xtext, "\x{F6}" -
is the guard.

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
**Open.** **The client waits 30 seconds for the reply to the end of data**
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
**Open.** **The relay waits 60 seconds for the reply to the end of data**
(`SmtpOutboundConfig.cs:38`, `ReadTimeoutMs = 60_000`, for every reply): RFC 5321
§4.5.3.2: "the minimum per-command timeout values SHOULD be as follows" - 5 minutes for
the greeting, MAIL and RCPT, 2 for DATA, 3 for each data block, and §4.5.3.2.6, DATA
Termination: 10 minutes, "A spurious timeout at this point would be very wasteful and
would typically result in delivery of multiple copies of the message, since it has been
successfully sent and the server has accepted responsibility for delivery." A next hop
that takes 61 seconds - a content filter, a slow disk - has the message; Hermod counts a
temporary failure and sends it again at the next retry. Test:
`A_next_hop_that_takes_a_minute_for_the_end_of_data_is_waited_for`.

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
**Open.** **The bounce of an SMTPUTF8 message has UTF-8 where 7 bits are the rule**
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

## ARC

RFC 8617 as `ArcValidator` checks the chain of every unauthenticated message and the
server writes `arc=` into Authentication-Results (`ArcValidationTests`), and as
`ArcSealer` seals (`ArcSealerTests`) - Hermod's server never calls the sealer; a
forwarder built on Hermod would. The chains are sealed, and Hermod's seals validated, by
the suite's own ARC implementation (`TestArc`), which `ArcToolingTests` checks. Covered
without a finding: one and two sets pass; a changed body, a gap in the instances, an
instance twice, cv=pass at instance 1 and cv=fail fail; Hermod's first seal and a seal on
a passing chain validate, with cv=none and cv=pass, no v= in the AMS, no h= in the AS.

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
