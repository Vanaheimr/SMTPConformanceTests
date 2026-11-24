using System.Net;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// REQUIRETLS (RFC 8689) on relay, beyond the option itself (O-4): which MX hosts a message
/// that requires TLS may go to, what follows when one does not do, what the TLS-Required header
/// field sets aside, and the reports on a message that requires TLS.
/// </summary>
public sealed partial class OutboundClientTests
{

    #region Setup

    private static readonly String[] DefaultExtensions = [ "PIPELINING", "SIZE 10485760", "8BITMIME", "ENHANCEDSTATUSCODES", "SMTPUTF8", "DSN" ];

    /// <summary>
    /// A next hop with a certificate - trusted by the relays of these tests, as an operator's own
    /// CA would be - which offers REQUIRETLS inside TLS, or not.
    /// </summary>
    private static SmtpServerScript TlsNextHop(Boolean RequireTls = true, Func<String, String>? RcptReply = null)

        => new () {
               Certificate  = TestCertificate.CreateServerCertificate(),
               Extensions   = RequireTls ? [ .. DefaultExtensions, "REQUIRETLS" ] : DefaultExtensions,
               RcptReply    = RcptReply ?? (_ => "250 2.1.5 Ok")
           };

    /// <summary>
    /// A relay to the MX hosts of route.test that trusts the scripted certificates - and asks
    /// route.test for its MTA-STS policy when one is given.
    /// </summary>
    private static SMTPOutboundClient RouteTestClient(StubDnsClient Dns, UInt16 Port, Boolean MtaSts)
    {

        if (MtaSts)
            MtaStsPolicyHost.Announce(Dns, "route.test", "v=STSv1; id=20261124;");

        return MxClient(Dns, Port, new SmtpOutboundConfig {
                                       LocalHostname               = "relay.hermod.test",
                                       ConnectTimeoutMs            = 3_000,
                                       ReadTimeoutMs               = 10_000,
                                       WriteTimeoutMs              = 3_000,
                                       RemoteCertificateValidator  = (_, _, _, _) => true,
                                       // The enforce policy names mail.route.test and *.mx.route.test.
                                       MtaStsHttpHandler           = MtaSts ? new MtaStsPolicyHost("route.test") : null
                                   });

    }

    /// <summary>
    /// A message with "TLS-Required: No" (RFC 8689 §3) in its header.
    /// </summary>
    private static EMailEnvelop TlsOptional(String To, Boolean RequireTls = false)

        => new (EMail.Parse([
                    "From: app@client.example",
                    "To: " + To,
                    "Subject: a report on a misconfigured mail server",
                    "TLS-Required: No",
                    "Content-Type: text/plain; charset=utf-8",
                    "",
                    "Your certificate expired yesterday."
                ])) { RequireTls = RequireTls };

    /// <summary>
    /// The queued message as the server tags one it received with the REQUIRETLS option on MAIL
    /// (RFC 8689 §4.1) - inside TLS, which the server of these relay runs does not speak.
    /// </summary>
    private static void TaggedRequireTls(QueuedMail Mail)

        => (typeof(QueuedMail).GetProperty(nameof(QueuedMail.RequireTls))
                ?? throw new InvalidOperationException("QueuedMail.RequireTls is gone")).
               SetValue(Mail, true);

    private static String Wire(params ScriptedSmtpServer[] Servers)
        => String.Concat(Servers.Select(Explain));

    #endregion


    #region O-23: an MX host that neither DNSSEC nor MTA-STS vouches for

    [Test(Description = "RFC 8689 §4.2.1: \"If the server lookup is accomplished via the recipient domain's MX record (the usual case) and is not accompanied by a valid DNSSEC signature, the client MUST also validate the SMTP server name using MTA-STS\"; \"If there are no more MX hosts, the client MUST NOT transmit the message to the domain\" - an MX record that may be forged does not get a message that requires TLS, whatever certificate its host has")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "O-23")]
    public async Task A_REQUIRETLS_message_goes_to_no_MX_host_that_neither_DNSSEC_nor_MTA_STS_vouches_for()
    {

        var script = TlsNextHop();
        await using var mx = ScriptedSmtpServer.Start(script, IPAddress.Loopback);

        var dns = new StubDnsClient();
        dns.Answer("route.test",      DNSResourceRecordTypes.MX, MxRecord("route.test", 10, "mail.route.test"));
        dns.Answer("mail.route.test", DNSResourceRecordTypes.A,  Address("mail.route.test", "127.0.0.1"));

        var result = await SendWith(RouteTestClient(dns, mx.Port, MtaSts: false), Envelope([ "you@route.test" ], RequireTls: true), mx);

        Assert.Multiple(() => {
            Assert.That(result.Status,       Is.Not.EqualTo(SendStatus.Success), $"{result.ResponseCode} {result.ResponseText}{Wire(mx)}");
            Assert.That(script.Transactions, Is.Empty, "no MAIL: an unsigned MX record without an MTA-STS policy is no path for REQUIRETLS" + Wire(mx));
        });

    }


    [Test(Description = "RFC 8689 §4.2.1: an MX host the domain's MTA-STS policy names (RFC 8461 §4.1) gets a message that requires TLS - a guard")]
    [Property("Finding", "O-23")]
    public async Task A_REQUIRETLS_message_goes_to_an_MX_host_its_MTA_STS_policy_names()
    {

        var script = TlsNextHop();
        await using var mx = ScriptedSmtpServer.Start(script, IPAddress.Loopback);

        var dns = new StubDnsClient();
        dns.Answer("route.test",      DNSResourceRecordTypes.MX, MxRecord("route.test", 10, "mail.route.test"));
        dns.Answer("mail.route.test", DNSResourceRecordTypes.A,  Address("mail.route.test", "127.0.0.1"));

        var result = await SendWith(RouteTestClient(dns, mx.Port, MtaSts: true), Envelope([ "you@route.test" ], RequireTls: true), mx);

        Assert.Multiple(() => {
            Assert.That(result.Status,     Is.EqualTo(SendStatus.Success), $"{result.ResponseCode} {result.ResponseText}{Wire(mx)}");
            Assert.That(Delivered(script), Is.True,                        Wire(mx));
            Assert.That(script.Transactions.FirstOrDefault()?.MailFromLine, Does.Contain(" REQUIRETLS"), Wire(mx));
        });

    }

    #endregion


    #region O-24: the next MX host after one that cannot take the message on TLS

    public static IEnumerable<TestCaseData> FirstMxHostsWithoutRequireTls()
    {

        TestCaseData Case(String Name, Func<SmtpServerScript> First, Boolean Finding)
        {

            var data = new TestCaseData(First).SetName($"A REQUIRETLS message, the first MX host {Name}: the second gets it");

            return Finding
                       ? data.SetCategory(TestCategories.KnownIssue).SetProperty("Finding", "O-24")
                       : data;

        }

        yield return Case("offers no REQUIRETLS",         () => TlsNextHop(RequireTls: false),                                             Finding: true);

        // Guards: a failure for now goes on to the next MX host already.
        yield return Case("offers no STARTTLS (guard)",   () => new SmtpServerScript(),                                                    Finding: false);
        yield return Case("refuses STARTTLS (guard)",     () => new SmtpServerScript { Certificate   = TestCertificate.CreateServerCertificate(),
                                                                                       StartTlsReply = "454 4.7.0 TLS not available due to temporary reason" },
                                                                                                                                           Finding: false);

    }


    [TestCaseSource(nameof(FirstMxHostsWithoutRequireTls))]
    [Description("RFC 8689 §4.2.1: \"If any of the above steps fail, the client MUST issue a QUIT to the server and repeat steps 2-5 with each host on the recipient domain's list of MX hosts in an attempt to find a mail path that meets the sender's requirements\" - one MX host without REQUIRETLS is not the domain's answer")]
    public async Task A_REQUIRETLS_message_goes_on_to_the_next_MX_host(Func<SmtpServerScript> First)
    {

        var first   = First();
        var second  = TlsNextHop();

        await using var mx1 = ScriptedSmtpServer.Start(first,  IPAddress.Loopback);
        await using var mx2 = ScriptedSmtpServer.Start(second, SecondLoopback, mx1.Port);

        var dns = new StubDnsClient();
        dns.Answer("route.test",      DNSResourceRecordTypes.MX, MxRecord("route.test", 10, "a.mx.route.test"),
                                                                 MxRecord("route.test", 20, "b.mx.route.test"));
        dns.Answer("a.mx.route.test", DNSResourceRecordTypes.A,  Address("a.mx.route.test", "127.0.0.1"));
        dns.Answer("b.mx.route.test", DNSResourceRecordTypes.A,  Address("b.mx.route.test", "127.0.0.2"));

        var result = await SendWith(RouteTestClient(dns, mx1.Port, MtaSts: true), Envelope([ "you@route.test" ], RequireTls: true));

        await mx1.WhenIdleAsync();
        await mx2.WhenIdleAsync();

        Assume.That(mx1.Sessions, Is.Not.Empty, "the first MX host was tried first" + Wire(mx1));

        Assert.Multiple(() => {
            Assert.That(result.Status,     Is.EqualTo(SendStatus.Success), $"{result.ResponseCode} {result.ResponseText}{Wire(mx1, mx2)}");
            Assert.That(Delivered(first),  Is.False,                       "nothing for the first MX host" + Wire(mx1));
            Assert.That(Delivered(second), Is.True,                        "the second MX host has the message" + Wire(mx2));
        });

    }

    #endregion


    #region O-25: no TLS for a message that requires it - a non-delivery, 5.7.10

    public static IEnumerable<TestCaseData> NextHopsWithoutTls()
    {

        TestCaseData Case(String Name, Func<SmtpServerScript> Script, Boolean TrustCertificate)
            => new TestCaseData(Script, TrustCertificate).SetName($"A REQUIRETLS message, a next hop {Name}: 5.7.10, a non-delivery")
                                                         .SetCategory(TestCategories.KnownIssue)
                                                         .SetProperty("Finding", "O-25");

        yield return Case("that offers no STARTTLS",                  () => new SmtpServerScript(),                                                   TrustCertificate: true);
        yield return Case("whose certificate the relay does not trust", () => new SmtpServerScript { Certificate = TestCertificate.CreateServerCertificate() }, TrustCertificate: false);

    }


    [TestCaseSource(nameof(NextHopsWithoutTls))]
    [Description("RFC 8689 §4.2.1: \"If there are no more MX hosts, the client MUST NOT transmit the message to the domain. Following such a failure, the SMTP client MUST send a non-delivery notification to the reverse-path of the failed message ... Unable to establish TLS-protected SMTP session: 5.7.10 Encryption needed\" - not a failure for now, tried again for days")]
    public async Task No_TLS_for_a_REQUIRETLS_message_is_a_non_delivery(Func<SmtpServerScript> Script, Boolean TrustCertificate)
    {

        var script = Script();
        await using var server = ScriptedSmtpServer.Start(script);

        var client = new SMTPOutboundClient(ConfigFor(server) with { RemoteCertificateValidator = (_, _, _, _) => TrustCertificate },
                                            null, new StubDnsClient(), new CapturingLogger());

        var result = await SendWith(client, Envelope([ "you@outbound.test" ], RequireTls: true), server);

        Assert.Multiple(() => {
            Assert.That(script.Transactions, Is.Empty,                         "no MAIL without TLS" + Explain(server));
            Assert.That(result.Status,       Is.EqualTo(SendStatus.PermFail),  $"{result.ResponseCode} {result.ResponseText}{Explain(server)}");
            Assert.That(result.ResponseText, Does.StartWith("5.7.10 "),        $"{result.ResponseCode} {result.ResponseText}");
        });

    }

    #endregion


    #region O-26: a bounce that carries REQUIRETLS

    [Test(Description = "RFC 8689 §4.2.1 holds for a message \"for which the MAIL FROM return-path is not empty (an empty MAIL FROM return-path indicating a bounce message)\"; §5: \"When the MAIL FROM return-path is empty, the REQUIRETLS parameter SHOULD NOT cause a bounce message to be discarded even if the next-hop relay does not advertise REQUIRETLS\"")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "O-26")]
    public async Task A_bounce_with_REQUIRETLS_goes_to_a_next_hop_without_REQUIRETLS()
    {

        var script = TlsNextHop(RequireTls: false);
        await using var nextHop = ScriptedSmtpServer.Start(script);

        var run = await RelayThroughHermod(nextHop, "MAIL FROM:<>", [ "RCPT TO:<app@outbound.test>" ],
                                           [ "Your message could not be delivered." ],
                                           BeforeDelivery: TaggedRequireTls);

        Assert.Multiple(() => {
            Assert.That(Delivered(script),   Is.True,                         "the bounce is delivered, not discarded" + run.Explain(nextHop));
            Assert.That(run.Relayed.Status,  Is.EqualTo(QueueItemStatus.Delivered), run.Explain(nextHop));
        });

    }

    #endregion


    #region O-27: "TLS-Required: No"

    /// <summary>
    /// A message to route.test, whose MTA-STS policy is enforce, through the MX host given.
    /// </summary>
    private static async Task<(SendResult Result, SmtpServerScript Script, ScriptedSmtpServer Server)> UnderEnforcePolicy(String        MxHost,
                                                                                                                       Boolean       Tls,
                                                                                                                       EMailEnvelop  Envelope)
    {

        var script = Tls ? TlsNextHop(RequireTls: false) : new SmtpServerScript();
        var server = ScriptedSmtpServer.Start(script, IPAddress.Loopback);

        var dns = new StubDnsClient();
        dns.Answer("route.test", DNSResourceRecordTypes.MX, MxRecord("route.test", 10, MxHost));
        dns.Answer(MxHost,       DNSResourceRecordTypes.A,  Address(MxHost, "127.0.0.1"));

        var result = await SendWith(RouteTestClient(dns, server.Port, MtaSts: true), Envelope, server);

        return (result, script, server);

    }

    public static IEnumerable<TestCaseData> PolicyFailures(Boolean TlsRequiredNo)
    {

        var what = TlsRequiredNo ? "\"TLS-Required: No\" sets the MTA-STS policy aside" : "without \"TLS-Required: No\" the MTA-STS policy holds";

        yield return new TestCaseData("mail.route.test", false).SetName($"An MX host that offers no STARTTLS: {what}");
        yield return new TestCaseData("smtp.route.test", true ).SetName($"An MX host the MTA-STS policy does not name: {what}");

    }


    [TestCaseSource(nameof(PolicyFailures), new Object[] { true })]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "O-27")]
    [Description("RFC 8689 §3: \"No - The SMTP client SHOULD attempt to send the message regardless of its ability to negotiate STARTTLS with the SMTP server, ignoring policy-based mechanisms (including MTA-STS and DANE), if any, asserted by the recipient domain\"; §4.1: a server \"MUST tag that message with the option specified in the TLS-Required header field\" - a report on a broken TLS setup reaches the domain whose TLS is broken")]
    public async Task A_message_with_TLS_Required_No_sets_the_MTA_STS_policy_aside(String MxHost, Boolean Tls)
    {

        var (result, script, server) = await UnderEnforcePolicy(MxHost, Tls, TlsOptional("you@route.test"));
        await using var _ = server;

        Assert.Multiple(() => {
            Assert.That(result.Status,     Is.EqualTo(SendStatus.Success), $"{result.ResponseCode} {result.ResponseText}{Explain(server)}");
            Assert.That(Delivered(script), Is.True,                        Explain(server));
        });

    }


    [TestCaseSource(nameof(PolicyFailures), new Object[] { false })]
    [Description("RFC 8461 §5: without \"TLS-Required: No\" the enforce policy holds - a guard")]
    public async Task A_message_without_TLS_Required_keeps_to_the_MTA_STS_policy(String MxHost, Boolean Tls)
    {

        var (result, script, server) = await UnderEnforcePolicy(MxHost, Tls, Envelope([ "you@route.test" ]));
        await using var _ = server;

        Assert.Multiple(() => {
            Assert.That(result.Status,     Is.Not.EqualTo(SendStatus.Success), $"{result.ResponseCode} {result.ResponseText}{Explain(server)}");
            Assert.That(Delivered(script), Is.False,                           Explain(server));
        });

    }


    [Test(Description = "RFC 8689 §4.1: \"If the REQUIRETLS MAIL FROM parameter is specified, the TLS-Required header field MUST be ignored\" - REQUIRETLS wins: no next hop without it, 5.7.30 - a guard")]
    [Property("Finding", "O-27")]
    public async Task With_REQUIRETLS_the_TLS_Required_field_is_ignored()
    {

        var script = TlsNextHop(RequireTls: false);
        await using var server = ScriptedSmtpServer.Start(script);

        var result = await SendDirect(server, TlsOptional("you@outbound.test", RequireTls: true));

        Assert.Multiple(() => {
            Assert.That(Delivered(script),   Is.False,                         Explain(server));
            Assert.That(result.ResponseText, Does.StartWith("5.7.30 "),        $"{result.ResponseCode} {result.ResponseText}{Explain(server)}");
        });

    }

    #endregion


    #region D-14, D-15: the bounce of a message that requires TLS

    public static IEnumerable<TestCaseData> RetOfARequireTlsMessage()
    {
        yield return new TestCaseData("MAIL FROM:<app@client.example> RET=FULL").SetName("The bounce of a REQUIRETLS message returns its header only: with RET=FULL");
        yield return new TestCaseData("MAIL FROM:<app@client.example>"         ).SetName("The bounce of a REQUIRETLS message returns its header only: without RET");
    }


    [TestCaseSource(nameof(RetOfARequireTlsMessage))]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "D-14")]
    [Description("RFC 8689 §5: \"If a REQUIRETLS message is bounced, the server MUST behave as if RET=HDRS was present, as described in [RFC3461]. If both RET=FULL and REQUIRETLS are present, the RET=FULL MUST be disregarded\" - the body of a message that was to travel on TLS only does not go back in a bounce")]
    public async Task The_bounce_of_a_REQUIRETLS_message_returns_its_header_only(String MailFrom)
    {

        await using var nextHop = ScriptedSmtpServer.Start(TlsNextHop(RcptReply: _ => "550 5.1.1 No such user"));

        var run    = await RelayThroughHermod(nextHop, MailFrom, [ "RCPT TO:<gone@outbound.test>" ],
                                              [ "The body of this REQUIRETLS message stays home." ],
                                              BeforeDelivery: TaggedRequireTls);
        var bounce = run.ReportsFor("gone@outbound.test").FirstOrDefault()?.MessageContent;

        Assume.That(bounce, Is.Not.Null, "a bounce" + run.Explain(nextHop));

        Assert.Multiple(() => {
            Assert.That(bounce, Does.Not.Contain("stays home"),                    run.Explain(nextHop));
            Assert.That(bounce, Does.Contain("Content-Type: text/rfc822-headers"), "RFC 6522 §4" + run.Explain(nextHop));
        });

    }


    [Test(Description = "RFC 8689 §5: non-delivery messages \"MUST be protected in the same manner as the original message. All non-delivery messages resulting from messages with the REQUIRETLS SMTP option, whether resulting from a REQUIRETLS error or some other issue, MUST also specify the REQUIRETLS SMTP option\"")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "D-15")]
    public async Task The_bounce_of_a_REQUIRETLS_message_requires_TLS()
    {

        await using var nextHop = ScriptedSmtpServer.Start(TlsNextHop(RcptReply: _ => "550 5.1.1 No such user"));

        var run    = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example>", [ "RCPT TO:<gone@outbound.test>" ],
                                              BeforeDelivery: TaggedRequireTls);
        var bounce = run.ReportsFor("gone@outbound.test").FirstOrDefault();

        Assume.That(bounce, Is.Not.Null, "a bounce" + run.Explain(nextHop));

        Assert.That(bounce!.RequireTls, Is.True, "the bounce is queued to be sent with REQUIRETLS" + run.Explain(nextHop));

    }

    #endregion

}
