using System.Collections.Concurrent;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// What the relay reports for TLS-RPT (RFC 8460) about a session under an MTA-STS policy
/// (RFC 8461): the smart host "localhost" is the policy domain (§3.4), its policy served by
/// the test, its certificate one nobody vouches for.
/// </summary>
public sealed partial class OutboundClientTests
{

    private static async Task<(SendResult Result, IReadOnlyList<TlsRptEvent> Events, String Explanation)> SendUnderPolicy(String Mode)
    {

        var script  = new SmtpServerScript { Certificate = TestCertificate.CreateServerCertificate("localhost") };
        await using var server = ScriptedSmtpServer.Start(script);

        var dns     = new StubDnsClient();
        MtaStsPolicyHost.Announce(dns, "localhost", "v=STSv1; id=20261119;");
        var policy  = new MtaStsPolicyHost("localhost") { Policy = $"version: STSv1\r\nmode: {Mode}\r\nmx: localhost\r\nmax_age: 604800\r\n" };

        var events  = new ConcurrentQueue<TlsRptEvent>();
        var log     = new CapturingLogger();
        var client  = new SMTPOutboundClient(ConfigFor(server) with {
                                                 SmartHost                   = "localhost",
                                                 RemoteCertificateValidator  = null,
                                                 MtaStsHttpHandler           = policy
                                             },
                                             null, dns, log, events.Enqueue);

        var result  = await SendWith(client, Envelope([ "you@outbound.test" ]), server);

        return (result, [ .. events ], $"{result.Status} {result.ResponseCode} {result.ResponseText}\nevents: {String.Join(", ", events)}\n--- client log ---\n{log}");

    }


    [Test(Description = "RFC 8461 §5: under enforce, a certificate nobody vouches for fails the policy - the delivery waits, and TLS-RPT (RFC 8460 §4.3) records a failed session; a guard for the events")]
    public async Task Under_an_enforced_policy_an_untrusted_certificate_is_a_reported_failure()
    {

        var (result, events, explanation) = await SendUnderPolicy("enforce");

        Assert.Multiple(() => {
            Assert.That(result.Status,                           Is.EqualTo(SendStatus.TempFail),       explanation);
            Assert.That(events.Select(e => e.Success),           Is.EqualTo(new[] { false }),           explanation);
            Assert.That(events.Single().PolicyType,              Is.EqualTo(TlsRptPolicyType.Sts),      explanation);
        });

    }


    [Test(Description = "RFC 8460 §4.4: \"policy-domain\" is \"The Policy Domain against which the MTA-STS or DANE policy is defined\" - through a smart host its own (RFC 8461 §3.4), not the recipient's: the report goes to whose policy it was")]
    [Property("Finding", "T-4")]
    public async Task Through_a_smart_host_the_session_is_reported_to_the_smart_hosts_domain()
    {

        var (_, events, explanation) = await SendUnderPolicy("enforce");

        Assert.That(events.Single().PolicyDomain, Is.EqualTo("localhost"), explanation);

    }


    [Test(Description = "RFC 8461 §5: in testing mode the mail goes out all the same, but \"Sending MTAs that also implement the TLSRPT specification [RFC8460] send a report indicating policy application failures\" - the session is a failure in the report, not a success")]
    [Property("Finding", "T-3")]
    public async Task In_testing_mode_an_untrusted_certificate_is_reported_as_a_failure()
    {

        var (result, events, explanation) = await SendUnderPolicy("testing");

        Assert.Multiple(() => {
            Assert.That(result.Status,                  Is.EqualTo(SendStatus.Success),  "testing mode does not hold the mail back " + explanation);
            Assert.That(events.Select(e => e.Success),  Is.EqualTo(new[] { false }),     explanation);
        });

    }

}
