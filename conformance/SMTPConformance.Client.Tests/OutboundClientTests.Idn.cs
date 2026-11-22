using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

public sealed partial class OutboundClientTests
{

    #region O-17: the way to a domain in U-labels

    // RFC 6531 §3.2: "Any domain name to be looked up in the DNS MUST conform to and be processed
    // as specified for Internationalizing Domain Names in Applications (IDNA) [RFC5890]. When
    // doing lookups, the SMTPUTF8-aware SMTP client or server MUST either use a Unicode-aware DNS
    // library, or transform the internationalized domain name to A-label form".

    private static Boolean AllAscii(StubDnsClient Dns)
        => Dns.Queries.All(query => query.Name.All(c => c < 0x80));


    [Test(Description = "RFC 6531 §3.2, RFC 5321 §5.1: a recipient domain in U-labels - its MX records are those of its A-labels, and the relay goes on to their hosts")]
    [Category(TestCategories.KnownIssue), Property("Finding", "O-17")]
    public async Task The_MX_hosts_of_a_domain_in_U_labels_are_those_of_its_A_labels()
    {

        var dns = new StubDnsClient();
        dns.Answer("xn--bcher-kva.test", DNSResourceRecordTypes.MX, MxRecord("xn--bcher-kva.test", 10, "mx.xn--bcher-kva.test"));

        var result = await Route(dns, "bücher.test");

        Assert.Multiple(() => {
            Assert.That(LookedUpAddressOf(dns, "mx.xn--bcher-kva.test"), Is.True,                         $"{result.ResponseCode} {result.ResponseText}; " + Queries(dns));
            Assert.That(result.ResponseText,                              Does.Not.Contain("MX lookup"),   Queries(dns));
        });

    }


    [Test(Description = "RFC 6531 §3.2: every name the relay asks the DNS about for a domain in U-labels - MX, MTA-STS (RFC 8461 §3.1) - is in A-labels")]
    [Category(TestCategories.KnownIssue), Property("Finding", "O-17")]
    public async Task Every_DNS_query_for_a_domain_in_U_labels_is_in_A_labels()
    {

        var dns = new StubDnsClient();
        dns.Answer("xn--bcher-kva.test", DNSResourceRecordTypes.MX, MxRecord("xn--bcher-kva.test", 10, "mx.xn--bcher-kva.test"));

        await Route(dns, "bücher.test");

        Assert.Multiple(() => {
            Assert.That(AllAscii(dns), Is.True, Queries(dns));
            Assert.That(dns.Queries.Any(query => query.Name == "_mta-sts.xn--bcher-kva.test" && query.Type == DNSResourceRecordTypes.TXT), Is.True, Queries(dns));
        });

    }


    [Test(Description = "RFC 5321 §5.1: a recipient domain in A-labels - its MX hosts are found (a guard)")]
    [Property("Finding", "O-17")]
    public async Task The_MX_hosts_of_a_domain_in_A_labels_are_found()
    {

        var dns = new StubDnsClient();
        dns.Answer("xn--bcher-kva.test", DNSResourceRecordTypes.MX, MxRecord("xn--bcher-kva.test", 10, "mx.xn--bcher-kva.test"));

        await Route(dns, "xn--bcher-kva.test");

        Assert.That(LookedUpAddressOf(dns, "mx.xn--bcher-kva.test"), Is.True, Queries(dns));

    }

    #endregion

    #region O-18: the relay's name in EHLO

    [Test(Description = "RFC 6531 §3.7.1: \"the SMTPUTF8-aware SMTP client MUST send only ASCII (LDH label or A-label [RFC5890]) domains in the EHLO command\" - a relay named in U-labels says EHLO with its A-labels")]
    [Category(TestCategories.KnownIssue), Property("Finding", "O-18")]
    public async Task The_relay_says_EHLO_with_its_name_in_A_labels()
    {

        var script = new SmtpServerScript();
        await using var server = ScriptedSmtpServer.Start(script);

        var client = new SMTPOutboundClient(ConfigFor(server) with { LocalHostname = "relais.bücher.test" },
                                            null, new StubDnsClient(), new CapturingLogger());
        var sender = new MailSender(new CapturingMailQueue(), new CapturingLogger(), client);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await sender.SendDirectAsync(Envelope([ "you@outbound.test" ]), cts.Token);
        await server.WhenIdleAsync();

        var ehlo = script.Commands.Select(command => command.Line).FirstOrDefault(line => line.StartsWith("EHLO ", StringComparison.OrdinalIgnoreCase));

        Assert.That(ehlo, Is.EqualTo("EHLO relais.xn--bcher-kva.test"), Explain(server));

    }

    #endregion

}
