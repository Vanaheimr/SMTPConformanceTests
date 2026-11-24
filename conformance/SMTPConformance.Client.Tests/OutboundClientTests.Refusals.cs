using System.Net;
using System.Reflection;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

public sealed partial class OutboundClientTests
{

    #region A next hop that refuses the session (RFC 5321 §3.1, §5.1)

    // Two next hops on the loopback, 127.0.0.1 and 127.0.0.2, on one port - two hosts the relay
    // reaches on the one port it knows. Linux and Windows answer on all of 127/8.

    private static readonly IPAddress SecondLoopback = IPAddress.Parse("127.0.0.2");

    private static A Address(String Host, String Address)
        => new (DomainName.Parse(Host), DNSQueryClasses.IN, TimeSpan.FromHours(1), org.GraphDefined.Vanaheimr.Hermod.IPv4Address.Parse(Address));

    /// <summary>
    /// A relay that delivers to the MX hosts on the given port. The port of the MX hosts is
    /// internal to Hermod - 25, which no test can listen on - and set here by reflection.
    /// </summary>
    private static SMTPOutboundClient MxClient(StubDnsClient Dns, UInt16 Port)
    {

        var config = new SmtpOutboundConfig {
                         LocalHostname     = "relay.hermod.test",
                         ConnectTimeoutMs  = 3_000,
                         ReadTimeoutMs     = 10_000,
                         WriteTimeoutMs    = 3_000
                     };

        var mxPort = typeof(SmtpOutboundConfig).GetProperty("MxPort", BindingFlags.Instance | BindingFlags.NonPublic)
                         ?? throw new InvalidOperationException("SmtpOutboundConfig.MxPort is gone: the test needs another way to set the port of the MX hosts");

        mxPort.SetValue(config, org.GraphDefined.Vanaheimr.Hermod.IPPort.Parse(Port));

        return new SMTPOutboundClient(config, null, Dns, new CapturingLogger());

    }

    private static Boolean Delivered(SmtpServerScript Script)
    {
        lock (Script.Transactions)
            return Script.Transactions.Any(transaction => transaction.DataLines.Count > 0);
    }


    #region O-21: a refused session at the first MX host

    public static IEnumerable<TestCaseData> GreetingsOfTheFirstMx()
    {

        TestCaseData Case(String Greeting, String Why, Boolean Finding)
        {

            var data = new TestCaseData(Greeting).SetName($"The first MX host greets \"{Greeting}\": the second gets the message - {Why}");

            return Finding
                       ? data.SetCategory(TestCategories.KnownIssue).SetProperty("Finding", "O-21")
                       : data;

        }

        yield return Case("554 5.7.1 mx1.route.test: no SMTP service for you",  "a session refused",                     Finding: true);
        yield return Case("521 5.3.2 mx1.route.test does not accept mail",     "a host that takes no mail (RFC 7504)",  Finding: true);

        // A guard: a refusal for now goes on to the next MX host already.
        yield return Case("421 4.3.2 mx1.route.test busy, try again later",    "a refusal for now (guard)",             Finding: false);

    }


    [TestCaseSource(nameof(GreetingsOfTheFirstMx))]
    [Description("RFC 5321 §5.1: \"the SMTP client MUST be able to try (and retry) each of the relevant addresses in this list in order, until a delivery attempt succeeds\"; §3.1: a 554 greeting is a server that will \"formally reject a mail session\" - this session, from this client, at this host; RFC 7504 §3: 521 is a host that \"does not accept mail\". Neither says anything of the message, or of the other MX hosts of the domain")]
    public async Task A_session_refused_by_the_first_MX_host_goes_to_the_next(String Greeting)
    {

        var first   = new SmtpServerScript { Greeting = Greeting };
        var second  = new SmtpServerScript();

        await using var mx1 = ScriptedSmtpServer.Start(first,  IPAddress.Loopback);
        await using var mx2 = ScriptedSmtpServer.Start(second, SecondLoopback, mx1.Port);

        var dns = new StubDnsClient();
        dns.Answer("route.test",     DNSResourceRecordTypes.MX, MxRecord("route.test", 10, "mx1.route.test"),
                                                                MxRecord("route.test", 20, "mx2.route.test"));
        dns.Answer("mx1.route.test", DNSResourceRecordTypes.A,  Address("mx1.route.test", "127.0.0.1"));
        dns.Answer("mx2.route.test", DNSResourceRecordTypes.A,  Address("mx2.route.test", "127.0.0.2"));

        var result = await SendWith(MxClient(dns, mx1.Port), Envelope([ "you@route.test" ]));

        await mx1.WhenIdleAsync();
        await mx2.WhenIdleAsync();

        Assume.That(mx1.Sessions, Is.Not.Empty, "the first MX host was tried first" + Explain(mx1));

        Assert.Multiple(() => {
            Assert.That(result.Status,     Is.EqualTo(SendStatus.Success), $"{result.ResponseCode} {result.ResponseText}{Explain(mx1)}{Explain(mx2)}");
            Assert.That(Delivered(second), Is.True,                        "the second MX host has the message" + Explain(mx2));
        });

    }

    #endregion


    #region O-22: the addresses of a multihomed next hop

    public static IEnumerable<TestCaseData> GreetingsOfTheFirstAddress()
    {

        TestCaseData Case(String Greeting, String Why)
            => new TestCaseData(Greeting).SetName($"The first address of the next hop greets \"{Greeting}\": its second gets the message - {Why}")
                                         .SetCategory(TestCategories.KnownIssue)
                                         .SetProperty("Finding", "O-22");

        yield return Case("421 4.3.2 busy, try again later",   "a refusal for now");
        yield return Case("554 5.7.1 no SMTP service for you", "a session refused");

    }


    [TestCaseSource(nameof(GreetingsOfTheFirstAddress))]
    [Description("RFC 5321 §5.1: \"The destination host (perhaps taken from the preferred MX record) may be multihomed, in which case the domain name resolver will return a list of alternative IP addresses ... the SMTP sender MUST try them in the order presented\"; \"the SMTP client MUST be able to try (and retry) each of the relevant addresses in this list in order, until a delivery attempt succeeds\" - an address that answers but refuses the session is an attempt that did not succeed")]
    public async Task A_session_refused_at_one_address_of_the_next_hop_goes_to_its_next_address(String Greeting)
    {

        var first   = new SmtpServerScript { Greeting = Greeting };
        var second  = new SmtpServerScript();

        await using var address1 = ScriptedSmtpServer.Start(first,  IPAddress.Loopback);
        await using var address2 = ScriptedSmtpServer.Start(second, SecondLoopback, address1.Port);

        // The smart host is one name with two addresses: no MX lookup, one host, multihomed.
        var dns = new StubDnsClient();
        dns.Answer("smart.route.test", DNSResourceRecordTypes.A, Address("smart.route.test", "127.0.0.1"),
                                                                 Address("smart.route.test", "127.0.0.2"));

        var client = new SMTPOutboundClient(new SmtpOutboundConfig {
                                                LocalHostname     = "relay.hermod.test",
                                                SmartHost         = "smart.route.test",
                                                SmartHostPort     = org.GraphDefined.Vanaheimr.Hermod.IPPort.Parse(address1.Port),
                                                ConnectTimeoutMs  = 3_000,
                                                ReadTimeoutMs     = 10_000,
                                                WriteTimeoutMs    = 3_000
                                            },
                                            null, dns, new CapturingLogger());

        var result = await SendWith(client, Envelope([ "you@route.test" ]));

        await address1.WhenIdleAsync();
        await address2.WhenIdleAsync();

        Assume.That(address1.Sessions, Is.Not.Empty, "the first address was tried first" + Explain(address1));

        Assert.Multiple(() => {
            Assert.That(result.Status,     Is.EqualTo(SendStatus.Success), $"{result.ResponseCode} {result.ResponseText}{Explain(address1)}{Explain(address2)}");
            Assert.That(Delivered(second), Is.True,                        "the second address has the message" + Explain(address2));
        });

    }

    #endregion

    #endregion

}
