using System.Net.Security;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;
using org.GraphDefined.Vanaheimr.Hermod.SMTP.Server;

using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

public sealed partial class OutboundClientTests
{

    #region Next hops at public addresses only

    /// <summary>
    /// Deliver to you@outbound.test, whose MX host has the given address, by a client that
    /// connects to public addresses only.
    /// </summary>
    private static async Task<SendResult> SendToMxAt(String Address, String Recipient = "you@outbound.test", String? SmartHost = null, UInt16 SmartHostPort = 25)
    {

        var dns = new StubDnsClient();
        dns.Answer("outbound.test", DNSResourceRecordTypes.MX,
                   new MX(DomainName.Parse("outbound.test"), DNSQueryClasses.IN, TimeSpan.FromHours(1), 10, DomainName.Parse("mx.outbound.test")));

        if (Address.Contains(':'))
            dns.Answer("mx.outbound.test", DNSResourceRecordTypes.AAAA,
                       new AAAA(DomainName.Parse("mx.outbound.test"), DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv6Address.Parse(Address)));
        else
            dns.Answer("mx.outbound.test", DNSResourceRecordTypes.A,
                       new A   (DomainName.Parse("mx.outbound.test"), DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse(Address)));

        var config  = new SmtpOutboundConfig {
                          LocalHostname        = "relay.hermod.test",
                          PublicAddressesOnly  = true,
                          SmartHost            = SmartHost,
                          SmartHostPort        = org.GraphDefined.Vanaheimr.Hermod.IPPort.Parse(SmartHostPort),
                          ConnectTimeoutMs     = 3_000,
                          ReadTimeoutMs        = 10_000,
                          WriteTimeoutMs       = 3_000,
                          RemoteCertificateValidator = (_, _, _, _) => true
                      };

        var sender  = new MailSender(new CapturingMailQueue(), new CapturingLogger(), new SMTPOutboundClient(config, null, dns, new CapturingLogger()));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        return (await sender.SendDirectAsync(Envelope([ Recipient ]), cts.Token)).Single().Result;

    }

    public static IEnumerable<TestCaseData> AddressesThatAreNotGlobal()
    {

        TestCaseData Case(String Address, String What)
            => new TestCaseData(Address).SetName($"Not connected to: {What} ({Address})");

        TestCaseData Finding(String Address, String What, String Id)
            => Case(Address, What).SetProperty("Finding", Id);

        yield return Case("127.0.0.1",          "the loopback");
        yield return Case("10.0.0.25",          "a private address (RFC 1918)");
        yield return Case("100.64.0.25",        "shared address space (RFC 6598)");
        yield return Case("169.254.0.25",       "an IPv4 link-local address");
        yield return Finding("192.0.2.25",      "documentation (TEST-NET-1, RFC 5737)", "P-1");
        yield return Finding("198.51.100.25",   "documentation (TEST-NET-2, RFC 5737)", "P-1");
        yield return Finding("203.0.113.25",    "documentation (TEST-NET-3, RFC 5737)", "P-1");
        yield return Case("198.18.0.25",        "benchmarking (RFC 2544)");
        yield return Case("0.0.0.0",            "\"this host on this network\"");
        yield return Case("::1",                "the IPv6 loopback");
        yield return Case("fd00::25",           "a unique local address");
        yield return Case("fe80::25",           "an IPv6 link-local address");
        yield return Case("2001:db8::25",       "IPv6 documentation (RFC 3849)");
        yield return Case("2002:7f00:1::25",    "the loopback behind the 6to4 prefix (RFC 3056 §2)");
        yield return Case("::ffff:127.0.0.1",   "the loopback as an IPv4-mapped address");
        yield return Case("64:ff9b::7f00:1",    "the loopback behind the NAT64 prefix (RFC 6052 §3.1)");

    }


    [TestCaseSource(nameof(AddressesThatAreNotGlobal))]
    [Description("RFC 6890 §2.2: special-purpose addresses that are not \"Global\" are not delivered to by a client told to keep to public addresses - the message bounces (RFC 3463 X.4.4, \"Unable to route\")")]
    public async Task An_MX_host_without_a_public_address_is_not_connected_to(String Address)
    {

        var result = await SendToMxAt(Address);

        Assert.Multiple(() => {
            Assert.That(result.Status,        Is.EqualTo(SendStatus.PermFail),  result.ResponseText);
            Assert.That(result.ResponseText,  Does.Contain("5.4.4"),            result.ResponseText);
        });

    }


    [Test(Description = "RFC 5321 §4.1.3: an address literal names the host itself - one that is not public is not connected to either")]
    public async Task An_address_literal_that_is_not_public_is_not_connected_to()
    {

        var result = await SendToMxAt("192.0.2.25", Recipient: "you@[127.0.0.1]");

        Assert.That(result.Status, Is.EqualTo(SendStatus.PermFail), result.ResponseText);

    }


    [Test(Description = "A smart host is configured, not named by a stranger, and may be on this machine: it is delivered to on the loopback, public addresses only or not (a guard)")]
    public async Task A_smart_host_on_the_loopback_is_delivered_to()
    {

        var script = new SmtpServerScript();
        await using var server = ScriptedSmtpServer.Start(script);

        var result = await SendToMxAt("127.0.0.1", SmartHost: "127.0.0.1", SmartHostPort: server.Port);
        await server.WhenIdleAsync();

        Assert.That(result.Status, Is.EqualTo(SendStatus.Success), result.ResponseText + Explain(server));

    }

    #endregion


    #region Smart host credentials

    // The certificate's chain is the operator's own - accepted - but its name is still checked.
    private static readonly Func<String, System.Security.Cryptography.X509Certificates.X509Certificate2?, System.Security.Cryptography.X509Certificates.X509Chain?, SslPolicyErrors, Boolean>
        OwnCaNameChecked = (_, _, _, errors) => (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) == SslPolicyErrors.None;

    /// <summary>
    /// Deliver through the smart host relay.test - the scripted server, at 127.0.0.1 - with
    /// credentials.
    /// </summary>
    private static async Task<SendResult> SendWithCredentials(ScriptedSmtpServer Server,
                                                              String             SmartHost                   = "relay.test",
                                                              Boolean            SmartHostAuthWithoutTls     = false,
                                                              Func<String, System.Security.Cryptography.X509Certificates.X509Certificate2?, System.Security.Cryptography.X509Certificates.X509Chain?, SslPolicyErrors, Boolean>? Validator = null)
    {

        var dns = new StubDnsClient();
        dns.Answer("relay.test", DNSResourceRecordTypes.A,
                   new A(DomainName.Parse("relay.test"), DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("127.0.0.1")));

        var config  = new SmtpOutboundConfig {
                          LocalHostname            = "relay.hermod.test",
                          SmartHost                = SmartHost,
                          SmartHostPort            = org.GraphDefined.Vanaheimr.Hermod.IPPort.Parse(Server.Port),
                          SmartHostUsername        = "relay-user",
                          SmartHostPassword        = "relay-secret",
                          SmartHostAuthWithoutTls  = SmartHostAuthWithoutTls,
                          ConnectTimeoutMs         = 3_000,
                          ReadTimeoutMs            = 10_000,
                          WriteTimeoutMs           = 3_000,
                          RemoteCertificateValidator = Validator
                      };

        var sender  = new MailSender(new CapturingMailQueue(), new CapturingLogger(), new SMTPOutboundClient(config, null, dns, new CapturingLogger()));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var result = (await sender.SendDirectAsync(Envelope([ "you@outbound.test" ]), cts.Token)).Single().Result;

        await Server.WhenIdleAsync();

        return result;

    }

    private static IReadOnlyList<(String Line, Boolean Tls)> AuthCommands(SmtpServerScript Script)
    {
        lock (Script.Commands)
            return [ .. Script.Commands.Where(command => command.Line.StartsWith("AUTH", StringComparison.OrdinalIgnoreCase)) ];
    }


    [Test(Description = "RFC 4616 §5: PLAIN \"should not be used without adequate external data security protection\" - a smart host across the network that offers no STARTTLS gets no password, even where cleartext AUTH was allowed for one on the loopback")]
    public async Task A_smart_host_without_TLS_across_the_network_gets_no_password()
    {

        var script = new SmtpServerScript { AuthMechanisms = [ "PLAIN", "LOGIN" ], AuthBeforeTls = true };
        await using var server = ScriptedSmtpServer.Start(script);

        var result = await SendWithCredentials(server, SmartHostAuthWithoutTls: true);

        Assert.Multiple(() => {
            Assert.That(AuthCommands(script),  Is.Empty,                         Explain(server));
            Assert.That(result.Status,         Is.Not.EqualTo(SendStatus.Success), "and the message waits: " + result.ResponseText);
        });

    }


    [Test(Description = "RFC 3207 §4.1, RFC 6125 §6: the password goes to the smart host that was named - not to a server whose certificate is for another name")]
    public async Task A_smart_host_whose_certificate_names_another_host_gets_no_password()
    {

        var script = new SmtpServerScript { Certificate = TestCertificate.CreateServerCertificate("other.test"), AuthMechanisms = [ "PLAIN", "LOGIN" ] };
        await using var server = ScriptedSmtpServer.Start(script);

        var result = await SendWithCredentials(server, Validator: OwnCaNameChecked);

        Assert.Multiple(() => {
            Assert.That(AuthCommands(script),  Is.Empty,                           Explain(server));
            Assert.That(result.Status,         Is.Not.EqualTo(SendStatus.Success), result.ResponseText);
        });

    }


    [Test(Description = "RFC 3207 §4.1: a certificate nobody vouches for does not authenticate the smart host - no password goes to it")]
    public async Task A_smart_host_with_an_untrusted_certificate_gets_no_password()
    {

        var script = new SmtpServerScript { Certificate = TestCertificate.CreateServerCertificate("relay.test"), AuthMechanisms = [ "PLAIN", "LOGIN" ] };
        await using var server = ScriptedSmtpServer.Start(script);

        var result = await SendWithCredentials(server);

        Assert.Multiple(() => {
            Assert.That(AuthCommands(script),  Is.Empty,                           Explain(server));
            Assert.That(result.Status,         Is.Not.EqualTo(SendStatus.Success), result.ResponseText);
        });

    }


    [Test(Description = "RFC 4954 §4: a smart host that proves its name over TLS gets the credentials - inside TLS (a guard for the tests above)")]
    public async Task A_smart_host_that_proves_its_name_gets_the_password_over_TLS()
    {

        var script = new SmtpServerScript { Certificate = TestCertificate.CreateServerCertificate("relay.test"), AuthMechanisms = [ "PLAIN", "LOGIN" ] };
        await using var server = ScriptedSmtpServer.Start(script);

        var result = await SendWithCredentials(server, Validator: OwnCaNameChecked);

        Assert.Multiple(() => {
            Assert.That(AuthCommands(script),                         Is.Not.Empty,                    Explain(server));
            Assert.That(AuthCommands(script).All(command => command.Tls), Is.True,                     Explain(server));
            Assert.That(result.Status,                                Is.EqualTo(SendStatus.Success),  result.ResponseText);
        });

    }


    [Test(Description = "A smart host on the loopback may get the password in cleartext where the operator allowed it - nothing crosses a network (a guard)")]
    public async Task A_smart_host_on_the_loopback_may_get_the_password_without_TLS()
    {

        var script = new SmtpServerScript { AuthMechanisms = [ "PLAIN", "LOGIN" ], AuthBeforeTls = true };
        await using var server = ScriptedSmtpServer.Start(script);

        var result = await SendWithCredentials(server, SmartHost: "127.0.0.1", SmartHostAuthWithoutTls: true);

        Assert.Multiple(() => {
            Assert.That(AuthCommands(script),  Is.Not.Empty,                    Explain(server));
            Assert.That(result.Status,         Is.EqualTo(SendStatus.Success),  result.ResponseText);
        });

    }

    #endregion

}
