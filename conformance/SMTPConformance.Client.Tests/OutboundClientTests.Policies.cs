using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// The relay under a transport security policy of the next hop: MTA-STS (RFC 8461), served
/// through the HTTP handler hook, and DANE (RFC 7672), against a smart host "localhost" in a
/// zone signed for the test and trusted through the trust anchor hook.
/// </summary>
public sealed partial class OutboundClientTests
{

    #region Setup

    private static async Task<SendResult> SendWith(SMTPOutboundClient   Client,
                                                   EMailEnvelop         Envelope,
                                                   ScriptedSmtpServer?  Server   = null)
    {

        var sender = new MailSender(new CapturingMailQueue(), new CapturingLogger(), Client);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var results = await sender.SendDirectAsync(Envelope, cts.Token);

        if (Server is not null)
            await Server.WhenIdleAsync();

        return results.Single().Result;

    }

    /// <summary>
    /// The zone "localhost", signed with a key of the test's, which a DANE client trusts through
    /// SmtpOutboundConfig.DnssecTrustAnchors.
    /// </summary>
    private sealed class SignedLocalhost : IDisposable
    {

        public StubDnsClient     Dns          { get; } = new();
        public CapturingLogger   Log          { get; } = new();
        public DNSSECSigningKey  Key          { get; } = DNSSECSigningKey.Generate(DomainName.ParseLenient("localhost"), 13, KeySigningKey: true);

        public SignedLocalhost()
        {
            Dns.Answer("localhost", DNSResourceRecordTypes.DNSKEY, Signed(Key.DNSKEY));
            // RFC 7672 §2.2.2: TLSA records count for a host whose address records are signed.
            Dns.Answer("localhost", DNSResourceRecordTypes.A,      Signed(new A(DomainName.Parse("localhost"), DNSQueryClasses.IN, TimeSpan.FromHours(1),
                                                                                 org.GraphDefined.Vanaheimr.Hermod.IPv4Address.Parse("127.0.0.1"))));
        }

        public IDNSResourceRecord[] Signed(params IDNSResourceRecord[] RRSet)
            => [ .. RRSet, DNSSECZoneSigner.SignRRSet(RRSet, Key, DateTime.UtcNow.AddHours(-1), DateTime.UtcNow.AddDays(1)) ];

        /// <summary>
        /// A signed TLSA record for the next hop: usage, SubjectPublicKeyInfo, SHA-256.
        /// </summary>
        public void Tlsa(UInt16 Port, TLSA_CertificateUsage Usage, X509Certificate2 Certificate)
            => Dns.Answer($"_{Port}._tcp.localhost", DNSResourceRecordTypes.TLSA,
                          Signed(new TLSA(DomainName.ParseLenient($"_{Port}._tcp.localhost"), DNSQueryClasses.IN, TimeSpan.FromHours(1),
                                          (Byte) Usage, (Byte) TLSA_Selector.SubjectPublicKeyInfo, (Byte) TLSA_MatchingType.SHA256,
                                          SHA256.HashData(Certificate.PublicKey.ExportSubjectPublicKeyInfo()))));

        public SMTPOutboundClient ClientFor(ScriptedSmtpServer Server)

            => new (new SmtpOutboundConfig {
                        LocalHostname       = "relay.hermod.test",
                        SmartHost           = "localhost",
                        SmartHostPort       = Server.Port,
                        ConnectTimeoutMs    = 3_000,
                        ReadTimeoutMs       = 10_000,
                        WriteTimeoutMs      = 3_000,
                        EnableDane          = true,
                        DnssecTrustAnchors  = [ Key.DelegationSigner() ]
                    },
                    null,
                    Dns,
                    Log);

        public void Dispose()
            => Key.Dispose();

    }

    #endregion


    #region MTA-STS (M-5, M-6)

    [Test(Description = "RFC 8461 §5: under enforce, no MX the policy allows is no reason to fail for good - \"MTAs SHOULD treat such failures as transient errors and retry delivery later\"")]
    [Property("Finding", "M-5")]
    public async Task No_MX_the_MTA_STS_policy_allows_is_a_temporary_failure()
    {

        var dns  = new StubDnsClient();
        MtaStsPolicyHost.Announce(dns, "outbound.test", "v=STSv1; id=20261004;");
        dns.Answer("outbound.test", DNSResourceRecordTypes.MX,
                   new MX(DomainName.Parse("outbound.test"), DNSQueryClasses.IN, TimeSpan.FromHours(1), 10, DomainName.Parse("mx.elsewhere.test")));

        var client = new SMTPOutboundClient(new SmtpOutboundConfig {
                                                LocalHostname      = "relay.hermod.test",
                                                ConnectTimeoutMs   = 3_000,
                                                MtaStsHttpHandler  = new MtaStsPolicyHost("outbound.test")
                                            },
                                            null, dns, new CapturingLogger());

        var result = await SendWith(client, Envelope([ "you@outbound.test" ]));

        Assert.Multiple(() => {
            Assert.That(result.Status,        Is.EqualTo(SendStatus.TempFail), $"{result.ResponseCode} {result.ResponseText}");
            Assert.That(result.ResponseText,  Does.Contain("MTA-STS"));
        });

    }


    [Test(Description = "RFC 8461 §3.4: \"When sending mail via a 'smart host' ... compliant senders MUST treat the smart host domain as the Policy Domain\" - the recipient domain's policy is not applied to the smart host")]
    [Property("Finding", "M-6")]
    public async Task Through_a_smart_host_the_recipient_domains_policy_does_not_apply()
    {

        var script = new SmtpServerScript();
        await using var server = ScriptedSmtpServer.Start(script);

        var dns = new StubDnsClient();
        MtaStsPolicyHost.Announce(dns, "outbound.test", "v=STSv1; id=20261004;");

        var client = new SMTPOutboundClient(ConfigFor(server) with { MtaStsHttpHandler = new MtaStsPolicyHost("outbound.test") },
                                            null, dns, new CapturingLogger());

        var result = await SendWith(client, Envelope([ "you@outbound.test" ]), server);

        Assert.That(result.Status, Is.EqualTo(SendStatus.Success),
                    "outbound.test's enforce policy names its own MX hosts, not the relay" + Explain(server));

    }

    #endregion

    #region DANE (N-3, N-4)

    [Test(Description = "RFC 7672 §3.1.1: a DANE-EE(3) record authenticates the certificate, whatever its name - a guard for the signed test zone")]
    [Property("Finding", "N-3")]
    public async Task DANE_EE_authenticates_the_next_hop()
    {

        var certificate = TestCertificate.CreateServerCertificate("whatever.test");
        var script      = new SmtpServerScript { Certificate = certificate };
        await using var server = ScriptedSmtpServer.Start(script);
        using var zone  = new SignedLocalhost();
        zone.Tlsa(server.Port, TLSA_CertificateUsage.DANE_EE, certificate);

        var result = await SendWith(zone.ClientFor(server), Envelope([ "you@outbound.test" ]), server);

        Assert.Multiple(() => {
            Assert.That(result.Status,                    Is.EqualTo(SendStatus.Success), Explain(server) + "\n--- client log ---\n" + zone.Log);
            Assert.That(script.Transactions.Single().Tls, Is.True,                        Explain(server) + "\n--- client log ---\n" + zone.Log);
        });

    }


    [Test(Description = "RFC 7672 §3.2.2: \"With DANE-TA(2), the server certificate MUST contain a name that matches one of the reference identifiers\" - a certificate of the trust anchor for another name does not do")]
    [Property("Finding", "N-3")]
    public async Task DANE_TA_refuses_a_certificate_for_another_name()
    {

        var (authority, certificate) = TestCertificate.CreateIssuedCertificate("evil.test");
        var script = new SmtpServerScript { Certificate = certificate, CertificateChain = [ authority ] };
        await using var server = ScriptedSmtpServer.Start(script);
        using var zone = new SignedLocalhost();
        zone.Tlsa(server.Port, TLSA_CertificateUsage.DANE_TA, authority);

        var result = await SendWith(zone.ClientFor(server), Envelope([ "you@outbound.test" ]), server);

        Assert.Multiple(() => {
            Assert.That(result.Status,       Is.EqualTo(SendStatus.TempFail), Explain(server) + "\n--- client log ---\n" + zone.Log);
            Assert.That(script.Transactions, Is.Empty,                        "nothing is handed over" + Explain(server) + "\n--- client log ---\n" + zone.Log);
        });

    }


    [Test(Description = "RFC 7672 §3.2.2, §3.2.3: a certificate of the trust anchor for the TLSA base domain is accepted - a guard for N-3")]
    [Property("Finding", "N-3")]
    public async Task DANE_TA_accepts_a_certificate_for_the_host()
    {

        var (authority, certificate) = TestCertificate.CreateIssuedCertificate("localhost");
        var script = new SmtpServerScript { Certificate = certificate, CertificateChain = [ authority ] };
        await using var server = ScriptedSmtpServer.Start(script);
        using var zone = new SignedLocalhost();
        zone.Tlsa(server.Port, TLSA_CertificateUsage.DANE_TA, authority);

        var result = await SendWith(zone.ClientFor(server), Envelope([ "you@outbound.test" ]), server);

        Assert.That(result.Status, Is.EqualTo(SendStatus.Success), Explain(server) + "\n--- client log ---\n" + zone.Log);

    }


    [Test(Description = "RFC 7672 §3.1.2: DANE-TA authenticates against the chain the server presents - not against one the platform completes from the network, and without waiting for it")]
    [Category(TestCategories.KnownIssue), Property("Finding", "N-5")]
    public async Task DANE_TA_does_not_depend_on_certificate_downloads()
    {

        var (authority, certificate) = TestCertificate.CreateIssuedCertificate("localhost", UnreachableIssuerUrl: true);
        var script = new SmtpServerScript { Certificate = certificate, CertificateChain = [ authority ] };
        await using var server = ScriptedSmtpServer.Start(script);
        using var zone = new SignedLocalhost();
        zone.Tlsa(server.Port, TLSA_CertificateUsage.DANE_TA, authority);

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var result    = await SendWith(zone.ClientFor(server), Envelope([ "you@outbound.test" ]), server);

        Assert.Multiple(() => {
            Assert.That(result.Status,      Is.EqualTo(SendStatus.Success),          Explain(server) + "\n--- client log ---\n" + zone.Log);
            Assert.That(stopwatch.Elapsed,  Is.LessThan(TimeSpan.FromSeconds(10)),  "no waiting for http://192.0.2.1/");
        });

    }


    [Test(Description = "RFC 7672 §2.2: with a secure TLSA RRset whose records are all unusable, \"Any connection to the MTA MUST be made via TLS, but authentication is not required\"")]
    [Property("Finding", "N-4")]
    public async Task Unusable_TLSA_records_need_TLS_but_no_authentication()
    {

        var certificate = TestCertificate.CreateServerCertificate("whatever.test");
        var script      = new SmtpServerScript { Certificate = certificate };
        await using var server = ScriptedSmtpServer.Start(script);
        using var zone  = new SignedLocalhost();
        zone.Tlsa(server.Port, TLSA_CertificateUsage.PKIX_EE, certificate);

        var result = await SendWith(zone.ClientFor(server), Envelope([ "you@outbound.test" ]), server);

        Assert.Multiple(() => {
            Assert.That(result.Status,                    Is.EqualTo(SendStatus.Success), Explain(server) + "\n--- client log ---\n" + zone.Log);
            Assert.That(script.Transactions.Single().Tls, Is.True,                        Explain(server) + "\n--- client log ---\n" + zone.Log);
        });

    }


    [Test(Description = "RFC 7672 §2.2.3: with secure TLSA records, usable or not, \"The SMTP client MUST NOT deliver mail via the corresponding host unless a TLS session is negotiated via STARTTLS\" - a guard for N-4")]
    [Property("Finding", "N-4")]
    public async Task Unusable_TLSA_records_still_need_TLS()
    {

        var script = new SmtpServerScript();
        await using var server = ScriptedSmtpServer.Start(script);
        using var zone = new SignedLocalhost();
        zone.Tlsa(server.Port, TLSA_CertificateUsage.PKIX_EE, TestCertificate.CreateServerCertificate("whatever.test"));

        var result = await SendWith(zone.ClientFor(server), Envelope([ "you@outbound.test" ]), server);

        Assert.Multiple(() => {
            Assert.That(result.Status,       Is.EqualTo(SendStatus.TempFail), Explain(server) + "\n--- client log ---\n" + zone.Log);
            Assert.That(script.Transactions, Is.Empty,                        Explain(server) + "\n--- client log ---\n" + zone.Log);
        });

    }

    #endregion

}
