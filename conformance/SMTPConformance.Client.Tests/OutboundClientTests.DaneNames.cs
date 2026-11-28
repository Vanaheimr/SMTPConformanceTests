using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// The names DANE (RFC 7672) authenticates a next hop by: the TLSA base domain of a smart host
/// that is a CNAME (§2.2.2), the name the client sends in SNI (§8.1), and the reference
/// identifiers of a DANE-TA(2) name check after an MX lookup that was not secure (§3.2.2) - in
/// the zone "localhost", signed for the test, and an MX record of outbound.test outside it.
/// </summary>
public sealed partial class OutboundClientTests
{

    #region Setup

    /// <summary>
    /// The zone "localhost", signed with a key of the test's, whose names the tests add: hosts,
    /// aliases, TLSA records, MX records, and names proven not to exist.
    /// </summary>
    private sealed class DaneZone : IDisposable
    {

        private readonly List<IDNSResourceRecord> records = [];

        public StubDnsClient     Dns  { get; } = new();
        public CapturingLogger   Log  { get; } = new();
        public DNSSECSigningKey  Key  { get; } = DNSSECSigningKey.Generate(DomainName.ParseLenient("localhost"), 13, KeySigningKey: true);

        public DaneZone()
            => Dns.Answer("localhost", DNSResourceRecordTypes.DNSKEY, Signed(Key.DNSKEY));

        private IDNSResourceRecord[] Signed(params IDNSResourceRecord[] RRSet)
        {
            records.AddRange(RRSet);
            return [ .. RRSet, DNSSECZoneSigner.SignRRSet(RRSet, Key, DateTime.UtcNow.AddHours(-1), DateTime.UtcNow.AddDays(1)) ];
        }

        private static A Address(String Host)
            => new (DomainName.Parse(Host), DNSQueryClasses.IN, TimeSpan.FromHours(1), org.GraphDefined.Vanaheimr.Hermod.IPv4Address.Parse("127.0.0.1"));

        /// <summary>
        /// A host of the zone, its address record signed.
        /// </summary>
        public void Host(String Name)
            => Dns.Answer(Name, DNSResourceRecordTypes.A, Signed(Address(Name)));

        /// <summary>
        /// An alias of the zone: the address lookup of <paramref name="Alias"/> answers with its
        /// CNAME to <paramref name="Target"/> and the address record of the target, each signed -
        /// a "secure CNAME" (RFC 7672 §2.2.2).
        /// </summary>
        public void Alias(String Alias, String Target)
        {
            var cname   = Signed(new CNAME(DomainName.Parse(Alias), DNSQueryClasses.IN, TimeSpan.FromHours(1), DomainName.Parse(Target)));
            var address = Signed(Address(Target));
            Dns.Answer(Alias,  DNSResourceRecordTypes.A, [ .. cname, .. address ]);
            Dns.Answer(Target, DNSResourceRecordTypes.A, address);
        }

        /// <summary>
        /// A signed TLSA record for the host at the port: usage, SubjectPublicKeyInfo, SHA-256.
        /// </summary>
        public void Tlsa(String Host, Int32 Port, TLSA_CertificateUsage Usage, X509Certificate2 Certificate)
        {
            var owner = $"_{Port}._tcp.{Host}";
            Dns.Answer(owner, DNSResourceRecordTypes.TLSA,
                       Signed(new TLSA(DomainName.ParseLenient(owner), DNSQueryClasses.IN, TimeSpan.FromHours(1),
                                       (Byte) Usage, (Byte) TLSA_Selector.SubjectPublicKeyInfo, (Byte) TLSA_MatchingType.SHA256,
                                       SHA256.HashData(Certificate.PublicKey.ExportSubjectPublicKeyInfo()))));
        }

        /// <summary>
        /// A signed MX record of a domain of the zone - a "secure" MX RRset (RFC 7672 §2.2.1).
        /// </summary>
        public void Mx(String Domain, String Host)
            => Dns.Answer(Domain, DNSResourceRecordTypes.MX,
                          Signed(new MX(DomainName.Parse(Domain), DNSQueryClasses.IN, TimeSpan.FromHours(1), 10, DomainName.Parse(Host))));

        /// <summary>
        /// The TLSA records of the host at the port do not exist, and the zone proves it: NXDOMAIN,
        /// with the NSEC records of the zone as it is now (RFC 4035 §3.1.3.2). Called after the
        /// names of the zone are in.
        /// </summary>
        public void NoTlsa(String Host, Int32 Port)
        {

            var owner = $"_{Port}._tcp.{Host}";

            Dns.Fail (owner, DNSResourceRecordTypes.TLSA, DNSResponseCodes.NameError);
            Dns.Proof(owner, DNSResourceRecordTypes.TLSA,
                      [ .. DNSSECZoneSigner.Sign(records, DomainName.ParseLenient("localhost"), [ Key ]).
                               Where(record => record.Type == DNSResourceRecordTypes.NSEC ||
                                               record is RRSIG rrsig && rrsig.TypeCovered == DNSResourceRecordTypes.NSEC) ]);

        }

        public SmtpOutboundConfig Config
            => new () {
                   LocalHostname       = "relay.hermod.test",
                   ConnectTimeoutMs    = 3_000,
                   ReadTimeoutMs       = 30_000,
                   WriteTimeoutMs      = 3_000,
                   EnableDane          = true,
                   DnssecTrustAnchors  = [ Key.DelegationSigner() ]
               };

        /// <summary>
        /// A client that goes through the smart host of the given name, on the server's port.
        /// </summary>
        public SMTPOutboundClient SmartHostClient(String SmartHost, ScriptedSmtpServer Server)
            => new (Config with {
                        SmartHost      = SmartHost,
                        SmartHostPort  = org.GraphDefined.Vanaheimr.Hermod.IPPort.Parse(Server.Port)
                    },
                    null, Dns, Log);

        public void Dispose()
            => Key.Dispose();

    }

    private static String Explain(ScriptedSmtpServer Server, SmtpServerScript Script, DaneZone Zone)
        => Explain(Server) +
           $"\nSNI: {String.Join(", ", Script.ServerNames)}" +
           $"\nqueries: {String.Join(", ", Zone.Dns.Queries.Select(query => $"{query.Name} {query.Type}"))}" +
           "\n--- client log ---\n" + Zone.Log;

    private const String Alias    = "relay.localhost";
    private const String Expanded = "smtp.localhost";

    #endregion


    #region N-7: the TLSA base domain of a smart host that is a CNAME (§2.2.2, §8.1)

    [Test(Description = "RFC 7672 §2.2.2: \"Secure CNAME: The input domain is a CNAME alias, and the ultimate network address RRset is \"secure\" ... Two candidate TLSA base domains are tried: the fully CNAME-expanded initial name and, failing that, the initial name itself\" - a DANE-EE record at the expanded name of the smart host, of another certificate, refuses the next hop; the unexpanded name has none, and proves it")]
    [Property("Finding", "N-7")]
    [Category(TestCategories.KnownIssue)]
    public async Task A_TLSA_record_at_the_expanded_name_of_a_smart_host_that_is_a_CNAME_is_not_passed_over()
    {

        var script = new SmtpServerScript { Certificate = TestCertificate.CreateServerCertificate(Expanded) };
        await using var server = ScriptedSmtpServer.Start(script);
        using var zone = new DaneZone();
        zone.Alias(Alias, Expanded);
        zone.Tlsa (Expanded, server.Port, TLSA_CertificateUsage.DANE_EE, TestCertificate.CreateServerCertificate("another.test"));
        zone.NoTlsa(Alias, server.Port);

        var result = await SendWith(zone.SmartHostClient(Alias, server), Envelope([ "you@outbound.test" ]), server);

        Assert.Multiple(() => {
            Assert.That(result.Status,       Is.EqualTo(SendStatus.TempFail), "the certificate matches no TLSA record of the TLSA base domain" + Explain(server, script, zone));
            Assert.That(script.Transactions, Is.Empty,                        "nothing is handed over" + Explain(server, script, zone));
        });

    }


    [TestCase(TLSA_CertificateUsage.DANE_EE, TestName = "A DANE-EE record at the expanded name of a smart host that is a CNAME authenticates it")]
    [TestCase(TLSA_CertificateUsage.DANE_TA, TestName = "A DANE-TA record at the expanded name of a smart host that is a CNAME authenticates a certificate for the expanded name")]
    [Description("RFC 7672 §2.2.2: \"if it is possible to securely obtain the full, CNAME-expanded, DNSSEC-validated address records for the input domain, then that name is the preferred TLSA base domain\"; §3.2.2: \"the SMTP client MUST employ the TLSA base domain as the primary reference identifier\" - the TLSA records are at the expanded name, and the unexpanded one need not be asked")]
    [Property("Finding", "N-7")]
    [Category(TestCategories.KnownIssue)]
    public async Task A_smart_host_that_is_a_CNAME_is_authenticated_by_the_TLSA_records_of_its_expanded_name(TLSA_CertificateUsage Usage)
    {

        var (authority, issued) = TestCertificate.CreateIssuedCertificate(Expanded);
        var script = Usage == TLSA_CertificateUsage.DANE_TA
                         ? new SmtpServerScript { Certificate = issued, CertificateChain = [ authority ] }
                         : new SmtpServerScript { Certificate = TestCertificate.CreateServerCertificate("whatever.test") };
        await using var server = ScriptedSmtpServer.Start(script);
        using var zone = new DaneZone();
        zone.Alias(Alias, Expanded);
        zone.Tlsa (Expanded, server.Port, Usage, Usage == TLSA_CertificateUsage.DANE_TA ? authority : script.Certificate!);

        var result = await SendWith(zone.SmartHostClient(Alias, server), Envelope([ "you@outbound.test" ]), server);

        Assert.Multiple(() => {
            Assert.That(result.Status,                                Is.EqualTo(SendStatus.Success), Explain(server, script, zone));
            Assert.That(script.Transactions.Select(t => t.Tls),       Is.EqualTo(new[] { true }),     Explain(server, script, zone));
        });

    }


    [Test(Description = "RFC 7672 §8.1: \"To ensure that the server sends the right certificate chain, the SMTP client MUST send the TLS SNI extension containing the TLSA base domain\" - for a smart host that is a secure CNAME, its expanded name")]
    [Property("Finding", "N-7")]
    [Category(TestCategories.KnownIssue)]
    public async Task The_SNI_of_a_smart_host_that_is_a_CNAME_is_its_TLSA_base_domain()
    {

        var script = new SmtpServerScript { Certificate = TestCertificate.CreateServerCertificate("whatever.test") };
        await using var server = ScriptedSmtpServer.Start(script);
        using var zone = new DaneZone();
        zone.Alias(Alias, Expanded);
        zone.Tlsa (Expanded, server.Port, TLSA_CertificateUsage.DANE_EE, script.Certificate!);
        zone.NoTlsa(Alias, server.Port);

        var result = await SendWith(zone.SmartHostClient(Alias, server), Envelope([ "you@outbound.test" ]), server);

        Assert.That(script.ServerNames, Is.EqualTo(new[] { Expanded }), $"{result.Status} {result.ResponseText}" + Explain(server, script, zone));

    }


    [Test(Description = "RFC 7672 §2.2.2: \"and, failing that, the initial name itself\" - with no TLSA records at the expanded name, those of the unexpanded name apply; a guard for N-7")]
    [Property("Finding", "N-7")]
    public async Task Without_TLSA_records_at_the_expanded_name_those_of_the_smart_hosts_own_name_apply()
    {

        var script = new SmtpServerScript { Certificate = TestCertificate.CreateServerCertificate(Expanded) };
        await using var server = ScriptedSmtpServer.Start(script);
        using var zone = new DaneZone();
        zone.Alias(Alias, Expanded);
        zone.Tlsa (Alias, server.Port, TLSA_CertificateUsage.DANE_EE, TestCertificate.CreateServerCertificate("another.test"));
        zone.NoTlsa(Expanded, server.Port);

        var result = await SendWith(zone.SmartHostClient(Alias, server), Envelope([ "you@outbound.test" ]), server);

        Assert.Multiple(() => {
            Assert.That(result.Status,       Is.EqualTo(SendStatus.TempFail), "the certificate matches no TLSA record of the smart host's name" + Explain(server, script, zone));
            Assert.That(script.Transactions, Is.Empty,                        Explain(server, script, zone));
        });

    }


    [Test(Description = "RFC 7672 §8.1: the SNI is the TLSA base domain - for a smart host that is no alias, its name; a guard for N-7")]
    [Property("Finding", "N-7")]
    public async Task The_SNI_of_a_smart_host_is_its_name()
    {

        var script = new SmtpServerScript { Certificate = TestCertificate.CreateServerCertificate("whatever.test") };
        await using var server = ScriptedSmtpServer.Start(script);
        using var zone = new DaneZone();
        zone.Host(Expanded);
        zone.Tlsa(Expanded, server.Port, TLSA_CertificateUsage.DANE_EE, script.Certificate!);

        var result = await SendWith(zone.SmartHostClient(Expanded, server), Envelope([ "you@outbound.test" ]), server);

        Assert.Multiple(() => {
            Assert.That(result.Status,       Is.EqualTo(SendStatus.Success),   Explain(server, script, zone));
            Assert.That(script.ServerNames,  Is.EqualTo(new[] { Expanded }),   Explain(server, script, zone));
        });

    }


    [Test(Description = "RFC 7672 §3.1.1: DANE-EE(3) - \"The expiration date of the server certificate MUST be ignored: the validity period of the TLSA record key binding is determined by the validity interval of the TLSA record DNSSEC signature\"")]
    public async Task DANE_EE_ignores_the_expiration_date_of_the_certificate()
    {

        using var rsa   = RSA.Create(2048);
        var request     = new CertificateRequest("CN=" + Expanded, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert  = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-10), DateTimeOffset.UtcNow.AddDays(-1));
        var expired     = X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx), null);

        var script = new SmtpServerScript { Certificate = expired };
        await using var server = ScriptedSmtpServer.Start(script);
        using var zone = new DaneZone();
        zone.Host(Expanded);
        zone.Tlsa(Expanded, server.Port, TLSA_CertificateUsage.DANE_EE, expired);

        var result = await SendWith(zone.SmartHostClient(Expanded, server), Envelope([ "you@outbound.test" ]), server);

        Assert.Multiple(() => {
            Assert.That(result.Status,                            Is.EqualTo(SendStatus.Success), Explain(server, script, zone));
            Assert.That(script.Transactions.Select(t => t.Tls),   Is.EqualTo(new[] { true }),     Explain(server, script, zone));
        });

    }

    #endregion

    #region N-6: the reference identifiers after an MX lookup that was not secure (§3.2.2)

    /// <summary>
    /// A message to <paramref name="Domain"/>, whose MX host mx.localhost - in the signed zone - has
    /// a DANE-TA record of the authority of a certificate for <paramref name="CertificateFor"/>.
    /// </summary>
    private static async Task<(SendResult Result, SmtpServerScript Script, String Explanation)> SendToMx(String   Domain,
                                                                                                        String   CertificateFor,
                                                                                                        Boolean  SecureMx)
    {

        var (authority, issued) = TestCertificate.CreateIssuedCertificate(CertificateFor);
        var script = new SmtpServerScript { Certificate = issued, CertificateChain = [ authority ] };
        await using var server = ScriptedSmtpServer.Start(script);
        using var zone = new DaneZone();

        zone.Host("mx.localhost");
        zone.Tlsa("mx.localhost", server.Port, TLSA_CertificateUsage.DANE_TA, authority);

        if (SecureMx)
            zone.Mx(Domain, "mx.localhost");
        else
            zone.Dns.Answer(Domain, DNSResourceRecordTypes.MX,
                            new MX(DomainName.Parse(Domain), DNSQueryClasses.IN, TimeSpan.FromHours(1), 10, DomainName.Parse("mx.localhost")));

        var result = await SendWith(MxClient(zone.Dns, (UInt16) server.Port, zone.Config), Envelope([ $"you@{Domain}" ]), server);

        return (result, script, $"{result.Status} {result.ResponseCode} {result.ResponseText}" + Explain(server, script, zone));

    }


    [Test(Description = "RFC 7672 §3.2.2: \"When the client MTA is employing DANE TLS security despite \"insecure\" MX redirection, the MX hostname is the only reference identifier\" - an MX record of outbound.test outside any signed zone, and a certificate of the DANE-TA authority for outbound.test, not for the MX host")]
    [Property("Finding", "N-6")]
    [Category(TestCategories.KnownIssue)]
    public async Task After_an_insecure_MX_lookup_the_next_hop_domain_is_no_reference_identifier()
    {

        var (result, script, explanation) = await SendToMx("outbound.test", CertificateFor: "outbound.test", SecureMx: false);

        Assert.Multiple(() => {
            Assert.That(result.Status,       Is.EqualTo(SendStatus.TempFail), explanation);
            Assert.That(script.Transactions, Is.Empty,                        "nothing is handed over: " + explanation);
        });

    }


    [Test(Description = "RFC 7672 §3.2.2: after an insecure MX lookup the MX hostname is the reference identifier - a certificate for it is accepted; a guard for N-6")]
    [Property("Finding", "N-6")]
    public async Task After_an_insecure_MX_lookup_a_certificate_for_the_MX_host_is_accepted()
    {

        var (result, script, explanation) = await SendToMx("outbound.test", CertificateFor: "mx.localhost", SecureMx: false);

        Assert.Multiple(() => {
            Assert.That(result.Status,                            Is.EqualTo(SendStatus.Success), explanation);
            Assert.That(script.Transactions.Select(t => t.Tls),   Is.EqualTo(new[] { true }),     explanation);
        });

    }


    [Test(Description = "RFC 7672 §3.2.2: \"If the TLSA base domain was obtained indirectly via a \"secure\" MX lookup ... then the original next-hop domain used in the MX lookup MUST be included as a second reference identifier\" - a certificate for the next-hop domain is accepted; a guard for N-6")]
    [Property("Finding", "N-6")]
    public async Task After_a_secure_MX_lookup_a_certificate_for_the_next_hop_domain_is_accepted()
    {

        var (result, script, explanation) = await SendToMx("next.localhost", CertificateFor: "next.localhost", SecureMx: true);

        Assert.Multiple(() => {
            Assert.That(result.Status,                            Is.EqualTo(SendStatus.Success), explanation);
            Assert.That(script.Transactions.Select(t => t.Tls),   Is.EqualTo(new[] { true }),     explanation);
        });

    }

    #endregion

}
