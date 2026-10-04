using System.Security.Cryptography;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// Hermod's <see cref="DaneResolver"/>, which decides for each next hop whether DANE (RFC 7672)
/// applies: against a stub resolver serving a zone signed for the test, with the test's own
/// trust anchor.
/// </summary>
[TestFixture]
public sealed class DaneResolverTests
{

    #region Setup

    /// <summary>
    /// A zone signed with a key generated for the test, whose DS is the trust anchor.
    /// </summary>
    private sealed class SignedZone : IDisposable
    {

        public DNSSECSigningKey  Key           { get; }
        public DS                TrustAnchor   { get; }

        public SignedZone(String Apex, StubDnsClient Dns)
        {

            Key          = DNSSECSigningKey.Generate(DomainName.ParseLenient(Apex), 13, KeySigningKey: true);
            TrustAnchor  = Key.DelegationSigner();

            Dns.Answer(Apex, DNSResourceRecordTypes.DNSKEY, Signed(Key.DNSKEY));

        }

        /// <summary>
        /// An RRset with its RRSIG.
        /// </summary>
        public IDNSResourceRecord[] Signed(params IDNSResourceRecord[] RRSet)
            => [ .. RRSet, DNSSECZoneSigner.SignRRSet(RRSet, Key, DateTime.UtcNow.AddHours(-1), DateTime.UtcNow.AddDays(1)) ];

        public void Dispose()
            => Key.Dispose();

    }

    private const String Zone    = "dane.test";
    private const String MxHost  = "mx.dane.test";
    private const String Owner   = "_25._tcp.mx.dane.test";

    private static TLSA Tlsa(String Owner = Owner)
        => new (DomainName.ParseLenient(Owner), DNSQueryClasses.IN, TimeSpan.FromHours(1),
                (Byte) TLSA_CertificateUsage.DANE_EE, (Byte) TLSA_Selector.SubjectPublicKeyInfo, (Byte) TLSA_MatchingType.SHA256,
                SHA256.HashData(RandomNumberGenerator.GetBytes(32)));

    private static DaneResolver ResolverFor(StubDnsClient Dns, SignedZone Zone)
        => new (Dns, new CapturingLogger(), new DNSSECValidator(Dns, [ Zone.TrustAnchor ]));

    #endregion


    [Test(Description = "RFC 7672 §2.2.3: a DNSSEC-validated TLSA RRset makes DANE apply - a guard for the stub zone the other tests use")]
    [Property("Finding", "N-1")]
    public async Task A_signed_TLSA_record_is_secure()
    {

        var dns = new StubDnsClient();
        using var zone = new SignedZone(Zone, dns);
        dns.Answer(Owner, DNSResourceRecordTypes.TLSA, zone.Signed(Tlsa()));

        var result = await ResolverFor(dns, zone).ResolveTlsaAsync(MxHost);

        Assert.Multiple(() => {
            Assert.That(result.Status,    Is.EqualTo(DaneStatus.Secure), result.Detail);
            Assert.That(result.IsUsable,  Is.True,                       result.Detail);
            Assert.That(dns.DnssecOK,     Is.True,                       "the DO bit is set for DANE");
        });

    }


    public static IEnumerable<TestCaseData> FailedLookups()
    {
        yield return new TestCaseData((Action<StubDnsClient>) (dns => dns.Fail (Owner, DNSResourceRecordTypes.TLSA, DNSResponseCodes.ServerFailure))).SetName("TLSA lookup fails with SERVFAIL");
        yield return new TestCaseData((Action<StubDnsClient>) (dns => dns.Throw(Owner, DNSResourceRecordTypes.TLSA))).                                     SetName("TLSA lookup times out");
    }

    [TestCaseSource(nameof(FailedLookups))]
    [Description("RFC 7672 §2.1.2: \"If any DNS queries used to locate TLSA records fail (... timeouts, malformed replies, SERVFAIL responses, etc.), then the SMTP client MUST treat that server as unreachable and MUST NOT deliver the message via that server\"")]
    [Category(TestCategories.KnownIssue), Property("Finding", "N-1")]
    public async Task A_failed_TLSA_lookup_defers_delivery(Action<StubDnsClient> Failure)
    {

        var dns = new StubDnsClient();
        using var zone = new SignedZone(Zone, dns);
        Failure(dns);

        var result = await ResolverFor(dns, zone).ResolveTlsaAsync(MxHost);

        Assert.That(result.MustDefer, Is.True, $"{result.Status}: {result.Detail}");

    }


    [Test(Description = "RFC 7672 §2.1.1, RFC 4035 §5.4: in a signed zone, \"no TLSA records\" is only true with a validated denial of existence - an empty answer without one is what stripping the records produces, and is bogus")]
    [Category(TestCategories.KnownIssue), Property("Finding", "N-2")]
    public async Task An_empty_answer_without_proof_in_a_signed_zone_defers_delivery()
    {

        var dns = new StubDnsClient();
        using var zone = new SignedZone(Zone, dns);
        // Nothing registered for the TLSA owner: an empty NOERROR, no NSEC, no RRSIG.

        var result = await ResolverFor(dns, zone).ResolveTlsaAsync(MxHost);

        Assert.That(result.MustDefer, Is.True, $"{result.Status}: {result.Detail}");

    }


    [Test(Description = "RFC 7672 §2.2: outside any signed zone, no TLSA records means no DANE - delivery goes on with opportunistic TLS (a guard for N-2)")]
    [Property("Finding", "N-2")]
    public async Task No_TLSA_records_outside_a_signed_zone_is_no_DANE()
    {

        var dns = new StubDnsClient();
        using var zone = new SignedZone(Zone, dns);

        var result = await ResolverFor(dns, zone).ResolveTlsaAsync("mx.unsigned.test");

        Assert.Multiple(() => {
            Assert.That(result.Status,     Is.EqualTo(DaneStatus.NoRecord), result.Detail);
            Assert.That(result.MustDefer,  Is.False,                        result.Detail);
        });

    }

}
