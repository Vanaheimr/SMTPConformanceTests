using System.Net;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 7489 §6.6.2 and §6.6.3: when a DMARC policy is applied at all - after a temporary
/// error of SPF, with two records, a version that is not exactly "DMARC1", a record without
/// a valid p=, or a DNS error at the From domain's record. Evaluated by
/// <see cref="DNSVerifier.VerifyAsync"/>, as the server evaluates inbound mail, against the
/// test's DNS. The messages come from news@author.test (or a subdomain), unsigned unless said
/// otherwise, through a client at 192.0.2.25 that no SPF record names: DMARC fails on them
/// wherever it is applied.
/// </summary>
[TestFixture]
public sealed class DmarcPolicyTests
{

    #region Setup

    private const String Author = "author.test";

    private static TXT Txt(String Name, String Text)
        => new (DNSServiceName.Parse(Name), DNSQueryClasses.IN, TimeSpan.FromHours(1), Text);

    private static String Message(String FromDomain = Author)

        => $"From: <news@{FromDomain}>\r\n" +
           "To: <alice@hermod.test>\r\n" +
           "Subject: DMARC policy\r\n" +
           $"Message-ID: <{Guid.NewGuid():N}@{FromDomain}>\r\n" +
           "Date: Sat, 21 Nov 2026 10:00:00 +0000\r\n" +
           "\r\n" +
           "Hello.\r\n";

    /// <summary>
    /// A DNS with the given DMARC records - several at one name for several records there.
    /// </summary>
    private static StubDnsClient Dmarc(params (String Domain, String Record)[] Records)
    {

        var dns = new StubDnsClient();

        foreach (var group in Records.GroupBy(record => record.Domain))
            dns.Answer("_dmarc." + group.Key, DNSResourceRecordTypes.TXT, [ .. group.Select(record => Txt("_dmarc." + group.Key, record.Record)) ]);

        return dns;

    }

    /// <summary>
    /// The message from the given MAIL FROM, through 192.0.2.25.
    /// </summary>
    private static Task<DnsVerificationResult> Verify(StubDnsClient Dns, String Message, String MailFrom = "bounce@bounces.unrelated.test")

        => new DNSVerifier(Dns, new CapturingLogger()).
               VerifyAsync(MailFrom[(MailFrom.IndexOf('@') + 1)..], IPAddress.Parse("192.0.2.25"), MailFrom, "mx.unrelated.test", EMailMessage.Parse(Message));

    private static String Explain(DnsVerificationResult Result)
        => $"spf={Result.Spf} dkim={Result.Dkim} dmarc={Result.Dmarc} policy={Result.DmarcPolicy} " +
           $"policy domain={Result.DmarcDetail?.PolicyDomain} disposition={Result.DmarcDetail?.Disposition}";

    #endregion


    [Test(Description = "RFC 7489 §6.6.2: an unauthenticated message from a domain with p=reject fails DMARC, and the policy says reject - a guard for the tests below")]
    public async Task An_unauthenticated_message_fails_under_p_reject()
    {

        var result = await Verify(Dmarc((Author, "v=DMARC1; p=reject")), Message());

        Assert.Multiple(() => {
            Assert.That(result.Dmarc,                     Is.EqualTo(DmarcResult.Fail),           Explain(result));
            Assert.That(result.DmarcDetail?.Disposition,  Is.EqualTo(DmarcDisposition.Reject),    Explain(result));
        });

    }


    #region V-18: a temporary error of SPF

    /// <summary>
    /// SPF of author.test names mail.author.test, whose address lookup fails with SERVFAIL:
    /// "temperror" (RFC 7208 §5).
    /// </summary>
    private static StubDnsClient SpfTemporaryError(String Dmarc)
    {
        var dns = DmarcPolicyTests.Dmarc((Author, Dmarc));
        dns.Answer(Author, DNSResourceRecordTypes.TXT, Txt(Author, "v=spf1 a:mail.author.test -all"));
        dns.Fail("mail.author.test", DNSResourceRecordTypes.A);
        return dns;
    }


    [Test(Description = "RFC 7489 §6.6.2: \"If neither passes and one or both of them fail due to a temporary error, the Receiver evaluating the message is unable to conclude that the DMARC mechanism had a permanent failure; they therefore cannot apply the advertised DMARC policy\" - SPF temperror, no signature, p=reject: no reject")]
    [Property("Finding", "V-18")]
    public async Task A_temporary_error_of_SPF_does_not_apply_the_policy()
    {

        var result = await Verify(SpfTemporaryError("v=DMARC1; p=reject"), Message(), MailFrom: $"news@{Author}");

        Assume.That(result.Spf, Is.EqualTo(SPFResult.TempError), Explain(result));

        Assert.Multiple(() => {
            Assert.That(result.Dmarc,                     Is.Not.EqualTo(DmarcResult.Fail),       Explain(result));
            Assert.That(result.DmarcDetail?.Disposition,  Is.Not.EqualTo(DmarcDisposition.Reject), Explain(result));
        });

    }


    [Test(Description = "RFC 7489 §6.6.2: an aligned DKIM signature that holds passes DMARC, whatever SPF says - a guard for V-18")]
    [Property("Finding", "V-18")]
    public async Task A_temporary_error_of_SPF_beside_an_aligned_signature_passes()
    {

        using var key = new TestDkimKey(Author);

        var dns = SpfTemporaryError("v=DMARC1; p=reject");
        dns.Answer(key.RecordName, DNSResourceRecordTypes.TXT, key.Record());

        var result = await Verify(dns, key.Sign(Message()), MailFrom: $"news@{Author}");

        Assert.That(result.Dmarc, Is.EqualTo(DmarcResult.Pass), Explain(result));

    }

    #endregion

    #region V-19: a DNS error at the From domain's record

    [Test(Description = "RFC 7489 §6.6.3: the Organizational Domain is asked \"If the set is now empty\" - the From domain answered that it has no record; a lookup that failed answered nothing, and \"any indication that there is no such record\" is set apart from \"a transient DNS error\". The Organizational Domain's record is not applied in place of a record that could not be read")]
    [Property("Finding", "V-19")]
    public async Task A_DNS_error_at_the_From_domain_does_not_fall_back_to_the_organizational_domain()
    {

        var dns = Dmarc((Author, "v=DMARC1; p=none; sp=none"));
        dns.Fail("_dmarc.news." + Author, DNSResourceRecordTypes.TXT);

        var result = await Verify(dns, Message(FromDomain: "news." + Author));

        Assert.That(result.DmarcDetail?.PolicyDomain, Is.Not.EqualTo(Author), Explain(result));

    }


    [Test(Description = "RFC 7489 §6.6.3: a From domain without a record of its own falls back to the Organizational Domain's - a guard for V-19")]
    [Property("Finding", "V-19")]
    public async Task A_From_domain_without_a_record_falls_back_to_the_organizational_domain()
    {

        var result = await Verify(Dmarc((Author, "v=DMARC1; p=none; sp=reject")), Message(FromDomain: "news." + Author));

        Assert.Multiple(() => {
            Assert.That(result.DmarcDetail?.PolicyDomain,  Is.EqualTo(Author),                    Explain(result));
            Assert.That(result.DmarcDetail?.Disposition,   Is.EqualTo(DmarcDisposition.Reject),    Explain(result));
        });

    }

    #endregion

    #region V-20, V-21: which record

    public static IEnumerable<TestCaseData> RecordSets()
    {

        static TestCaseData Case(String Finding, String Name, Boolean Applied, params String[] Records)

            => new TestCaseData(Records, Applied).SetName($"DMARC record set: {Name}")
                                                 .SetProperty("Finding", Finding);

        yield return Case("V-20", "two records",                               false, "v=DMARC1; p=reject", "v=DMARC1; p=none");
        yield return Case("V-21", "v=dmarc1, not DMARC1",                      false, "v=dmarc1; p=reject");
        yield return Case("V-21", "v=DMARC1x",                                 false, "v=DMARC1x; p=reject");
        yield return Case("V-21", "white space around the = of v",             true,  "v = DMARC1; p=reject");
        yield return Case("V-21", "guard: no space after the separator",       true,  "v=DMARC1;p=reject");
        yield return Case("V-20", "guard: one record among other TXT records", true,  "site-verification=4711", "v=DMARC1; p=reject");

    }


    [TestCaseSource(nameof(RecordSets))]
    [Description("RFC 7489 §6.6.3: \"Records that do not start with a \"v=\" tag that identifies the current version of DMARC are discarded\"; \"If the remaining set contains multiple records or no records, policy discovery terminates and DMARC processing is not applied to this message\"; §6.3, v: \"It MUST have the value of \"DMARC1\". The value of this tag MUST match precisely\"; §6.4: dmarc-version = \"v\" *WSP \"=\" *WSP %x44 %x4d %x41 %x52 %x43 %x31")]
    public async Task Only_one_record_of_version_DMARC1_is_applied(String[] Records, Boolean Applied)
    {

        var result = await Verify(Dmarc([ .. Records.Select(record => (Author, record)) ]), Message());

        if (Applied)
            Assert.That(result.DmarcDetail?.Disposition, Is.EqualTo(DmarcDisposition.Reject), Explain(result));
        else
            Assert.That(result.Dmarc, Is.EqualTo(DmarcResult.None), Explain(result));

    }

    #endregion

    #region V-22: records without a valid p= or sp=

    [TestCase("v=DMARC1; sp=reject",                  Description = "no p=")]
    [TestCase("v=DMARC1; p=bogus",                    Description = "p= of no policy")]
    [TestCase("v=DMARC1; p=reject; sp=bogus",         Description = "sp= of no policy")]
    [Test(Description = "RFC 7489 §6.6.3: \"If a retrieved policy record does not contain a valid \"p\" tag, or contains an \"sp\" tag that is not valid, then: 1. if a \"rua\" tag is present and contains at least one syntactically valid reporting URI, the Mail Receiver SHOULD act as if a record containing a valid \"v\" tag and \"p=none\" was retrieved, and continue processing; 2. otherwise, the Mail Receiver applies no DMARC processing to this message\" - without rua")]
    [Property("Finding", "V-22")]
    public async Task A_record_without_a_valid_policy_and_without_rua_is_not_applied(String Record)
    {

        var result = await Verify(Dmarc((Author, Record)), Message());

        Assert.That(result.Dmarc, Is.EqualTo(DmarcResult.None), Explain(result));

    }


    [Test(Description = "RFC 7489 §6.6.3: with a valid rua, a record without a valid p= is p=none - DMARC is evaluated, nothing rejected: a guard for V-22")]
    [Property("Finding", "V-22")]
    public async Task A_record_without_a_valid_policy_but_with_rua_is_p_none()
    {

        var result = await Verify(Dmarc((Author, "v=DMARC1; p=bogus; rua=mailto:dmarc@author.test")), Message());

        Assert.Multiple(() => {
            Assert.That(result.Dmarc,                     Is.EqualTo(DmarcResult.Fail),        Explain(result));
            Assert.That(result.DmarcDetail?.Disposition,  Is.EqualTo(DmarcDisposition.None),   Explain(result));
        });

    }

    #endregion

}
