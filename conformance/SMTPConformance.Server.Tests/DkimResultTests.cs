using System.Text;
using System.Text.RegularExpressions;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 6376 §6.1.1, §6.1.2, RFC 8601 §2.7.1: the result of a DKIM signature that neither
/// passes nor fails its verification - "temperror", for "a temporary inability to retrieve a
/// public key", and "permerror", for a signature that "could not be verified due to some error
/// that is unrecoverable" - as <see cref="DNSVerifier.VerifyDkimAsync"/> gives it, the
/// verification the server applies to inbound mail, against the test's DNS. Every signature
/// here is made by the suite's own signer.
/// </summary>
[TestFixture]
public sealed class DkimResultTests
{

    #region Setup

    private const String Author = "author.test";

    internal static String Message(String Domain, String Subject = "DKIM results")

        => $"From: <news@{Domain}>\r\n" +
           "To: <alice@hermod.test>\r\n" +
           $"Subject: {Subject}\r\n" +
           $"Message-ID: <{Guid.NewGuid():N}@{Domain}>\r\n" +
           "Date: Fri, 27 Nov 2026 10:00:00 +0000\r\n" +
           "\r\n" +
           "Hello.\r\n";

    private static async Task<(DkimResult Result, String? Details, String? Domain)> Verify(StubDnsClient Dns, String SignedMessage)
        => await new DNSVerifier(Dns, new CapturingLogger()).VerifyDkimAsync(Encoding.UTF8.GetBytes(SignedMessage));

    #endregion


    #region V-31: a DNS error at the key is a temporary error

    private static IEnumerable<TestCaseData> DnsErrorsAtTheKey()
    {

        static TestCaseData Case(String Name, Action<StubDnsClient, String> Error)
            => new TestCaseData(Error).SetName($"A DNS error at the key is a temporary error: {Name}")
                                      .SetProperty("Finding", "V-31");

        yield return Case("the lookup fails with SERVFAIL",  (dns, name) => dns.Fail (name, DNSResourceRecordTypes.TXT));
        yield return Case("the lookup times out",            (dns, name) => dns.Throw(name, DNSResourceRecordTypes.TXT));

    }

    [TestCaseSource(nameof(DnsErrorsAtTheKey))]
    [Description("RFC 6376 §6.1.2: \"If the query for the public key fails to respond, the Verifier MAY seek a later verification attempt by returning TEMPFAIL (key unavailable)\"; RFC 8601 §2.7.1, temperror: \"The message could not be verified due to some error that is likely transient in nature, such as a temporary inability to retrieve a public key\" - not \"fail\", which says the signature was verified and did not hold")]
    public async Task A_DNS_error_at_the_key_is_a_temporary_error(Action<StubDnsClient, String> Error)
    {

        using var key = new TestDkimKey(Author);

        var dns = new StubDnsClient();
        Error(dns, key.RecordName);

        var (result, details, _) = await Verify(dns, key.Sign(Message(Author)));

        Assert.That(result, Is.EqualTo(DkimResult.TempError), details);

    }


    [TestCase(DNSResponseCodes.NameError, TestName = "A key that does not exist is no temporary error: NXDOMAIN")]
    [TestCase(DNSResponseCodes.NoError,   TestName = "A key that does not exist is no temporary error: no TXT record")]
    [Description("RFC 6376 §6.1.2: \"If the query for the public key fails because the corresponding key record does not exist, the Verifier MUST immediately return PERMFAIL (no key for signature)\" - a key that is not there is no temporary error (a guard for V-31)")]
    [Property("Finding", "V-31")]
    public async Task A_key_that_does_not_exist_is_no_temporary_error(DNSResponseCodes ResponseCode)
    {

        using var key = new TestDkimKey(Author);

        var dns = new StubDnsClient();
        if (ResponseCode != DNSResponseCodes.NoError)
            dns.Fail(key.RecordName, DNSResourceRecordTypes.TXT, ResponseCode);

        var (result, details, _) = await Verify(dns, key.Sign(Message(Author)));

        Assert.That(result, Is.Not.EqualTo(DkimResult.TempError).And.Not.EqualTo(DkimResult.Pass), details);

    }

    #endregion

    #region V-32: a signature that cannot be evaluated is a permanent error

    private static IEnumerable<TestCaseData> SignaturesThatCannotBeEvaluated()
    {

        static TestCaseData Case(String Name, Func<String, String>? Tags, String? TagsBeforeKey, DNSResponseCodes? KeyLookup = null)
            => new TestCaseData(Tags, TagsBeforeKey, KeyLookup).SetName($"A signature that cannot be evaluated is a permanent error: {Name}")
                                                               .SetProperty("Finding", "V-32");

        // §6.1.1: "PERMFAIL (signature missing required tag)", "PERMFAIL (incompatible version)".
        yield return Case("no bh=, a required tag",            tags => Regex.Replace(tags, @";\s*bh=[^;]*$", ""), "v=DKIM1; k=rsa; ");
        yield return Case("v=2",                               tags => tags.Replace("v=1;", "v=2;"),               "v=DKIM1; k=rsa; ");
        // §6.1.2: "PERMFAIL (no key for signature)", "PERMFAIL (key syntax error)".
        yield return Case("no key record, NXDOMAIN",           null,                                               null, DNSResponseCodes.NameError);
        yield return Case("no key record, no TXT",             null,                                               null);
        yield return Case("a key record with a tag twice",     null,                                               "v=DKIM1; k=rsa; k=rsa; ");

    }

    [TestCaseSource(nameof(SignaturesThatCannotBeEvaluated))]
    [Description("RFC 8601 §2.7.1: \"fail: The message was signed and the signature or signatures were acceptable to the ADMD, but they failed the verification test(s)\"; \"permerror: The message could not be verified due to some error that is unrecoverable, such as a required header field being absent\" - RFC 6376 §6.1.1 and §6.1.2 end the verification of these with PERMFAIL before there is anything to verify")]
    public async Task A_signature_that_cannot_be_evaluated_is_a_permanent_error(Func<String, String>? Tags, String? TagsBeforeKey, DNSResponseCodes? KeyLookup)
    {

        using var key = new TestDkimKey(Author);

        var dns = new StubDnsClient();

        if (KeyLookup is { } code)
            dns.Fail(key.RecordName, DNSResourceRecordTypes.TXT, code);
        else if (TagsBeforeKey is not null)
            dns.Answer(key.RecordName, DNSResourceRecordTypes.TXT, key.Record(TagsBeforeKey));

        var signed = Tags is null ? key.Sign(Message(Author)) : key.Sign(Message(Author), Tags);

        var (result, details, _) = await Verify(dns, signed);

        Assert.That(result, Is.EqualTo(DkimResult.PermError), details);

    }


    private static IEnumerable<TestCaseData> SignaturesThatDoNotVerify()
    {

        static TestCaseData Case(String Name, Func<String, String> Change, String TagsBeforeKey)
            => new TestCaseData(Change, TagsBeforeKey).SetName($"A signature that does not verify fails: {Name}")
                                                      .SetProperty("Finding", "V-32");

        yield return Case("the body changed",       message => message.Replace("Hello.", "Hallo."),                "v=DKIM1; k=rsa; ");
        yield return Case("the Subject changed",    message => message.Replace("Subject: DKIM", "Subject: DKlM"),  "v=DKIM1; k=rsa; ");

    }

    [TestCaseSource(nameof(SignaturesThatDoNotVerify))]
    [Description("RFC 8601 §2.7.1: a signature that was verified and did not hold \"failed the verification test(s)\" - \"fail\" (a guard for V-32)")]
    public async Task A_signature_that_does_not_verify_fails(Func<String, String> Change, String TagsBeforeKey)
    {

        using var key = new TestDkimKey(Author);

        var dns = new StubDnsClient().Answer(key.RecordName, DNSResourceRecordTypes.TXT, key.Record(TagsBeforeKey));

        var (result, details, _) = await Verify(dns, Change(key.Sign(Message(Author))));

        Assert.That(result, Is.EqualTo(DkimResult.Fail), details);

    }


    [Test(Description = "RFC 6376 §6.1.2: \"If the \"p=\" tag is empty, the key has been revoked; the Verifier MUST treat this as a failed signature check and return PERMFAIL (key revoked)\" - \"fail\" (a guard for V-32)")]
    [Property("Finding", "V-32")]
    public async Task A_signature_of_a_revoked_key_fails()
    {

        using var key = new TestDkimKey(Author);

        var dns = new StubDnsClient().Answer(key.RecordName, DNSResourceRecordTypes.TXT,
                                             new TXT(DNSServiceName.Parse(key.RecordName), DNSQueryClasses.IN, TimeSpan.FromHours(1), "v=DKIM1; k=rsa; p="));

        var (result, details, _) = await Verify(dns, key.Sign(Message(Author)));

        Assert.That(result, Is.EqualTo(DkimResult.Fail), details);

    }

    #endregion

}


/// <summary>
/// RFC 7489 §6.6.2, RFC 8601 §2.7.1: what the server makes of a DKIM signature whose key it
/// could not retrieve, or that it could not evaluate - in the Authentication-Results field it
/// writes, and in the DMARC policy it applies.
/// </summary>
[TestFixture]
public sealed class DkimResultDeliveryTests : HermodServerTestBase
{

    #region Setup

    private void PublishDmarc(String Domain, String Record)
        => Server.Dns.Answer("_dmarc." + Domain, DNSResourceRecordTypes.TXT,
                             new TXT(DNSServiceName.Parse("_dmarc." + Domain), DNSQueryClasses.IN, TimeSpan.FromHours(1), Record));

    private void PublishSpf(String Domain, String Record)
        => Server.Dns.Answer(Domain, DNSResourceRecordTypes.TXT,
                             new TXT(DNSServiceName.Parse(Domain), DNSQueryClasses.IN, TimeSpan.FromHours(1), Record));

    /// <summary>
    /// One transaction from news@ the domain to alice, signed by the key: the reply to the end
    /// of data, this receiver's Authentication-Results field unfolded if the message was stored,
    /// and the wire transcript.
    /// </summary>
    private async Task<(SmtpReply? Final, String AuthenticationResults, String Explanation)> Deliver(String Domain, TestDkimKey Key)
    {

        var marker = Marker();

        await using var client = await Server.ConnectAndEhloAsync("mx." + Domain);

        var (mail, rcpts) = await client.EnvelopeAsync($"news@{Domain}", "alice@hermod.test");
        Assert.That(mail.Code,      Is.EqualTo(250), Explain(client));
        Assert.That(rcpts[0].Code,  Is.EqualTo(250), Explain(client));

        var (_, final) = await client.DataAsync(Key.Sign(DkimResultTests.Message(Domain, marker)));
        var stored     = final?.Code == 250 ? await Server.Storage.WaitForMarkerAsync(marker) : null;

        var match      = stored is null
                             ? Match.Empty
                             : Regex.Match(stored.Raw, @"^Authentication-Results:(?<value>[^\r\n]*(?:\r\n[ \t][^\r\n]*)*)", RegexOptions.Multiline | RegexOptions.IgnoreCase);

        return (final,
                match.Success ? Regex.Replace(match.Groups["value"].Value.Replace("\r\n", ""), @"\s+", " ").Trim() : "",
                Explain(client));

    }

    private static Boolean Says(String AuthenticationResults, String Result)
        => Regex.IsMatch(AuthenticationResults, $@"(^|[;\s]){Regex.Escape(Result)}([;\s]|$)", RegexOptions.IgnoreCase);

    #endregion


    #region V-31: a DNS error at the author's key

    private static IEnumerable<TestCaseData> DnsErrorsAtTheAuthorsKey()
    {

        static TestCaseData Case(String Name, String Label, Action<StubDnsClient, String> Error)
            => new TestCaseData(Label, Error).SetName($"A DNS error at the author's key does not apply p=reject: {Name}")
                                             .SetProperty("Finding", "V-31");

        yield return Case("the lookup fails with SERVFAIL",  "servfail",  (dns, name) => dns.Fail (name, DNSResourceRecordTypes.TXT));
        yield return Case("the lookup times out",            "timeout",   (dns, name) => dns.Throw(name, DNSResourceRecordTypes.TXT));

    }

    [TestCaseSource(nameof(DnsErrorsAtTheAuthorsKey))]
    [Description("RFC 7489 §6.6.2: \"If neither passes and one or both of them fail due to a temporary error, the Receiver evaluating the message is unable to conclude that the DMARC mechanism had a permanent failure; they therefore cannot apply the advertised DMARC policy\"; RFC 8601 §2.7.1, temperror: \"a temporary inability to retrieve a public key\" - the author's signed message, its key unreachable for a moment, is not refused under p=reject, and Authentication-Results says dkim=temperror and dmarc=temperror")]
    public async Task A_DNS_error_at_the_authors_key_does_not_apply_p_reject(String Label, Action<StubDnsClient, String> Error)
    {

        var domain = $"{Label}.key.author.test";

        PublishDmarc(domain, "v=DMARC1; p=reject");

        using var key = new TestDkimKey(domain);
        Error(Server.Dns, key.RecordName);

        var (final, results, explanation) = await Deliver(domain, key);

        Assert.That(final?.Code, Is.EqualTo(250), explanation);
        Assert.Multiple(() => {
            Assert.That(Says(results, "dkim=temperror"),  Is.True, results);
            Assert.That(Says(results, "dmarc=temperror"), Is.True, results);
        });

    }


    [Test(Description = "RFC 6376 §6.1.2: a key that does not exist is \"PERMFAIL (no key for signature)\" - with nothing else for the author, DMARC fails, and p=reject refuses the message (a guard for V-31)")]
    [Property("Finding", "V-31")]
    public async Task A_key_that_does_not_exist_applies_p_reject()
    {

        const String domain = "nxdomain.key.author.test";

        PublishDmarc(domain, "v=DMARC1; p=reject");

        using var key = new TestDkimKey(domain);
        Server.Dns.Fail(key.RecordName, DNSResourceRecordTypes.TXT, DNSResponseCodes.NameError);

        var (final, _, explanation) = await Deliver(domain, key);

        Assert.That(final?.Code, Is.EqualTo(550), explanation);

    }


    [Test(Description = "RFC 7489 §6.6.2: with SPF aligned and passing, a DNS error at the key does not keep DMARC from passing (a guard for V-31)")]
    [Property("Finding", "V-31")]
    public async Task A_DNS_error_at_the_key_with_SPF_aligned_passes_DMARC()
    {

        const String domain = "spf.key.author.test";

        PublishDmarc(domain, "v=DMARC1; p=reject");
        PublishSpf  (domain, "v=spf1 ip4:127.0.0.1 ip6:::1 -all");

        using var key = new TestDkimKey(domain);
        Server.Dns.Fail(key.RecordName, DNSResourceRecordTypes.TXT);

        var (final, results, explanation) = await Deliver(domain, key);

        Assert.That(final?.Code, Is.EqualTo(250), explanation);
        Assert.That(Says(results, "dmarc=pass"), Is.True, results);

    }

    #endregion

    #region V-32: a signature without a key

    [Test(Description = "RFC 8601 §2.7.1: \"permerror: The message could not be verified due to some error that is unrecoverable\" - a signature whose key record does not exist (RFC 6376 §6.1.2, \"PERMFAIL (no key for signature)\") is dkim=permerror in Authentication-Results, not dkim=fail")]
    [Property("Finding", "V-32")]
    public async Task A_signature_without_a_key_is_reported_as_permerror()
    {

        const String domain = "nokey.author.test";

        using var key = new TestDkimKey(domain);

        var (final, results, explanation) = await Deliver(domain, key);

        Assert.That(final?.Code, Is.EqualTo(250), explanation);
        Assert.That(Says(results, "dkim=permerror"), Is.True, results);

    }

    #endregion

}
