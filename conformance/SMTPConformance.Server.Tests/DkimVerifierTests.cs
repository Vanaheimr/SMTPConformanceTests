using System.Net;
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 6376 §6.1.1 and §6.1.2, RFC 8301 §3.2: what a verifier checks of a signature before it
/// hashes anything, and of the key record it finds - the tags a signature must have, the
/// From field it must sign, the i= it may name, the key size, and the tags of the key record.
/// Every signature here is a valid signature over what it says, made by the suite's own
/// signer; what is wrong is what it says. Verified by <see cref="DNSVerifier.VerifyDkimAsync"/>,
/// the verification the server applies to inbound mail, against the test's DNS.
/// </summary>
[TestFixture]
public sealed class DkimVerifierTests
{

    #region Setup

    private const String Author = "author.test";

    private static String Message(String From = $"news@{Author}")

        => $"From: <{From}>\r\n" +
           "To: <alice@hermod.test>\r\n" +
           "Subject: DKIM verifier\r\n" +
           $"Message-ID: <{Guid.NewGuid():N}@{Author}>\r\n" +
           "Date: Fri, 20 Nov 2026 10:00:00 +0000\r\n" +
           "\r\n" +
           "Hello.\r\n";

    /// <summary>
    /// A DNS that publishes the key's record - as TestDkimKey writes it, or with the given tags
    /// before p=.
    /// </summary>
    private static StubDnsClient Publish(TestDkimKey Key, String? TagsBeforeKey = null)
    {
        var dns = new StubDnsClient();
        dns.Answer(Key.RecordName, DNSResourceRecordTypes.TXT, TagsBeforeKey is null ? Key.Record() : Key.Record(TagsBeforeKey));
        return dns;
    }

    private static async Task<(DkimResult Result, String? Details)> Verify(StubDnsClient Dns, String SignedMessage)
    {
        var (result, details, _) = await new DNSVerifier(Dns, new CapturingLogger()).VerifyDkimAsync(Encoding.UTF8.GetBytes(SignedMessage));
        return (result, details);
    }

    #endregion


    [Test(Description = "RFC 6376 §6.1: a signature by the suite's signer over the usual fields verifies - a guard for the tests below")]
    public async Task A_signature_of_the_suites_signer_verifies()
    {

        using var key = new TestDkimKey(Author);

        var (result, details) = await Verify(Publish(key), key.Sign(Message()));

        Assert.That(result, Is.EqualTo(DkimResult.Pass), details);

    }


    #region V-13: From signed

    [Test(Description = "RFC 6376 §6.1.1: \"If the \"h=\" tag does not include the From header field, the Verifier MUST ignore the DKIM-Signature header field and return PERMFAIL (From field not signed)\" - h=to:subject:date:message-id")]
    [Category(TestCategories.KnownIssue), Property("Finding", "V-13")]
    public async Task A_signature_that_does_not_sign_From_does_not_verify()
    {

        using var key = new TestDkimKey(Author);

        var (result, details) = await Verify(Publish(key), key.Sign(Message(), "to", "subject", "date", "message-id"));

        Assert.That(result, Is.Not.EqualTo(DkimResult.Pass), details);

    }


    [Test(Description = "RFC 6376 §6.1.1, RFC 7489 §3.1.1: a signature that does not sign From - here the From was put in after signing - gives DMARC no aligned identifier, and DMARC does not pass on it")]
    [Category(TestCategories.KnownIssue), Property("Finding", "V-13")]
    public async Task A_signature_that_does_not_sign_From_does_not_pass_DMARC()
    {

        using var key = new TestDkimKey(Author);

        var dns = Publish(key);
        dns.Answer("_dmarc." + Author, DNSResourceRecordTypes.TXT,
                   new TXT(DNSServiceName.Parse("_dmarc." + Author), DNSQueryClasses.IN, TimeSpan.FromHours(1), "v=DMARC1; p=reject"));

        // Signed as a message from someone else, From then changed: the signature still holds
        // over what it signed.
        var signed   = key.Sign(Message(From: "nobody@unrelated.test"), "to", "subject", "date", "message-id").
                           Replace("From: <nobody@unrelated.test>", $"From: <ceo@{Author}>");

        var result   = await new DNSVerifier(dns, new CapturingLogger()).
                                 VerifyAsync("bounces.unrelated.test", IPAddress.Parse("192.0.2.25"), "bounce@bounces.unrelated.test",
                                             "mx.unrelated.test", EMailMessage.Parse(signed));

        Assert.That(result.Dmarc, Is.Not.EqualTo(DmarcResult.Pass), $"dkim={result.Dkim} ({result.DkimDetails})");

    }

    #endregion

    #region V-14: key size

    [Test(Description = "RFC 8301 §3.2: \"Verifiers MUST NOT consider signatures using RSA keys of less than 1024 bits as valid signatures\" - a 512-bit key")]
    [Category(TestCategories.KnownIssue), Property("Finding", "V-14")]
    public async Task A_signature_with_a_key_of_512_bits_does_not_verify()
    {

        using var key = new TestDkimKey(Author, Bits: 512);

        var (result, details) = await Verify(Publish(key), key.Sign(Message()));

        Assert.That(result, Is.Not.EqualTo(DkimResult.Pass), details);

    }


    [Test(Description = "RFC 8301 §3.2: \"Verifiers MUST be able to validate signatures with keys ranging from 1024 bits to 4096 bits\" - a 1024-bit key: a guard for V-14")]
    [Property("Finding", "V-14")]
    public async Task A_signature_with_a_key_of_1024_bits_verifies()
    {

        using var key = new TestDkimKey(Author, Bits: 1024);

        var (result, details) = await Verify(Publish(key), key.Sign(Message()));

        Assert.That(result, Is.EqualTo(DkimResult.Pass), details);

    }

    #endregion

    #region V-15: required tags, and the version

    public static IEnumerable<TestCaseData> RequiredTags()
    {

        TestCaseData Case(String Name, Func<String, String> Tags)
            => new TestCaseData(Tags).SetName($"Not verified: {Name}")
                                     .SetCategory(TestCategories.KnownIssue)
                                     .SetProperty("Finding", "V-15");

        yield return Case("no v= tag",    tags => tags.Replace("v=1; ", ""));
        yield return Case("v=2",          tags => tags.Replace("v=1; ", "v=2; "));
        yield return Case("no a= tag",    tags => tags.Replace("a=rsa-sha256; ", ""));

    }


    [TestCaseSource(nameof(RequiredTags))]
    [Description("RFC 6376 §6.1.1: \"If any tag listed as \"required\" in Section 3.5 is omitted from the DKIM-Signature header field, the Verifier MUST ignore the DKIM-Signature header field and return PERMFAIL\" - v=, a=, b=, bh=, d=, h=, s=; \"Verifiers MUST return PERMFAIL (incompatible version) when presented a DKIM-Signature header field with a \"v=\" tag that is inconsistent with this specification\" (§3.5, v=: \"It MUST have the value \"1\" for implementations compliant with this version of DKIM\")")]
    public async Task A_signature_without_a_required_tag_or_of_another_version_does_not_verify(Func<String, String> Tags)
    {

        using var key = new TestDkimKey(Author);

        var signed = key.Sign(Message(), Tags);
        var (result, details) = await Verify(Publish(key), signed);

        Assert.That(result, Is.Not.EqualTo(DkimResult.Pass), details + "\n" + signed[..signed.IndexOf("\r\n", StringComparison.Ordinal)]);

    }

    #endregion

    #region V-16: i= within d=

    [Test(Description = "RFC 6376 §6.1.1: \"Verifiers MUST confirm that the domain specified in the \"d=\" tag is the same as or a parent domain of the domain part of the \"i=\" tag. If not, the DKIM-Signature header field MUST be ignored\" - i=@evil.test under d=author.test")]
    [Category(TestCategories.KnownIssue), Property("Finding", "V-16")]
    public async Task A_signature_whose_i_is_outside_its_d_does_not_verify()
    {

        using var key = new TestDkimKey(Author);

        var (result, details) = await Verify(Publish(key), key.Sign(Message(), tags => tags + "; i=news@evil.test"));

        Assert.That(result, Is.Not.EqualTo(DkimResult.Pass), details);

    }


    [Test(Description = "RFC 6376 §3.5: i= may name a subdomain of d= - i=news@lists.author.test under d=author.test: a guard for V-16")]
    [Property("Finding", "V-16")]
    public async Task A_signature_whose_i_is_a_subdomain_of_its_d_verifies()
    {

        using var key = new TestDkimKey(Author);

        var (result, details) = await Verify(Publish(key), key.Sign(Message(), tags => tags + $"; i=news@lists.{Author}"));

        Assert.That(result, Is.EqualTo(DkimResult.Pass), details);

    }

    #endregion

    #region V-17: the tags of the key record

    public static IEnumerable<TestCaseData> KeyRecords()
    {

        TestCaseData Case(String Name, String Record, String? Identity, Boolean Verifies)
        {

            var data = new TestCaseData(Record, Identity, Verifies).SetName($"Key record {(Verifies ? "taken" : "not taken")}: {Name}")
                                                                   .SetProperty("Finding", "V-17");

            return Verifies ? data : data.SetCategory(TestCategories.KnownIssue);

        }

        yield return Case("h=sha1, the signature rsa-sha256",          "v=DKIM1; k=rsa; h=sha1; ",     null,                      false);
        yield return Case("s=other, a service that is not email",      "v=DKIM1; k=rsa; s=other; ",    null,                      false);
        yield return Case("t=s, the signature's i= a subdomain",       "v=DKIM1; k=rsa; t=s; ",        $"news@lists.{Author}",    false);
        yield return Case("k=dsa, a key type the signature is not of", "v=DKIM1; k=dsa; ",             null,                      false);

        yield return Case("h=sha1:sha256",                             "v=DKIM1; k=rsa; h=sha1:sha256; ", null,                   true);
        yield return Case("s=email",                                   "v=DKIM1; k=rsa; s=email; ",    null,                      true);
        yield return Case("s=*",                                       "v=DKIM1; k=rsa; s=*; ",        null,                      true);
        yield return Case("t=s, the signature's i= the domain itself", "v=DKIM1; k=rsa; t=s; ",        $"news@{Author}",          true);

    }


    [TestCaseSource(nameof(KeyRecords))]
    [Description("RFC 6376 §6.1.2: \"If the \"h=\" tag exists in the public-key record and the hash algorithm implied by the \"a=\" tag in the DKIM-Signature header field is not included in the contents of the \"h=\" tag, the Verifier MUST ignore the key record\"; \"If the public-key data is not suitable for use with the algorithm and key types defined by the \"a=\" and \"k=\" tags ... the Verifier MUST immediately return PERMFAIL\"; §3.6.1, s=: \"Verifiers for a given service type MUST ignore this record if the appropriate type is not listed\"; t=s: \"the \"i=\" domain MUST NOT be a subdomain of \"d=\"\"")]
    public async Task The_tags_of_the_key_record_are_applied(String Record, String? Identity, Boolean Verifies)
    {

        using var key = new TestDkimKey(Author);

        var signed = Identity is null
                         ? key.Sign(Message())
                         : key.Sign(Message(), tags => tags + $"; i={Identity}");

        var (result, details) = await Verify(Publish(key, Record), signed);

        if (Verifies)
            Assert.That(result, Is.EqualTo(DkimResult.Pass), details);
        else
            Assert.That(result, Is.Not.EqualTo(DkimResult.Pass), details);

    }

    #endregion

}
