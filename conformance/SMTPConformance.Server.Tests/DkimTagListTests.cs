using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 6376 §3.2, §3.5, §3.6.1: what the tags of a DKIM-Signature and of a key record say, as a
/// verifier reads them - the canonicalization a c= tag of one name stands for, a tag-list with a
/// tag named twice, the version of a key record. Every signature here is a valid signature over
/// what it says, made by the suite's own signer. Verified by
/// <see cref="DNSVerifier.VerifyDkimAsync"/>, the verification the server applies to inbound
/// mail, against the test's DNS.
/// </summary>
[TestFixture]
public sealed class DkimTagListTests
{

    #region Setup

    private const String Author = "author.test";

    private static String Message(String Body = "Hello.\r\n")

        => $"From: <news@{Author}>\r\n" +
           "To: <alice@hermod.test>\r\n" +
           "Subject: DKIM tag-lists\r\n" +
           $"Message-ID: <{Guid.NewGuid():N}@{Author}>\r\n" +
           "Date: Fri, 27 Nov 2026 10:00:00 +0000\r\n" +
           "\r\n" +
           Body;

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

    private static async Task<(DkimResult Result, String? Details, String? Domain)> Verify(StubDnsClient Dns, String SignedMessage)
        => await new DNSVerifier(Dns, new CapturingLogger()).VerifyDkimAsync(Encoding.UTF8.GetBytes(SignedMessage));

    #endregion


    #region V-26: c= with one name

    [Test(Description = "RFC 6376 §3.5, c=: \"If only one algorithm is named, that algorithm is used for the header and \"simple\" is used for the body. For example, \"c=relaxed\" is treated the same as \"c=relaxed/simple\"\" - a signature with c=relaxed over a body with white space that simple canonicalization keeps (§3.4.3) verifies")]
    [Property("Finding", "V-26")]
    public async Task A_signature_with_c_relaxed_hashes_the_body_simple()
    {

        using var key = new TestDkimKey(Author);

        var signed = key.SignCanonicalized(Message("Hello,  world.  \r\nBye.\r\n"), "relaxed");

        var (result, details, _) = await Verify(Publish(key), signed);

        Assert.That(result, Is.EqualTo(DkimResult.Pass), details);

    }


    [Test(Description = "RFC 6376 §3.4.3, §3.5: with c=relaxed the body is canonicalized simple - \"The \"simple\" body canonicalization algorithm ignores all empty lines at the end of the message body\", and nothing else - so white space put into the body after signing breaks the signature, where relaxed body canonicalization (§3.4.4) would have hidden it")]
    [Property("Finding", "V-26")]
    public async Task White_space_added_to_a_body_signed_with_c_relaxed_breaks_the_signature()
    {

        using var key = new TestDkimKey(Author);

        var signed   = key.SignCanonicalized(Message("Pay 10 EUR.\r\n"), "relaxed");
        var modified = signed.Replace("Pay 10 EUR.\r\n", "Pay 10   EUR.  \r\n");

        Assume.That(modified, Is.Not.EqualTo(signed));

        var (result, details, _) = await Verify(Publish(key), modified);

        Assert.That(result, Is.Not.EqualTo(DkimResult.Pass), details);

    }


    private static IEnumerable<TestCaseData> CanonicalizationsNamedInFull()
    {

        static TestCaseData Case(String Canonicalization)
            => new TestCaseData(Canonicalization).SetName($"A signature with c={Canonicalization} verifies")
                                                 .SetProperty("Finding", "V-26");

        yield return Case("relaxed/simple");
        yield return Case("relaxed/relaxed");

    }

    [TestCaseSource(nameof(CanonicalizationsNamedInFull))]
    [Description("RFC 6376 §3.5, c=: \"two names separated by a \"slash\" (%d47) character, corresponding to the header and body canonicalization algorithms, respectively\" - a signature with both named, over a body with white space, verifies (a guard for V-26)")]
    public async Task A_signature_with_both_canonicalizations_named_verifies(String Canonicalization)
    {

        using var key = new TestDkimKey(Author);

        var signed = key.SignCanonicalized(Message("Hello,  world.  \r\nBye.\r\n"), Canonicalization);

        var (result, details, _) = await Verify(Publish(key), signed);

        Assert.That(result, Is.EqualTo(DkimResult.Pass), details);

    }

    #endregion

    #region V-27: a tag named twice in a DKIM-Signature

    [Test(Description = "RFC 6376 §3.2: \"Tags with duplicate names MUST NOT occur within a single tag-list; if a tag name does occur more than once, the entire tag-list is invalid\" - a DKIM-Signature that names d= twice, the author's domain first and the signer's own after it, is no signature: not a pass for either domain, whatever the key of the second says")]
    [Property("Finding", "V-27")]
    public async Task A_DKIM_Signature_with_d_twice_is_invalid()
    {

        using var key = new TestDkimKey("signer.test");

        var signed = key.Sign(Message(), tags => tags.Replace("d=signer.test", $"d={Author}; d=signer.test"));

        Assume.That(signed, Does.Contain($"d={Author}; d=signer.test"));

        var (result, details, domain) = await Verify(Publish(key), signed);

        Assert.That(result, Is.Not.EqualTo(DkimResult.Pass), $"d={domain}: {details}");

    }


    private static IEnumerable<TestCaseData> TagsNamedTwice()
    {

        static TestCaseData Case(String Name, String Tag)
            => new TestCaseData(Tag).SetName($"A DKIM-Signature with a tag named twice is invalid: {Name}")
                                    .SetProperty("Finding", "V-27");

        yield return Case("v= twice",  "v=1");
        yield return Case("s= twice",  "s=test");

    }

    [TestCaseSource(nameof(TagsNamedTwice))]
    [Description("RFC 6376 §3.2: \"if a tag name does occur more than once, the entire tag-list is invalid\" - even when both say the same")]
    public async Task A_DKIM_Signature_with_a_tag_named_twice_is_invalid(String Tag)
    {

        using var key = new TestDkimKey(Author);

        var signed = key.Sign(Message(), tags => tags + "; " + Tag);

        var (result, details, _) = await Verify(Publish(key), signed);

        Assert.That(result, Is.Not.EqualTo(DkimResult.Pass), details);

    }

    #endregion

    #region V-28: the tag-list of the key record

    private static IEnumerable<TestCaseData> KeyRecordsNotToBeUsed()
    {

        static TestCaseData Case(String Name, String TagsBeforeKey)
            => new TestCaseData(TagsBeforeKey).SetName($"A key record is not used: {Name}")
                                              .SetProperty("Finding", "V-28");

        yield return Case("v=DKIM1 not the first tag",     "k=rsa; v=DKIM1; ");
        yield return Case("a tag named twice",             "v=DKIM1; k=rsa; k=rsa; ");

        // A record beginning with another version was discarded before V-28 as well.
        yield return Case("v=DKIM2",                       "v=DKIM2; k=rsa; ");

    }

    [TestCaseSource(nameof(KeyRecordsNotToBeUsed))]
    [Description("RFC 6376 §3.6.1, v=: \"If specified, this tag MUST be set to \"DKIM1\" (without the quotes). This tag MUST be the first tag in the record. Records beginning with a \"v=\" tag with any other value MUST be discarded\"; §3.2: a tag-list with a tag named twice \"is invalid\"; §6.1.2: \"If the result returned from the query does not adhere to the format defined in this specification, the Verifier MUST ignore the key record and return PERMFAIL (key syntax error)\", \"the Verifier MUST ignore keys with a version code (\"v=\" tag) that they do not implement\"")]
    public async Task A_key_record_not_to_be_used_is_not_used(String TagsBeforeKey)
    {

        using var key = new TestDkimKey(Author);

        var signed = key.Sign(Message());

        var (result, details, _) = await Verify(Publish(key, TagsBeforeKey), signed);

        Assert.That(result, Is.Not.EqualTo(DkimResult.Pass), details);

    }


    private static IEnumerable<TestCaseData> KeyRecordsToBeUsed()
    {

        static TestCaseData Case(String Name, String TagsBeforeKey)
            => new TestCaseData(TagsBeforeKey).SetName($"A key record is used: {Name}")
                                              .SetProperty("Finding", "V-28");

        yield return Case("v=DKIM1 first",                 "v=DKIM1; k=rsa; ");
        yield return Case("no v= (RECOMMENDED only)",      "k=rsa; ");
        yield return Case("white space around the tags",   "v = DKIM1 ;  k = rsa ; ");

    }

    [TestCaseSource(nameof(KeyRecordsToBeUsed))]
    [Description("RFC 6376 §3.6.1: v= is \"RECOMMENDED, default is \"DKIM1\"\"; §3.2: tag-list = tag-spec *( \";\" tag-spec ) [ \";\" ], tag-spec = [FWS] tag-name [FWS] \"=\" [FWS] tag-value [FWS] - the key records RFC 6376 has are used (a guard for V-28)")]
    public async Task A_key_record_as_RFC_6376_has_it_is_used(String TagsBeforeKey)
    {

        using var key = new TestDkimKey(Author);

        var signed = key.Sign(Message());

        var (result, details, _) = await Verify(Publish(key, TagsBeforeKey), signed);

        Assert.That(result, Is.EqualTo(DkimResult.Pass), details);

    }

    #endregion

}
