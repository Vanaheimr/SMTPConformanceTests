using System.Text;
using System.Text.RegularExpressions;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 6376 §2.8, §3.4.2, §3.4.4, §3.5: what white space is to a DKIM verifier - WSP, a space or
/// a tab, and nothing else, where the relaxed canonicalization deletes it; and the white space a
/// base64 value of a DKIM-Signature may hold. Every signature here is a valid signature over what
/// it says, made by the suite's own signer over the UTF-8 octets of the message. Verified by
/// <see cref="DNSVerifier.VerifyDkimAsync"/>, the verification the server applies to inbound
/// mail, against the test's DNS.
/// </summary>
[TestFixture]
public sealed class DkimWhiteSpaceTests
{

    #region Setup

    private const String Author = "author.test";

    private static String Message(String Body, String Subject = "DKIM white space")

        => $"From: <news@{Author}>\r\n" +
           "To: <alice@hermod.test>\r\n" +
           $"Subject: {Subject}\r\n" +
           $"Message-ID: <{Guid.NewGuid():N}@{Author}>\r\n" +
           "Date: Fri, 27 Nov 2026 10:00:00 +0000\r\n" +
           "MIME-Version: 1.0\r\n" +
           "Content-Type: text/plain; charset=utf-8\r\n" +
           "Content-Transfer-Encoding: 8bit\r\n" +
           "\r\n" +
           Body;

    private static StubDnsClient Publish(TestDkimKey Key)
    {
        var dns = new StubDnsClient();
        dns.Answer(Key.RecordName, DNSResourceRecordTypes.TXT, Key.Record());
        return dns;
    }

    private static async Task<(DkimResult Result, String? Details, String? Domain)> Verify(StubDnsClient Dns, String SignedMessage)
        => await new DNSVerifier(Dns, new CapturingLogger()).VerifyDkimAsync(Encoding.UTF8.GetBytes(SignedMessage));

    #endregion


    #region V-29: white space is WSP, and nothing else

    private static IEnumerable<TestCaseData> LinesEndingInNoWsp()
    {

        static TestCaseData Case(String Name, String Line)
            => new TestCaseData(Line).SetName($"A relaxed body whose line ends in {Name} verifies")
                                     .SetProperty("Finding", "V-29");

        // The last octet of each is one .NET takes for white space when read one char per octet:
        // 0xA0 (NO-BREAK SPACE), 0x85 (NEXT LINE), 0x0C (FORM FEED).
        yield return Case("à, C3 A0 (French)",           "Rendez-vous demain, voilà\r\n");
        yield return Case("ą, C4 85 (Polish)",           "Do zobaczenia z tobą\r\n");
        yield return Case("х, D1 85 (Russian)",          "До встречи в выходных\r\n");
        yield return Case("a NO-BREAK SPACE, C2 A0",     "Total: 10 EUR \r\n");
        yield return Case("a form feed, 0C",             "Page 1\f\r\n");

    }

    [TestCaseSource(nameof(LinesEndingInNoWsp))]
    [Description("RFC 6376 §3.4.4: relaxed body canonicalization deletes \"all whitespace at the end of lines\", and §2.8 says what that is - \"WSP = SP / HTAB\", so \"whitespace\" is a space or a tab. A line that ends in an octet of a UTF-8 character, in a NO-BREAK SPACE or in a form feed keeps it, and a valid signature over such a line verifies - a mail in Polish, Russian or French signed by any other signer with c=relaxed/relaxed, the canonicalization most signers use")]
    public async Task A_relaxed_body_whose_line_ends_in_no_WSP_verifies(String Line)
    {

        using var key = new TestDkimKey(Author);

        var signed = key.Sign(Message(Line));

        var (result, details, _) = await Verify(Publish(key), signed);

        Assert.That(result, Is.EqualTo(DkimResult.Pass), details);

    }


    private static IEnumerable<TestCaseData> FieldsEndingInNoWsp()
    {

        static TestCaseData Case(String Name, String Subject)
            => new TestCaseData(Subject).SetName($"A relaxed header field that ends in {Name} verifies")
                                        .SetProperty("Finding", "V-29");

        yield return Case("ą, C4 85 (Polish)",  "Spotkanie z tobą");
        yield return Case("à, C3 A0 (French)",  "Le programme, voilà");

    }

    [TestCaseSource(nameof(FieldsEndingInNoWsp))]
    [Description("RFC 6376 §3.4.2: relaxed header canonicalization deletes \"all WSP characters at the end of each unfolded header field value\" - WSP, a space or a tab (§2.8). A Subject in UTF-8 (RFC 6532 §3.2) that ends in a character whose last octet is 0xA0 or 0x85 keeps it, and a valid signature over it verifies")]
    public async Task A_relaxed_header_field_that_ends_in_no_WSP_verifies(String Subject)
    {

        using var key = new TestDkimKey(Author);

        var signed = key.Sign(Message("Hello.\r\n", Subject));

        var (result, details, _) = await Verify(Publish(key), signed);

        Assert.That(result, Is.EqualTo(DkimResult.Pass), details);

    }


    [Test(Description = "RFC 6376 §3.4.4: what is WSP at the end of a line - spaces and tabs - is deleted, and a run of it inside a line is one space: a valid signature over a body with both verifies, and so does one after the white space was changed (a guard for V-29)")]
    [Property("Finding", "V-29")]
    public async Task White_space_that_is_WSP_is_deleted_at_the_end_of_a_line()
    {

        using var key = new TestDkimKey(Author);

        var signed   = key.Sign(Message("Hello, \t world. \t \r\nBye.  \r\n"));
        var modified = signed.Replace("Hello, \t world. \t \r\n", "Hello, world.\r\n");

        Assume.That(modified, Is.Not.EqualTo(signed));

        var (result,  details,  _) = await Verify(Publish(key), signed);
        var (changed, detailsC, _) = await Verify(Publish(key), modified);

        Assert.Multiple(() => {
            Assert.That(result,  Is.EqualTo(DkimResult.Pass), details);
            Assert.That(changed, Is.EqualTo(DkimResult.Pass), detailsC);
        });

    }

    #endregion

    #region V-30: white space in bh=

    private static IEnumerable<TestCaseData> BodyHashesWithWhiteSpace()
    {

        static TestCaseData Case(String Name, String Replacement)
            => new TestCaseData(Replacement).SetName($"A bh= with white space verifies: {Name}")
                                            .SetProperty("Finding", "V-30");

        yield return Case("folded after 20 characters", "bh=$1\r\n\t$2");
        yield return Case("a space in it, and around", "bh= $1 $2 ");

    }

    [TestCaseSource(nameof(BodyHashesWithWhiteSpace))]
    [Description("RFC 6376 §3.5, bh=: \"The hash of the canonicalized body part of the message ... (base64; REQUIRED). Whitespace is ignored in this value and MUST be ignored when reassembling the original signature\" - base64string = ALPHADIGITPS *([FWS] ALPHADIGITPS) (§2.4). A valid signature whose bh= is folded, or has a space in it, verifies")]
    public async Task A_bh_with_white_space_verifies(String Replacement)
    {

        using var key = new TestDkimKey(Author);

        var signed = key.Sign(Message("Hello.\r\n"), tags => Regex.Replace(tags, @"bh=(.{20})(.+)$", Replacement));

        Assume.That(signed, Does.Not.Match(@"bh=[A-Za-z0-9+/=]{44}"));

        var (result, details, _) = await Verify(Publish(key), signed);

        Assert.That(result, Is.EqualTo(DkimResult.Pass), details);

    }


    [Test(Description = "RFC 6376 §3.5, bh=: the white space is ignored, not the hash - a bh= with white space that hashes another body does not verify (a guard for V-30)")]
    [Property("Finding", "V-30")]
    public async Task A_bh_with_white_space_of_another_body_does_not_verify()
    {

        using var key = new TestDkimKey(Author);

        var signed   = key.Sign(Message("Hello.\r\n"), tags => Regex.Replace(tags, @"bh=(.{20})(.+)$", "bh=$1\r\n\t$2"));
        var modified = signed.Replace("Hello.\r\n", "Hello!\r\n");

        var (result, details, _) = await Verify(Publish(key), modified);

        Assert.That(result, Is.Not.EqualTo(DkimResult.Pass), details);

    }

    #endregion

}
