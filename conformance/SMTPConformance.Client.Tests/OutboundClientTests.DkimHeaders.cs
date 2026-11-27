using System.Text.RegularExpressions;

using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;

namespace SMTPConformance.Client.Tests;

public sealed partial class OutboundClientTests
{

    #region The header fields Hermod signs

    /// <summary>
    /// The h= tag of the DKIM-Signature the message arrived with, unfolded.
    /// </summary>
    private static String SignedFieldsOf(String Message)
    {
        var header = Regex.Replace(Message[..Message.IndexOf("\r\n\r\n", StringComparison.Ordinal)], @"\r\n[ \t]", " ");
        return Regex.Match(header, @"^DKIM-Signature:[^\r\n]*?(?:;|:)\s*h=([^;]*)", RegexOptions.Multiline).Groups[1].Value.Trim();
    }

    private static IEnumerable<String> Names(String SignedFields)
        => SignedFields.Split(':').Select(name => name.Trim().ToLowerInvariant()).Where(name => name.Length > 0);


    #region P-6: From is always signed

    [TestCase("to:subject", TestName = "A signer configured without From signs From all the same: to:subject")]
    [TestCase("",           TestName = "A signer configured without From signs From all the same: nothing configured")]
    [Description("RFC 6376 §5.4: \"The From header field MUST be signed (that is, included in the \"h=\" tag of the resulting DKIM-Signature header field)\"; §6.1.1: a verifier MUST ignore a signature whose h= does not include From - one without it is a signature no verifier takes, Hermod's own among them (V-13)")]
    [Property("Finding", "P-6")]
    public async Task A_signer_configured_without_From_signs_From_all_the_same(String SignedHeaders)
    {

        var rsa = RsaKey("hermod.test");
        var key = rsa with { Config = rsa.Config with { SignedHeaders = SignedHeaders } };

        var (results, message) = await SendSignedWith(key, Letter("news@hermod.test", "Hello."));
        var h                  = SignedFieldsOf(message);

        Assert.Multiple(() => {
            Assert.That(Names(h),                    Does.Contain("from"),          "h=" + h + "\n" + message);
            Assert.That(results.Select(r => r.Valid), Is.EqualTo(new[] { true }),   String.Join("; ", results.Select(r => r.Detail)) + "\n" + message);
        });

    }


    [Test(Description = "RFC 6376 §5.4: the default configuration signs From, To, Subject, Date and Message-ID, and the signature verifies (a guard for P-6)")]
    [Property("Finding", "P-6")]
    public async Task The_default_configuration_signs_From()
    {

        var (results, message) = await SendSignedWith(RsaKey("hermod.test"), Letter("news@hermod.test", "Hello."));
        var h                  = SignedFieldsOf(message);

        Assert.Multiple(() => {
            Assert.That(Names(h),                    Is.SupersetOf(new[] { "from", "to", "subject", "date", "message-id" }), "h=" + h);
            Assert.That(results.Select(r => r.Valid), Is.EqualTo(new[] { true }),   String.Join("; ", results.Select(r => r.Detail)) + "\n" + message);
        });

    }


    [Test(Description = "RFC 6376 §5.4: a name listed once more than the message has instances of it signs their absence - \"if that header field is added later, the signature will fail\" (a guard for P-6)")]
    [Property("Finding", "P-6")]
    public async Task A_field_named_once_more_than_it_occurs_signs_its_absence()
    {

        var rsa = RsaKey("hermod.test");
        var key = rsa with { Config = rsa.Config with { SignedHeaders = "from:subject:subject" } };

        var (results, message) = await SendSignedWith(key, Letter("news@hermod.test", "Hello."));
        var added              = "Subject: another subject\r\n" + message;
        var addedResults       = TestDkimVerifier.Verify(added, new Dictionary<String, String> { [key.RecordName] = key.Record });

        Assert.Multiple(() => {
            Assert.That(SignedFieldsOf(message),           Is.EqualTo("from:subject:subject"), message);
            Assert.That(results.Select(r => r.Valid),      Is.EqualTo(new[] { true }),         String.Join("; ", results.Select(r => r.Detail)) + "\n" + message);
            Assert.That(addedResults.Select(r => r.Valid), Is.EqualTo(new[] { false }),        "a Subject added on top: " + added);
        });

    }


    [Test(Description = "RFC 6376 §5.4.2: of a field that occurs more than once, \"Signers wishing to sign multiple instances of such a header field MUST include the header field name multiple times in the \"h=\" tag ... and MUST sign such header fields in order starting from the bottom of the header field block and working upward\" - two Comments fields, named twice, verify (a guard for P-6)")]
    [Property("Finding", "P-6")]
    public async Task Two_instances_of_a_field_are_signed_from_the_bottom_up()
    {

        var rsa   = RsaKey("hermod.test");
        var key   = rsa with { Config = rsa.Config with { SignedHeaders = "from:comments:comments" } };

        var lines = Letter("news@hermod.test", "Hello.").ToList();
        lines.InsertRange(1, [ "Comments: the first", "Comments: the second" ]);

        var (results, message) = await SendSignedWith(key, [ .. lines ]);
        // The two Comments fields where they arrived, exchanged.
        var swapped            = Regex.Replace(message, "^Comments: the (first|second)\r\n", match => match.Value.Contains("first") ? "Comments: the second\r\n" : "Comments: the first\r\n", RegexOptions.Multiline);
        var swappedResults     = TestDkimVerifier.Verify(swapped, new Dictionary<String, String> { [key.RecordName] = key.Record });

        Assert.Multiple(() => {
            Assert.That(results.Select(r => r.Valid),        Is.EqualTo(new[] { true }),  String.Join("; ", results.Select(r => r.Detail)) + "\n" + message);
            Assert.That(swapped,                             Is.Not.EqualTo(message));
            Assert.That(swappedResults.Select(r => r.Valid), Is.EqualTo(new[] { false }), "the two swapped: " + swapped);
        });

    }


    [Test(Description = "RFC 6376 §5.4: \"Signers MAY claim to have signed header fields that do not exist\" - a configured field the message lacks is no obstacle, the signature verifies (a guard for P-6)")]
    [Property("Finding", "P-6")]
    public async Task A_configured_field_the_message_lacks_is_no_obstacle()
    {

        var rsa = RsaKey("hermod.test");
        var key = rsa with { Config = rsa.Config with { SignedHeaders = "from:reply-to:subject" } };

        var (results, message) = await SendSignedWith(key, Letter("news@hermod.test", "Hello."));

        Assert.Multiple(() => {
            Assert.That(Names(SignedFieldsOf(message)),  Is.SupersetOf(new[] { "from", "subject" }), message);
            Assert.That(results.Select(r => r.Valid),    Is.EqualTo(new[] { true }),                 String.Join("; ", results.Select(r => r.Detail)) + "\n" + message);
        });

    }

    #endregion

    #endregion

}
