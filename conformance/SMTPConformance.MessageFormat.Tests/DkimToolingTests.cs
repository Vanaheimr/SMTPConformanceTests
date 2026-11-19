using NUnit.Framework;

using SMTPConformance.Core.Fixtures;

namespace SMTPConformance.MessageFormat.Tests;

/// <summary>
/// The suite's own DKIM signer and verifier, which the tests of Hermod's DKIM rely on: what
/// the one signs the other verifies, and a change to a signed part it does not.
/// </summary>
[TestFixture]
public sealed class DkimToolingTests
{

    private const String Message = "From: <news@tooling.test>\r\n" +
                                   "To: <alice@hermod.test>\r\n" +
                                   "Subject: tooling\r\n" +
                                   "Date: Thu, 19 Nov 2026 10:00:00 +0000\r\n" +
                                   "Message-ID: <tooling@tooling.test>\r\n" +
                                   "\r\n" +
                                   "Hello  world \r\n" +
                                   "\r\n";

    private static IReadOnlyList<DkimVerification> Verify(TestDkimKey Key, String Message)
        => TestDkimVerifier.Verify(Message, new Dictionary<String, String> { [Key.RecordName] = Key.Record().Text });


    [Test(Description = "RFC 6376 §3.7: a message the suite's signer signed, the suite's verifier verifies")]
    public void A_signed_message_verifies()
    {

        using var key = new TestDkimKey("tooling.test");

        Assert.That(Verify(key, key.Sign(Message)).Single().Valid, Is.True);

    }


    [TestCase("Hello  world ",  "Hello  world!",   TestName = "A changed body does not verify")]
    [TestCase("Subject: tooling", "Subject: t00ling", TestName = "A changed signed header field does not verify")]
    [Test(Description = "RFC 6376 §6.1.3: a change to the body or to a signed header field makes the signature fail")]
    public void A_changed_message_does_not_verify(String Original, String Changed)
    {

        using var key = new TestDkimKey("tooling.test");

        Assert.That(Verify(key, key.Sign(Message).Replace(Original, Changed)).Single().Valid, Is.False);

    }


    [Test(Description = "RFC 6376 §3.4.4: relaxed body canonicalization - whitespace changed within a line and at its end still verifies")]
    public void Whitespace_the_relaxed_canonicalization_ignores_still_verifies()
    {

        using var key = new TestDkimKey("tooling.test");

        Assert.That(Verify(key, key.Sign(Message).Replace("Hello  world \r\n", "Hello world\t \r\n")).Single().Valid, Is.True);

    }

}
