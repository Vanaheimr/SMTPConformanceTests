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


    [Test(Description = "RFC 6376 §3.2: tags in any order - a signature with b= first, as the tests of V-4 send it, verifies with the suite's verifier")]
    public void A_signature_whose_b_tag_comes_first_verifies()
    {

        using var key = new TestDkimKey("tooling.test");

        var signed = key.Sign(Message, "rsa-sha256", true);

        Assert.Multiple(() => {
            Assert.That(signed,                             Does.StartWith("DKIM-Signature: b="));
            Assert.That(Verify(key, signed).Single().Valid,  Is.True);
        });

    }


    [Test(Description = "The rsa-sha1 signature the tests of V-3 send is one: SHA-1 hashes and signature, a=rsa-sha1 - and the suite's verifier, as RFC 8301 §3.1 says, does not take it")]
    public void A_signature_with_rsa_sha1_is_what_it_says_and_does_not_verify()
    {

        using var key = new TestDkimKey("tooling.test");
        using var rsa = key.PublicKey();

        var signed = key.Sign(Message, "rsa-sha1", false);
        var tags   = TestArc.Tags(signed["DKIM-Signature:".Length..signed.IndexOf("\r\n", StringComparison.Ordinal)]);

        Assert.Multiple(() => {
            Assert.That(tags["a"],                                    Is.EqualTo("rsa-sha1"));
            Assert.That(Convert.FromBase64String(tags["bh"]).Length,  Is.EqualTo(20), "a SHA-1 body hash");
            Assert.That(Verify(key, signed).Single().Valid,           Is.False);
        });

    }

}


/// <summary>
/// The suite's own ARC sealer and validator (RFC 8617), which the tests of Hermod's ARC rely
/// on: what the one seals the other validates, and each set a validator has to refuse it
/// refuses.
/// </summary>
[TestFixture]
public sealed class ArcToolingTests
{

    private const String Message = "From: <news@tooling.test>\r\n" +
                                   "To: <list@forwarder.example>\r\n" +
                                   "Subject: tooling\r\n" +
                                   "Date: Thu, 19 Nov 2026 10:00:00 +0000\r\n" +
                                   "Message-ID: <tooling@tooling.test>\r\n" +
                                   "\r\n" +
                                   "Hello through a list.\r\n";

    private static String Status(String Message, params TestArcSealOptions[] Sets)
    {

        using var key = new TestDkimKey("forwarder.example", "arc");
        using var rsa = key.PublicKey();

        foreach (var set in Sets)
            Message = TestArc.Seal(Message, key, set);

        return TestArc.Validate(Message, rsa).Status;

    }


    [Test(Description = "RFC 8617 §5.2: one and three sets as the suite seals them pass; a message without a set has none")]
    public void Sealed_chains_pass()
    {
        Assert.Multiple(() => {
            Assert.That(Status(Message),                                   Is.EqualTo("none"));
            Assert.That(Status(Message, new TestArcSealOptions()),          Is.EqualTo("pass"));
            Assert.That(Status(Message, new(), new(), new()),               Is.EqualTo("pass"));
            Assert.That(Status(Message, new TestArcSealOptions { SignatureFirst = true }), Is.EqualTo("pass"));
        });
    }


    [Test(Description = "RFC 8617 §5.2: each set the tests of Hermod's validator expect it to refuse, the suite's validator refuses")]
    public void Broken_chains_fail()
    {

        using var key = new TestDkimKey("forwarder.example", "arc");
        using var rsa = key.PublicKey();

        var fiftyOne  = Message;
        for (var i = 1; i <= 51; i++)
            fiftyOne  = TestArc.Seal(fiftyOne, key);

        var changed   = TestArc.Seal(Message, key).Replace("Hello through", "Hello past");

        Assert.Multiple(() => {
            Assert.That(TestArc.Validate(fiftyOne, rsa).Status,                                         Is.EqualTo("fail"), "51 sets");
            Assert.That(TestArc.Validate(changed,  rsa).Status,                                         Is.EqualTo("fail"), "the body changed");
            Assert.That(Status(Message, new(), new TestArcSealOptions { Instance = 3 }),                Is.EqualTo("fail"), "a gap");
            Assert.That(Status(Message, new(), new TestArcSealOptions { Instance = 1 }),                Is.EqualTo("fail"), "instance 1 twice");
            Assert.That(Status(Message, new TestArcSealOptions { Cv = "pass" }),                        Is.EqualTo("fail"), "cv=pass at 1");
            Assert.That(Status(Message, new(), new TestArcSealOptions { Cv = "fail" }),                 Is.EqualTo("fail"), "cv=fail");
            Assert.That(Status(Message, new(), new TestArcSealOptions { Cv = "fail; cv=pass" }),        Is.EqualTo("fail"), "cv twice");
            Assert.That(Status(Message, new TestArcSealOptions { ExtraSealTags = "h=from:to" }),        Is.EqualTo("fail"), "h= in the AS");
            Assert.That(Status(Message, new TestArcSealOptions { Algorithm = "rsa-sha1" }),             Is.EqualTo("fail"), "rsa-sha1");
        });

    }


    [Test(Description = "Each broken set fails for the rule it breaks - not for a signature the suite got wrong")]
    public void Broken_sets_fail_for_the_rule_they_break()
    {

        using var key = new TestDkimKey("forwarder.example", "arc");
        using var rsa = key.PublicKey();

        Assert.Multiple(() => {
            Assert.That(TestArc.Validate(TestArc.Seal(TestArc.Seal(Message, key), key, new() { Cv = "fail; cv=pass" }), rsa).Detail,  Does.Contain("twice"));
            Assert.That(TestArc.Validate(TestArc.Seal(Message, key, new() { ExtraSealTags = "h=from:to" }), rsa).Detail,              Does.Contain("h= tag"));
            Assert.That(TestArc.Validate(TestArc.Seal(Message, key, new() { Algorithm = "rsa-sha1" }), rsa).Detail,                   Does.Contain("a=rsa-sha1"));
        });

    }

}
