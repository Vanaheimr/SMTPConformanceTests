using System.Text.RegularExpressions;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 8617 (ARC) as Hermod's server validates it on inbound mail, and as it reports the
/// result in Authentication-Results (§7). The chains are sealed by the suite's own ARC
/// sealer (<see cref="TestArc"/>), not by Hermod's.
/// </summary>
[TestFixture]
public sealed class ArcValidationTests : HermodServerTestBase
{

    #region Setup

    private TestDkimKey forwarder = null!;

    [OneTimeSetUp]
    public void PublishTheForwardersKey()
    {
        forwarder = new TestDkimKey("forwarder.example", "arc");
        Server.Dns.Answer(forwarder.RecordName, DNSResourceRecordTypes.TXT, forwarder.Record());
    }

    [OneTimeTearDown]
    public void DisposeTheKey()
        => forwarder?.Dispose();


    private static String Message(String Marker)

        => "From: <news@origin.example>\r\n" +
           "To: <alice@hermod.test>\r\n" +
           $"Subject: {Marker}\r\n" +
           $"Message-ID: <{Guid.NewGuid():N}@origin.example>\r\n" +
           "Date: Thu, 19 Nov 2026 10:00:00 +0000\r\n" +
           "\r\n" +
           "Hello through a list.\r\n";

    private String Sealed(String Message, params TestArcSealOptions[] Sets)
    {
        foreach (var set in Sets.Length == 0 ? [ new TestArcSealOptions() ] : Sets)
            Message = TestArc.Seal(Message, forwarder, set);
        return Message;
    }

    /// <summary>
    /// One transaction from the forwarder to alice: the final reply (null if none came in
    /// time), the arc= result of the stored message ("" if none), and what to print.
    /// </summary>
    private async Task<(SmtpReply? Final, String Arc, String Explanation)> Deliver(String Message, String Marker)
    {

        await using var client = await Server.ConnectAndEhloAsync("mx.forwarder.example");

        var (mail, rcpts) = await client.EnvelopeAsync("list@forwarder.example", "alice@hermod.test");
        Assert.That(mail.Code,      Is.EqualTo(250), Explain(client));
        Assert.That(rcpts[0].Code,  Is.EqualTo(250), Explain(client));

        SmtpReply? final = null;

        try
        {
            (_, final) = await client.DataAsync(Message);
        }
        catch (TimeoutException)
        {
            // asserted by the caller
        }

        var stored  = final?.Code == 250 ? await Server.Storage.WaitForMarkerAsync(Marker) : null;
        var results = stored is null
                          ? ""
                          : Regex.Match(stored.Raw, @"^Authentication-Results:(?<value>[^\r\n]*(?:\r\n[ \t][^\r\n]*)*)", RegexOptions.Multiline | RegexOptions.IgnoreCase).Groups["value"].Value;
        var arc     = Regex.Match(results, @"(?:^|[;\s])arc=(?<result>[a-z]+)", RegexOptions.IgnoreCase).Groups["result"].Value.ToLowerInvariant();

        return (final, arc, $"Authentication-Results:{results}\n{Explain(client)}");

    }

    private async Task AssertArc(String Message, String Marker, String Expected)
    {

        var (final, arc, explanation) = await Deliver(Message, Marker);

        Assert.Multiple(() => {
            Assert.That(final?.Code, Is.EqualTo(250),      explanation);
            Assert.That(arc,         Is.EqualTo(Expected), explanation);
        });

    }

    #endregion


    #region The chain as it should be

    [Test(Description = "RFC 8617 §5.2: one ARC set with a valid AMS and AS, cv=none - the chain passes; a guard for the suite's sealer")]
    public async Task One_ARC_set_passes()
    {
        var marker = Marker();
        await AssertArc(Sealed(Message(marker)), marker, "pass");
    }

    [Test(Description = "RFC 8617 §5.2: two sets, the second with cv=pass - the chain passes")]
    public async Task Two_ARC_sets_pass()
    {
        var marker = Marker();
        await AssertArc(Sealed(Message(marker), new(), new()), marker, "pass");
    }

    [Test(Description = "RFC 8617 §5.2 step 4: the body changed after the newest AMS - the chain fails")]
    public async Task A_body_changed_after_sealing_fails()
    {
        var marker = Marker();
        await AssertArc(Sealed(Message(marker)).Replace("Hello through a list.", "Hello from somebody else."), marker, "fail");
    }

    [Test(Description = "RFC 8617 §5.2 step 3B: \"The instance values of the ARC Sets MUST form a continuous sequence from 1..N with no gaps or repetition\" - sets 1 and 3")]
    public async Task A_gap_in_the_instances_fails()
    {
        var marker = Marker();
        await AssertArc(Sealed(Message(marker), new(), new TestArcSealOptions { Instance = 3 }), marker, "fail");
    }

    [Test(Description = "RFC 8617 §5.2 step 3A: \"Each ARC Set MUST contain exactly one each of the three ARC header fields\" - instance 1 twice")]
    public async Task An_instance_twice_fails()
    {
        var marker = Marker();
        await AssertArc(Sealed(Message(marker), new(), new TestArcSealOptions { Instance = 1 }), marker, "fail");
    }

    [Test(Description = "RFC 8617 §5.2 step 3C: \"For the ARC Set with instance value = 1, the value MUST be \"none\"\"")]
    public async Task A_first_set_saying_cv_pass_fails()
    {
        var marker = Marker();
        await AssertArc(Sealed(Message(marker), new TestArcSealOptions { Cv = "pass" }), marker, "fail");
    }

    [Test(Description = "RFC 8617 §5.2 step 2: the newest set saying cv=fail - the chain fails")]
    public async Task A_newest_set_saying_cv_fail_fails()
    {
        var marker = Marker();
        await AssertArc(Sealed(Message(marker), new(), new TestArcSealOptions { Cv = "fail" }), marker, "fail");
    }

    #endregion

    #region What a validator has to refuse

    [Test(Description = "RFC 8617 §5.2 step 1: \"The maximum number of ARC Sets that can be attached to a message is 50. If more than the maximum exist, the Chain Validation Status is \"fail\"\"")]
    [Property("Finding", "A-1")]
    public async Task More_than_50_ARC_sets_fail()
    {

        var marker  = Marker();
        var message = Message(marker);

        for (var i = 1; i <= 51; i++)
            message = TestArc.Seal(message, forwarder);

        await AssertArc(message, marker, "fail");

    }

    [Test(Description = "RFC 8617 §4.1.3: \"the DKIM \"h\" tag is NOT allowed and, if found, MUST result in a cv status of \"fail\"\"")]
    [Property("Finding", "A-2")]
    public async Task An_ARC_Seal_with_an_h_tag_fails()
    {
        var marker = Marker();
        await AssertArc(Sealed(Message(marker), new TestArcSealOptions { ExtraSealTags = "h=from:to" }), marker, "fail");
    }

    [Test(Description = "RFC 6376 §3.2, which ARC's tag-lists follow: \"Tags with duplicate names MUST NOT occur within a single tag-list; if a tag name does occur more than once, the entire tag-list is invalid\" - cv=fail, then cv=pass")]
    [Property("Finding", "A-3")]
    public async Task An_ARC_Seal_naming_cv_twice_fails()
    {
        var marker = Marker();
        await AssertArc(Sealed(Message(marker), new(), new TestArcSealOptions { Cv = "fail; cv=pass" }), marker, "fail");
    }

    [Test(Description = "RFC 8617 §5.2 imports the signature methods of RFC 6376, and RFC 8301 §3.1: \"rsa-sha1 MUST NOT be used for signing or verifying\"")]
    [Property("Finding", "V-3")]
    public async Task A_chain_sealed_with_rsa_sha1_fails()
    {
        var marker = Marker();
        await AssertArc(Sealed(Message(marker), new TestArcSealOptions { Algorithm = "rsa-sha1" }), marker, "fail");
    }

    [Test(Description = "RFC 6376 §3.2: the tags of a tag-list may come in any order; §3.7: the b= value is removed wherever b= stands - b= first in the AMS and the AS")]
    [Property("Finding", "V-4")]
    public async Task A_chain_whose_signatures_come_first_passes()
    {
        var marker = Marker();
        await AssertArc(Sealed(Message(marker), new TestArcSealOptions { SignatureFirst = true }), marker, "pass");
    }

    #endregion

    #region A-6: the ARC-Message-Signature read as a DKIM-Signature

    private static String WithWhiteSpace(String Marker)
        => Message(Marker).Replace("Hello through a list.\r\n", "Hello  through a list.  \r\nBye.\r\n");

    [Test(Description = "RFC 8617 §4.1.2: the AMS \"is syntactically and semantically identical to a DKIM-Signature header field\"; RFC 6376 §3.5, c=: \"If no canonicalization algorithm is specified, the Signer MUST use \"simple/simple\"\" - an AMS without c=, made simple/simple, passes")]
    [Property("Finding", "A-6")]
    public async Task An_AMS_without_c_is_simple_simple()
    {
        var marker = Marker();
        await AssertArc(Sealed(WithWhiteSpace(marker), new TestArcSealOptions { AmsCanonicalization = null }), marker, "pass");
    }

    [Test(Description = "RFC 8617 §4.1.2; RFC 6376 §3.5, c=: \"If only one algorithm is named, that algorithm is used for the header and \"simple\" is used for the body. For example, \"c=relaxed\" is treated the same as \"c=relaxed/simple\"\" - an AMS with c=relaxed over a body with white space that simple canonicalization keeps passes")]
    [Property("Finding", "A-6")]
    public async Task An_AMS_with_c_relaxed_hashes_the_body_simple()
    {
        var marker = Marker();
        await AssertArc(Sealed(WithWhiteSpace(marker), new TestArcSealOptions { AmsCanonicalization = "relaxed" }), marker, "pass");
    }

    [Test(Description = "RFC 8617 §5.2 step 4; RFC 6376 §3.4.3, §3.5: with c=relaxed the body of the AMS is canonicalized simple, so white space put into it after sealing makes the chain fail, where relaxed body canonicalization would have hidden it")]
    [Property("Finding", "A-6")]
    public async Task White_space_added_to_a_body_sealed_with_c_relaxed_fails()
    {
        var marker = Marker();
        var sealed_ = Sealed(Message(marker), new TestArcSealOptions { AmsCanonicalization = "relaxed" });
        await AssertArc(sealed_.Replace("Hello through a list.\r\n", "Hello   through a list.  \r\n"), marker, "fail");
    }

    [Test(Description = "RFC 8617 §4.1.2; RFC 6376 §3.5, bh=: \"Whitespace is ignored in this value and MUST be ignored when reassembling the original signature\" - an AMS whose bh= is folded passes")]
    [Property("Finding", "A-6")]
    public async Task An_AMS_with_bh_folded_passes()
    {
        var marker = Marker();
        await AssertArc(Sealed(Message(marker), new TestArcSealOptions { AmsTags = tags => Regex.Replace(tags, @"bh=(.{20})(.+)$", "bh=$1\r\n\t$2") }), marker, "pass");
    }

    [TestCase("relaxed/simple")]
    [TestCase("simple/simple")]
    [Description("RFC 8617 §4.1.2; RFC 6376 §3.5, c=: both canonicalizations named - an AMS with c=relaxed/simple or c=simple/simple over a body with white space passes (a guard for A-6)")]
    [Property("Finding", "A-6")]
    public async Task An_AMS_with_both_canonicalizations_named_passes(String Canonicalization)
    {
        var marker = Marker();
        await AssertArc(Sealed(WithWhiteSpace(marker), new TestArcSealOptions { AmsCanonicalization = Canonicalization }), marker, "pass");
    }

    #endregion

}


/// <summary>
/// An ARC instance number as no chain can have: the validation must end at once (RFC 8617
/// §5.2 step 1). On its own fixture: where it does not end, the session it hangs is this one's.
/// </summary>
[TestFixture]
public sealed class ArcInstanceLimitTests : HermodServerTestBase
{

    [Test(Description = "RFC 8617 §4.2.1: \"Instance tag values can range from 1-50 (inclusive)\"; §5.2 step 1 - beyond, the chain fails, and the message is answered without delay")]
    [Property("Finding", "A-1")]
    public async Task An_instance_number_beyond_50_is_answered_at_once()
    {

        var marker  = Marker();
        var message = "ARC-Seal: i=2147483647; a=rsa-sha256; cv=none; d=forwarder.example; s=arc; t=1763546400; b=AAAA\r\n" +
                      "ARC-Message-Signature: i=2147483647; a=rsa-sha256; c=relaxed/relaxed; d=forwarder.example; s=arc; h=from; bh=AAAA; b=AAAA\r\n" +
                      "ARC-Authentication-Results: i=2147483647; forwarder.example; spf=pass\r\n" +
                      "From: <news@origin.example>\r\n" +
                      "To: <alice@hermod.test>\r\n" +
                      $"Subject: {marker}\r\n" +
                      "\r\n" +
                      "Hello.\r\n";

        await using var client = await Server.ConnectAndEhloAsync("mx.forwarder.example");
        await client.EnvelopeAsync("list@forwarder.example", "alice@hermod.test");

        SmtpReply? final = null;

        try
        {
            (_, final) = await client.DataAsync(message);
        }
        catch (TimeoutException)
        {
        }

        Assert.That(final?.Code, Is.EqualTo(250), "no answer within 10 s to the end of the data - the validator is still counting instances" + Explain(client));

    }

}


/// <summary>
/// RFC 8617 §4 and §5.1 as Hermod's <see cref="ArcSealer"/> seals - Hermod's server never
/// calls it; a forwarder built on Hermod would. What it seals is validated by the suite's
/// own validator (<see cref="TestArc.Validate"/>).
/// </summary>
[TestFixture]
public sealed class ArcSealerTests
{

    private static String Message()

        => "From: <news@origin.example>\r\n" +
           "To: <list@forwarder.example>\r\n" +
           "Subject: sealed\r\n" +
           $"Message-ID: <{Guid.NewGuid():N}@origin.example>\r\n" +
           "Date: Thu, 19 Nov 2026 10:00:00 +0000\r\n" +
           "\r\n" +
           "Hello through a list.\r\n";

    private static ArcSealer Sealer(TestDkimKey Key, String? SignedHeaders = null)

        => new (SignedHeaders is null
                    ? new ArcConfig { Domain = Key.Domain, Selector = Key.Selector, PrivateKeyPem = Key.ExportPrivateKeyPem() }
                    : new ArcConfig { Domain = Key.Domain, Selector = Key.Selector, PrivateKeyPem = Key.ExportPrivateKeyPem(), SignedHeaders = SignedHeaders },
                new CapturingLogger());


    [Test(Description = "RFC 8617 §5.1: the first set - i=1, cv=none, an AMS without v=, an AS without h= - validates with the suite's validator")]
    public void A_first_seal_validates()
    {

        using var key    = new TestDkimKey("forwarder.example", "arc");
        using var rsa    = key.PublicKey();

        var sealed_      = Sealer(key).Seal(Message(), "forwarder.example", "spf=pass smtp.mailfrom=origin.example", ArcResult.None);
        var seal         = TestArc.Tags(TestArc.Header(sealed_, TestArc.AS).Single());
        var ams          = TestArc.Tags(TestArc.Header(sealed_, TestArc.AMS).Single());

        Assert.Multiple(() => {
            Assert.That(TestArc.Validate(sealed_, rsa),  Is.EqualTo(("pass", "1 ARC set(s)")));
            Assert.That(seal["i"],                       Is.EqualTo("1"));
            Assert.That(seal["cv"],                      Is.EqualTo("none"));
            Assert.That(seal.ContainsKey("h"),           Is.False, "§4.1.3: no h= in the AS");
            Assert.That(ams.ContainsKey("v"),            Is.False, "§4.1.2: no v= in the AMS");
        });

    }

    [Test(Description = "RFC 8617 §5.1: on a chain that passed, the next set has the next instance and cv=pass - and the chain still validates")]
    public void A_seal_on_a_passing_chain_says_cv_pass()
    {

        using var key    = new TestDkimKey("forwarder.example", "arc");
        using var rsa    = key.PublicKey();

        var received     = TestArc.Seal(TestArc.Seal(Message(), key), key);
        var sealed_      = Sealer(key).Seal(received, "relay.example", "arc=pass", ArcResult.Pass);
        var seal         = TestArc.Tags(TestArc.Header(sealed_, TestArc.AS).First(value => TestArc.InstanceOf(value) == 3));

        Assert.Multiple(() => {
            Assert.That(TestArc.Validate(sealed_, rsa).Status,  Is.EqualTo("pass"), TestArc.Validate(sealed_, rsa).Detail);
            Assert.That(seal["cv"],                             Is.EqualTo("pass"));
        });

    }

    [Test(Description = "RFC 8617 §5.1 step 2: with the most recent AS reporting cv=fail, \"there is no need to proceed and the algorithm stops here\" - no further set")]
    [Property("Finding", "A-4")]
    public void A_chain_that_failed_is_not_sealed_again()
    {

        using var key    = new TestDkimKey("forwarder.example", "arc");

        var received     = TestArc.Seal(TestArc.Seal(Message(), key), key, new TestArcSealOptions { Cv = "fail" });
        var sealed_      = Sealer(key).Seal(received, "relay.example", "arc=fail", ArcResult.Fail);

        Assert.That(TestArc.Header(sealed_, TestArc.AS), Has.Count.EqualTo(2), "the two sets it came with, no third");

    }

    [Test(Description = "RFC 8617 §4.1.2: in the AMS, \"ARC-related header fields (ARC-Authentication-Results, ARC-Message-Signature, and ARC-Seal) MUST NOT be included\" - not even when the configuration names them")]
    [Property("Finding", "A-5")]
    public void The_AMS_signs_no_ARC_header_field()
    {

        using var key    = new TestDkimKey("forwarder.example", "arc");

        var received     = TestArc.Seal(Message(), key);
        var sealed_      = Sealer(key, "from:to:subject:arc-seal:arc-message-signature:arc-authentication-results").
                               Seal(received, "relay.example", "arc=pass", ArcResult.Pass);
        var h            = TestArc.Tags(TestArc.Header(sealed_, TestArc.AMS).First(value => TestArc.InstanceOf(value) == 2))["h"];

        Assert.That(h.Split(':').Select(name => name.Trim().ToLowerInvariant()), Has.None.StartsWith("arc-"), "h=" + h);

    }


    [TestCase("to:subject", TestName = "A sealer configured without From signs From in the AMS all the same: to:subject")]
    [TestCase("",           TestName = "A sealer configured without From signs From in the AMS all the same: nothing configured")]
    [Description("RFC 8617 §4.1.2: the AMS \"is syntactically and semantically identical to a DKIM-Signature header field\", and RFC 6376 §5.4: \"The From header field MUST be signed (that is, included in the \"h=\" tag of the resulting DKIM-Signature header field)\" - whatever the configuration names")]
    [Property("Finding", "A-7")]
    public void A_sealer_configured_without_From_signs_From_all_the_same(String SignedHeaders)
    {

        using var key    = new TestDkimKey("forwarder.example", "arc");
        using var rsa    = key.PublicKey();

        var sealed_      = Sealer(key, SignedHeaders).Seal(Message(), "forwarder.example", "spf=pass smtp.mailfrom=origin.example", ArcResult.None);
        var h            = TestArc.Tags(TestArc.Header(sealed_, TestArc.AMS).Single())["h"];

        Assert.Multiple(() => {
            Assert.That(h.Split(':').Select(name => name.Trim().ToLowerInvariant()), Does.Contain("from"), "h=" + h);
            Assert.That(TestArc.Validate(sealed_, rsa), Is.EqualTo(("pass", "1 ARC set(s)")), sealed_);
        });

    }


    [Test(Description = "RFC 6376 §5.4: the AMS of the default configuration signs From (a guard for A-7)")]
    [Property("Finding", "A-7")]
    public void The_AMS_of_the_default_configuration_signs_From()
    {

        using var key    = new TestDkimKey("forwarder.example", "arc");

        var sealed_      = Sealer(key).Seal(Message(), "forwarder.example", "spf=pass smtp.mailfrom=origin.example", ArcResult.None);
        var h            = TestArc.Tags(TestArc.Header(sealed_, TestArc.AMS).Single())["h"];

        Assert.That(h.Split(':').Select(name => name.Trim().ToLowerInvariant()), Does.Contain("from"), "h=" + h);

    }

}
