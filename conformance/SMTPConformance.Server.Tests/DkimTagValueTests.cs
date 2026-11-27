using System.Text;
using System.Text.RegularExpressions;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 6376 §3.5, §6.1.1: the values of the optional tags of a DKIM-Signature - t=, x=, l= and
/// q= - as <see cref="DNSVerifier.VerifyDkimAsync"/> reads them. §6.1.1: "Implementers MUST
/// meticulously validate the format and values in the DKIM-Signature header field; any
/// inconsistency or unexpected values MUST cause the header field to be completely ignored and
/// the Verifier to return PERMFAIL (signature syntax error)." Every signature here is made by
/// the suite's own signer, valid over what it says, the tag under test signed with the others.
/// </summary>
[TestFixture]
public sealed class DkimTagValueTests
{

    #region Setup

    private const String Author = "author.test";

    /// <summary>
    /// The t= the suite's signer wrote into the tags.
    /// </summary>
    private static Int64 TimestampOf(String Tags)
        => Int64.Parse(Regex.Match(Tags, @"(?:^|;)\s*t=(\d+)").Groups[1].Value);

    private static String WithTimestamp(String Tags, String Value)
    {
        var replaced = Regex.Replace(Tags, @"(^|;\s*)t=\d+", "${1}t=" + Value);
        Assert.That(replaced, Does.Contain("t=" + Value + ";"), replaced);
        return replaced;
    }

    private static async Task<(DkimResult Result, String? Details)> Verify(Func<String, String> Tags)
    {

        using var key = new TestDkimKey(Author);

        var dns = new StubDnsClient();
        dns.Answer(key.RecordName, DNSResourceRecordTypes.TXT, key.Record());

        var signed = key.Sign(DkimResultTests.Message(Author), Tags);

        var (result, details, _) = await new DNSVerifier(dns, new CapturingLogger()).VerifyDkimAsync(Encoding.UTF8.GetBytes(signed));
        return (result, details);

    }

    #endregion


    #region V-33: t= and x=

    private static IEnumerable<TestCaseData> TimestampsOfAnUnexpectedValue()
    {

        static TestCaseData Case(String Name, Func<String, String> Tags)
            => new TestCaseData(Tags).SetName($"A t= or x= of an unexpected value is a permanent error: {Name}")
                                     .SetProperty("Finding", "V-33");

        // sig-t-tag = %x74 [FWS] "=" [FWS] 1*12DIGIT; sig-x-tag the same.
        yield return Case("t=yesterday",              tags => WithTimestamp(tags, "yesterday"));
        yield return Case("t= without a value",       tags => WithTimestamp(tags, ""));
        yield return Case("t=-5",                     tags => WithTimestamp(tags, "-5"));
        yield return Case("x=tomorrow",               tags => tags + "; x=tomorrow");
        // "The value of the "x=" tag MUST be greater than the value of the "t=" tag if both are present."
        yield return Case("x= the same as t=",        tags => tags + $"; x={TimestampOf(tags)}");
        yield return Case("x= an hour before t=",     tags => tags + $"; x={TimestampOf(tags) - 3600}");

    }

    [TestCaseSource(nameof(TimestampsOfAnUnexpectedValue))]
    [Description("RFC 6376 §3.5: sig-t-tag and sig-x-tag are 1*12DIGIT, and \"The value of the \"x=\" tag MUST be greater than the value of the \"t=\" tag if both are present\"; §6.1.1: \"any inconsistency or unexpected values MUST cause the header field to be completely ignored and the Verifier to return PERMFAIL (signature syntax error)\"")]
    public async Task A_t_or_x_of_an_unexpected_value_is_a_permanent_error(Func<String, String> Tags)
    {

        var (result, details) = await Verify(Tags);

        Assert.That(result, Is.EqualTo(DkimResult.PermError), details);

    }


    [Test(Description = "RFC 6376 §3.5: a signature whose x= is a day after its t= verifies - a guard for V-33")]
    [Property("Finding", "V-33")]
    public async Task A_signature_that_expires_after_its_timestamp_passes()
    {

        var (result, details) = await Verify(tags => tags + $"; x={TimestampOf(tags) + 86400}");

        Assert.That(result, Is.EqualTo(DkimResult.Pass), details);

    }

    #endregion

    #region V-34: l=

    private static IEnumerable<TestCaseData> BodyLengthsOfAnUnexpectedValue()
    {

        static TestCaseData Case(String Name, String Value)
            => new TestCaseData(Value).SetName($"An l= of an unexpected value is a permanent error: {Name}")
                                      .SetProperty("Finding", "V-34");

        // sig-l-tag = %x6c [FWS] "=" [FWS] 1*76DIGIT.
        yield return Case("l=abc",                                 "abc");
        yield return Case("l=-1",                                  "-1");
        // "This value MUST NOT be larger than the actual number of octets in the canonicalized message body."
        yield return Case("l=1000, of a body of 8 octets",         "1000");

    }

    [TestCaseSource(nameof(BodyLengthsOfAnUnexpectedValue))]
    [Description("RFC 6376 §3.5: sig-l-tag is 1*76DIGIT, and l= \"MUST NOT be larger than the actual number of octets in the canonicalized message body\"; §6.1.1: \"any inconsistency or unexpected values MUST cause the header field to be completely ignored and the Verifier to return PERMFAIL (signature syntax error)\"")]
    public async Task An_l_of_an_unexpected_value_is_a_permanent_error(String Value)
    {

        var (result, details) = await Verify(tags => tags + "; l=" + Value);

        Assert.That(result, Is.EqualTo(DkimResult.PermError), details);

    }


    [Test(Description = "RFC 6376 §3.5, §3.7: a signature whose l= is the length of the canonicalized body - \"Hello.\" and CRLF, 8 octets - verifies - a guard for V-34")]
    [Property("Finding", "V-34")]
    public async Task A_signature_whose_l_is_the_length_of_the_body_passes()
    {

        var (result, details) = await Verify(tags => tags + "; l=8");

        Assert.That(result, Is.EqualTo(DkimResult.Pass), details);

    }

    #endregion

    #region V-35: q=

    private static IEnumerable<TestCaseData> QueryMethodsTheVerifierDoesNotKnow()
    {

        static TestCaseData Case(String Name, String Value)
            => new TestCaseData(Value).SetName($"A q= without a query method the verifier knows is a permanent error: {Name}")
                                      .SetProperty("Finding", "V-35");

        // sig-q-tag = %x71 [FWS] "=" [FWS] sig-q-tag-method *([FWS] ":" [FWS] sig-q-tag-method).
        yield return Case("q= without a value",                    "");
        // "The only option defined for the "dns" query type is "txt", which MUST be included."
        yield return Case("q=dns, without the option txt",         "dns");
        // "Unrecognized query mechanisms MUST be ignored" - and none is left.
        yield return Case("q=foo/bar, a method of no one",         "foo/bar");

    }

    [TestCaseSource(nameof(QueryMethodsTheVerifierDoesNotKnow))]
    [Description("RFC 6376 §3.5, q=: \"Currently, the only valid value is \"dns/txt\"\"; \"The only option defined for the \"dns\" query type is \"txt\", which MUST be included\"; \"Unrecognized query mechanisms MUST be ignored\" - a signature that names no query method the verifier knows tells it no way to its key, and §6.1.1: \"unexpected values MUST cause the header field to be completely ignored and the Verifier to return PERMFAIL (signature syntax error)\"")]
    public async Task A_q_without_a_query_method_the_verifier_knows_is_a_permanent_error(String Value)
    {

        var (result, details) = await Verify(tags => tags + "; q=" + Value);

        Assert.That(result, Is.EqualTo(DkimResult.PermError), details);

    }


    [TestCase("dns/txt",         TestName = "A q= with dns/txt passes: q=dns/txt")]
    [TestCase("foo/bar:dns/txt", TestName = "A q= with dns/txt passes: an unknown method before it")]
    [Description("RFC 6376 §3.5, q=: \"Verifiers and Signers MUST support \"dns/txt\"\", and \"Unrecognized query mechanisms MUST be ignored\" - a guard for V-35")]
    [Property("Finding", "V-35")]
    public async Task A_q_with_dns_txt_passes(String Value)
    {

        var (result, details) = await Verify(tags => tags + "; q=" + Value);

        Assert.That(result, Is.EqualTo(DkimResult.Pass), details);

    }

    #endregion

}
