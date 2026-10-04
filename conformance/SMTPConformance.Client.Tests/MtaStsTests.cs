using NUnit.Framework;

using SMTPConformance.Core;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// MTA-STS (RFC 8461) as Hermod's relay applies it: which MX hosts a policy allows.
/// </summary>
[TestFixture]
public sealed class MtaStsTests
{

    #region M-1: MX host validation

    public static IEnumerable<TestCaseData> MxPatterns()
    {

        TestCaseData Case(String Pattern, String MxHost, Boolean Matches, Boolean Open = false)
        {
            var testCase = new TestCaseData(Pattern, MxHost, Matches).SetName($"mx: {Pattern} {(Matches ? "matches" : "does not match")} {MxHost}");
            return Open ? testCase.SetCategory(TestCategories.KnownIssue) : testCase;
        }

        yield return Case("*.example.com",     "mail.example.com",      true);
        yield return Case("*.example.com",     "MAIL.Example.COM",      true);
        yield return Case("mail.example.com",  "mail.example.com",      true);
        yield return Case("*.example.com",     "example.com",           false, Open: true);
        yield return Case("*.example.com",     "foo.bar.example.com",   false, Open: true);
        yield return Case("*.example.com",     "mailexample.com",       false);
        yield return Case("mail.example.com",  "mail.example.com.evil", false);

    }

    [TestCaseSource(nameof(MxPatterns))]
    [Description("RFC 8461 §4.1: \"the wildcard character '*' may only be used to match the entire left-most label in the presented identifier. Thus, the mx pattern '*.example.com' matches 'mail.example.com' but not 'example.com' or 'foo.bar.example.com'\"")]
    [Property("Finding", "M-1")]
    public void An_mx_pattern_matches_as_RFC_8461_says(String Pattern, String MxHost, Boolean Matches)
    {

        var policy = new MtaStsPolicy { Mode = MtaStsMode.Enforce, MxPatterns = [ Pattern ], MaxAge = TimeSpan.FromDays(7) };

        Assert.That(policy.MatchesMx(MxHost), Is.EqualTo(Matches));

    }

    #endregion

}
