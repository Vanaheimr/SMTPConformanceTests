using System.Net;
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core.Fixtures;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// The Policy Host of a Policy Domain (RFC 8461 §3.2): answers
/// https://mta-sts.&lt;domain&gt;/.well-known/mta-sts.txt as a test tells it, through the
/// HTTP handler hook of <see cref="MtaStsResolver"/> and <see cref="SmtpOutboundConfig"/>.
/// </summary>
internal sealed class MtaStsPolicyHost(String PolicyDomain) : HttpMessageHandler
{

    public const String EnforcePolicy = "version: STSv1\r\nmode: enforce\r\nmx: mail.{0}\r\nmx: *.mx.{0}\r\nmax_age: 604800\r\n";

    public volatile String  Policy        = String.Format(EnforcePolicy, PolicyDomain);
    public volatile String  ContentType   = "text/plain";
    public HttpStatusCode   Status        = HttpStatusCode.OK;
    public Uri?             RedirectedTo;
    public Int32            Requests;

    public Uri PolicyUrl
        => new ($"https://mta-sts.{PolicyDomain}/.well-known/mta-sts.txt");

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage Request, CancellationToken CancellationToken)
    {

        Interlocked.Increment(ref Requests);

        if (Request.RequestUri != PolicyUrl)
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound) { RequestMessage = Request });

        var response = new HttpResponseMessage(Status) { Content = new StringContent(Policy, Encoding.UTF8, ContentType) };

        if ((Int32) Status is >= 300 and < 400)
            response.Headers.Location = new Uri("https://elsewhere.test/policy.txt");

        // As a handler that follows redirects hands the answer back: from where it ended up.
        response.RequestMessage = RedirectedTo is not null
                                      ? new HttpRequestMessage(HttpMethod.Get, RedirectedTo)
                                      : Request;

        return Task.FromResult(response);

    }

    /// <summary>
    /// The _mta-sts TXT records of the Policy Domain (RFC 8461 §3.1).
    /// </summary>
    public static void Announce(StubDnsClient Dns, String PolicyDomain, params String[] Txt)
        => Dns.Answer($"_mta-sts.{PolicyDomain}", DNSResourceRecordTypes.TXT,
                      [.. Txt.Select(text => new TXT(DomainName.ParseLenient($"_mta-sts.{PolicyDomain}"), DNSQueryClasses.IN, TimeSpan.FromHours(1), text))]);

}


/// <summary>
/// MTA-STS (RFC 8461) as Hermod's relay applies it: which MX hosts a policy allows, which TXT
/// records and policies count, and how a policy is fetched and kept.
/// </summary>
[TestFixture]
public sealed class MtaStsTests
{

    private const String Domain = "outbound.test";

    private static async Task<MtaStsPolicy> PolicyFor(String[] Txt, MtaStsPolicyHost Host)
    {

        var dns = new StubDnsClient();
        MtaStsPolicyHost.Announce(dns, Domain, Txt);

        using var resolver = new MtaStsResolver(dns, new CapturingLogger(), Host);
        return await resolver.GetPolicyAsync(Domain);

    }

    private static Task<MtaStsPolicy> PolicyFor(MtaStsPolicyHost Host)
        => PolicyFor([ "v=STSv1; id=20261004;" ], Host);


    #region M-1: MX host validation

    public static IEnumerable<TestCaseData> MxPatterns()
    {

        TestCaseData Case(String Pattern, String MxHost, Boolean Matches)
            => new TestCaseData(Pattern, MxHost, Matches).SetName($"mx: {Pattern} {(Matches ? "matches" : "does not match")} {MxHost}");

        yield return Case("*.example.com",     "mail.example.com",      true);
        yield return Case("*.example.com",     "MAIL.Example.COM",      true);
        yield return Case("mail.example.com",  "mail.example.com",      true);
        yield return Case("*.example.com",     "example.com",           false);
        yield return Case("*.example.com",     "foo.bar.example.com",   false);
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

    #region M-2: the TXT record

    public static IEnumerable<TestCaseData> TxtRecords()
    {

        TestCaseData Case(String Name, MtaStsMode Mode, params String[] Txt)
            => new TestCaseData(Txt, Mode).SetName($"TXT: {Name}");

        yield return Case("a valid record",                     MtaStsMode.Enforce, "v=STSv1; id=20261004;");
        yield return Case("a record of another kind beside it", MtaStsMode.Enforce, "v=STSv1; id=20261004", "google-site-verification=abc");
        yield return Case("not beginning with v=STSv1",         MtaStsMode.None,    "id=20261004; v=STSv1;");
        yield return Case("another version",                    MtaStsMode.None,    "v=STSv10; id=20261004;");
        yield return Case("two records",                        MtaStsMode.None,    "v=STSv1; id=20261004;", "v=STSv1; id=20261005;");
        yield return Case("no id",                              MtaStsMode.None,    "v=STSv1;");
        yield return Case("an id with a dash",                  MtaStsMode.None,    "v=STSv1; id=2026-10-04;");

    }

    [TestCaseSource(nameof(TxtRecords))]
    [Description("RFC 8461 §3.1: records not beginning with \"v=STSv1;\" are discarded; \"If the number of resulting records is not one, or if the resulting record is syntactically invalid, senders MUST assume the recipient domain does not have an available MTA-STS Policy\"")]
    [Property("Finding", "M-2")]
    public async Task Only_one_valid_TXT_record_announces_a_policy(String[] Txt, MtaStsMode Mode)
    {
        Assert.That((await PolicyFor(Txt, new MtaStsPolicyHost(Domain))).Mode, Is.EqualTo(Mode));
    }

    #endregion

    #region M-3: the policy

    public static IEnumerable<TestCaseData> Policies()
    {

        TestCaseData Case(String Name, MtaStsMode Mode, String Policy)
            => new TestCaseData(Policy, Mode).SetName($"Policy: {Name}");

        yield return Case("LF line ends, an unknown field", MtaStsMode.Testing, "version: STSv1\nmode: testing\nmx: mail.outbound.test\nmax_age: 86400\nfoo: bar\n");
        yield return Case("mode none needs no mx",          MtaStsMode.None,    "version: STSv1\r\nmode: none\r\nmax_age: 86400\r\n");
        yield return Case("a repeated field counts first",  MtaStsMode.Enforce, "version: STSv1\r\nmode: enforce\r\nmode: none\r\nmx: mail.outbound.test\r\nmax_age: 86400\r\n");
        yield return Case("no version",                     MtaStsMode.None,    "mode: enforce\r\nmx: mail.outbound.test\r\nmax_age: 86400\r\n");
        yield return Case("no max_age",                     MtaStsMode.None,    "version: STSv1\r\nmode: enforce\r\nmx: mail.outbound.test\r\n");
        yield return Case("enforce without mx",             MtaStsMode.None,    "version: STSv1\r\nmode: enforce\r\nmax_age: 86400\r\n");

    }

    [TestCaseSource(nameof(Policies))]
    [Description("RFC 8461 §3.2: version, mode and max_age \"required once\", mx \"required at least once, except when mode is 'none'\"; of a repeated field \"all entries except for the first SHALL be ignored\"; unknown fields are ignored")]
    [Property("Finding", "M-3")]
    public async Task Only_a_valid_policy_counts(String Policy, MtaStsMode Mode)
    {
        Assert.That((await PolicyFor(new MtaStsPolicyHost(Domain) { Policy = Policy })).Mode, Is.EqualTo(Mode));
    }


    [Test(Description = "RFC 8461 §3.2: \"senders SHOULD validate that the media type is 'text/plain'\"")]
    [Property("Finding", "M-3")]
    public async Task A_policy_that_is_not_text_plain_does_not_count()
    {
        Assert.That((await PolicyFor(new MtaStsPolicyHost(Domain) { ContentType = "text/html" })).Mode, Is.EqualTo(MtaStsMode.None));
    }


    [Test(Description = "RFC 8461 §3.2: max_age is at most 31557600 seconds")]
    [Property("Finding", "M-3")]
    public async Task A_max_age_above_a_year_is_a_year()
    {

        var host = new MtaStsPolicyHost(Domain);
        host.Policy = host.Policy.Replace("604800", "9999999999");

        Assert.That((await PolicyFor(host)).MaxAge, Is.EqualTo(TimeSpan.FromSeconds(31_557_600)));

    }

    #endregion

    #region M-4: redirects

    [Test(Description = "RFC 8461 §3.3: \"Policies fetched via HTTPS are only valid if the HTTP response code is 200 (OK). HTTP 3xx redirects MUST NOT be followed\" - a guard: a 301 itself")]
    [Property("Finding", "M-4")]
    public async Task A_redirect_is_not_a_policy()
    {
        Assert.That((await PolicyFor(new MtaStsPolicyHost(Domain) { Status = HttpStatusCode.MovedPermanently })).Mode, Is.EqualTo(MtaStsMode.None));
    }


    [Test(Description = "RFC 8461 §3.3: \"HTTP 3xx redirects MUST NOT be followed\" - a policy that a handler fetched by following one is not taken")]
    [Property("Finding", "M-4")]
    public async Task A_policy_reached_through_a_redirect_is_not_taken()
    {
        Assert.That((await PolicyFor(new MtaStsPolicyHost(Domain) { RedirectedTo = new Uri("https://elsewhere.test/policy.txt") })).Mode,
                    Is.EqualTo(MtaStsMode.None));
    }

    #endregion

    #region M-5: a new policy is looked for

    [Test(Description = "RFC 8461 §3, §5: a new id in the TXT record means a new policy - fetched then, not when the cached one's max_age has passed; the same id is not fetched again")]
    [Property("Finding", "M-5")]
    public async Task A_new_policy_id_fetches_the_new_policy()
    {

        var dns  = new StubDnsClient();
        var host = new MtaStsPolicyHost(Domain);
        using var resolver = new MtaStsResolver(dns, new CapturingLogger(), host);

        MtaStsPolicyHost.Announce(dns, Domain, "v=STSv1; id=20261004;");
        var first = await resolver.GetPolicyAsync(Domain);
        var again = await resolver.GetPolicyAsync(Domain);

        MtaStsPolicyHost.Announce(dns, Domain, "v=STSv1; id=20261005;");
        host.Policy = "version: STSv1\r\nmode: none\r\nmax_age: 86400\r\n";
        var updated = await resolver.GetPolicyAsync(Domain);

        Assert.Multiple(() => {
            Assert.That(first.Mode,     Is.EqualTo(MtaStsMode.Enforce));
            Assert.That(again.Mode,     Is.EqualTo(MtaStsMode.Enforce));
            Assert.That(updated.Mode,   Is.EqualTo(MtaStsMode.None), "the policy of id 20261005");
            Assert.That(host.Requests,  Is.EqualTo(2),               "the same id is not fetched twice");
        });

    }


    [Test(Description = "RFC 8461 §3.3: \"if no 'live' policy can be discovered via DNS or fetched via HTTPS, but a valid (non-expired) policy exists in the sender's cache, the sender MUST apply that cached policy\"")]
    [Property("Finding", "M-5")]
    public async Task The_cached_policy_applies_when_no_live_one_can_be_had()
    {

        var dns  = new StubDnsClient();
        var host = new MtaStsPolicyHost(Domain);
        using var resolver = new MtaStsResolver(dns, new CapturingLogger(), host);

        MtaStsPolicyHost.Announce(dns, Domain, "v=STSv1; id=20261004;");
        await resolver.GetPolicyAsync(Domain);

        MtaStsPolicyHost.Announce(dns, Domain, "v=STSv1; id=20261005;");
        host.Status = HttpStatusCode.InternalServerError;
        var fetchFails = await resolver.GetPolicyAsync(Domain);

        MtaStsPolicyHost.Announce(dns, Domain);
        var noTxt = await resolver.GetPolicyAsync(Domain);

        Assert.Multiple(() => {
            Assert.That(fetchFails.Mode, Is.EqualTo(MtaStsMode.Enforce));
            Assert.That(noTxt.Mode,      Is.EqualTo(MtaStsMode.Enforce));
        });

    }

    #endregion

}
