using System.Text.Json;
using System.Text.RegularExpressions;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// RFC 8460 (SMTP TLS Reporting) as Hermod's relay reports: which TXT record names the
/// destinations (§3), the report mail (§5.3) and the JSON in it (§4.4). Driven through
/// <see cref="TlsRptReportService"/> directly - the outbound client feeds it the same events -
/// and read from the mail it queues.
/// </summary>
[TestFixture]
public sealed class TlsRptTests
{

    #region Setup

    private sealed class Reporter : IDisposable
    {

        private readonly String          directory = Directory.CreateTempSubdirectory("tlsrpt-").FullName;

        public  StubDnsClient            Dns       { get; } = new();
        public  CapturingMailQueue       Queue     { get; } = new();
        public  TlsRptReportService      Service   { get; }

        public Reporter()
        {
            var log  = new CapturingLogger();
            Service  = new TlsRptReportService(new TlsRptAggregator(Path.Combine(directory, "state.json"), log),
                                               new TlsRptResolver(Dns, log),
                                               Queue,
                                               new TlsRptReportingOptions("Hermod conformance", "TLS Reports <tls-reports@relay.hermod.test>",
                                                                          "tls-reports@relay.hermod.test", "relay.hermod.test",
                                                                          "mailto:postmaster@relay.hermod.test", TimeSpan.FromDays(1)),
                                               log);
        }

        public Reporter Publish(String Domain, params String[] Records)
        {
            var name = $"_smtp._tls.{Domain}";
            Dns.Answer(name, DNSResourceRecordTypes.TXT,
                       [ .. Records.Select(record => (IDNSResourceRecord) new TXT(DNSServiceName.Parse(name), DNSQueryClasses.IN, TimeSpan.FromHours(1), record)) ]);
            return this;
        }

        /// <summary>
        /// Two sessions to policy.test that went well under its MTA-STS policy, one whose
        /// certificate had expired; then the reports.
        /// </summary>
        public async Task<IReadOnlyList<QueuedMail>> Report()
        {
            Service.Record(new TlsRptEvent("policy.test", TlsRptPolicyType.Sts, "mx.policy.test", "192.0.2.25", "198.51.100.1", true,  null));
            Service.Record(new TlsRptEvent("policy.test", TlsRptPolicyType.Sts, "mx.policy.test", "192.0.2.25", "198.51.100.1", true,  null));
            Service.Record(new TlsRptEvent("policy.test", TlsRptPolicyType.Sts, "mx.policy.test", "192.0.2.25", "198.51.100.1", false, "certificate-expired"));
            await Service.GenerateAndSendAsync(CancellationToken.None);
            return [ .. Queue.Queued ];
        }

        public void Dispose()
        {
            try { Directory.Delete(directory, recursive: true); } catch { }
        }

    }

    private static JsonElement Json(QueuedMail Mail)
        => JsonDocument.Parse(ReportMail.Part(Mail.MessageContent, "application/tlsrpt+gzip").Gunzipped()).RootElement;

    #endregion


    #region The TLSRPT record (§3)

    [Test(Description = "RFC 8460 §3: rua= is one or more URIs, comma-separated, mailto: and https:; an unknown field is ignored - the report goes to the mailto address")]
    public async Task The_report_goes_to_the_mailto_address_of_the_record()
    {

        using var reporter = new Reporter().Publish("policy.test", "v=TLSRPTv1; rua=https://reports.policy.test/tlsrpt , mailto:tlsrpt@policy.test; ext=future");

        var queued = await reporter.Report();

        Assert.That(queued.Single().EnvelopeTo, Is.EqualTo(new[] { "tlsrpt@policy.test" }));

    }


    [Test(Description = "RFC 8460 §3: no record, no report")]
    public async Task Without_a_record_no_report()
    {
        using var reporter = new Reporter();
        Assert.That(await reporter.Report(), Is.Empty);
    }


    [TestCase("v=TLSRPTv1; rua=mailto:a@policy.test|v=TLSRPTv1; rua=mailto:b@policy.test",              TestName = "Two records: no report")]
    [TestCase("rua=mailto:a@policy.test; v=TLSRPTv1",                                                     TestName = "A record not beginning with v=TLSRPTv1: no report")]
    [TestCase("v=tlsrptv1; rua=mailto:a@policy.test",                                                     TestName = "A record with v=tlsrptv1 in lower case: no report")]
    [Test(Description = "RFC 8460 §3: \"records that do not begin with \"v=TLSRPTv1;\" are discarded\" (%s, case-sensitive); \"If the number of resulting records is not one, senders MUST assume the recipient domain does not implement TLSRPT\"")]
    [Property("Finding", "T-1")]
    public async Task A_domain_without_exactly_one_valid_record_gets_no_report(String Records)
    {

        using var reporter = new Reporter().Publish("policy.test", Records.Split('|'));

        Assert.That(await reporter.Report(), Is.Empty);

    }

    #endregion

    #region The report mail (§5.3)

    [Test(Description = "RFC 8460 §5.3: multipart/report; report-type=\"tlsrpt\", the report as application/tlsrpt+gzip; TLS-Report-Domain and TLS-Report-Submitter \"MUST be included\"; Subject \"Report Domain: ... Submitter: ... Report-ID: <...>\"")]
    public async Task The_report_mail_is_as_section_5_3_says()
    {

        using var reporter = new Reporter().Publish("policy.test", "v=TLSRPTv1; rua=mailto:tlsrpt@policy.test");

        var mail    = (await reporter.Report()).Single();
        var headers = ReportMail.Headers(mail.MessageContent);

        Assert.Multiple(() => {
            Assert.That(headers["Content-Type"],                                        Does.StartWith("multipart/report"));
            Assert.That(ReportMail.Parameter(headers["Content-Type"], "report-type"),   Is.EqualTo("tlsrpt"));
            Assert.That(() => ReportMail.Part(mail.MessageContent, "application/tlsrpt+gzip"), Throws.Nothing);
            Assert.That(headers.GetValueOrDefault("TLS-Report-Domain"),                 Is.EqualTo("policy.test"));
            Assert.That(headers.GetValueOrDefault("TLS-Report-Submitter"),              Is.EqualTo("relay.hermod.test"));
            Assert.That(headers["Subject"],                                             Does.Match(@"^Report Domain: policy\.test Submitter: relay\.hermod\.test Report-ID: <[^<>\s]+>$"));
        });

    }


    [Test(Description = "RFC 8460 §5.1: filename = sender \"!\" policy-domain \"!\" begin-timestamp \"!\" end-timestamp [ \"!\" unique-id ] \".\" extension - \"json.gz\" for gzip")]
    public async Task The_attachment_is_named_as_section_5_1_says()
    {

        using var reporter = new Reporter().Publish("policy.test", "v=TLSRPTv1; rua=mailto:tlsrpt@policy.test");

        var part     = ReportMail.Part((await reporter.Report()).Single().MessageContent, "application/tlsrpt+gzip");
        var filename = ReportMail.Parameter(part.Headers.GetValueOrDefault("Content-Disposition") ?? "", "filename");

        Assert.That(filename, Does.Match(@"^[^!]+!policy\.test!\d+!\d+(![^.!]+)?\.json\.gz$"));

    }

    #endregion

    #region The JSON (§4.4)

    [Test(Description = "RFC 8460 §4.4: organization-name, date-range (RFC 3339 date-times), contact-info, report-id; per policy: policy-type, policy-domain, summary, and the failures by result-type")]
    public async Task The_JSON_has_the_report_of_section_4_4()
    {

        using var reporter = new Reporter().Publish("policy.test", "v=TLSRPTv1; rua=mailto:tlsrpt@policy.test");

        var json    = Json((await reporter.Report()).Single());
        var policy  = json.GetProperty("policies")[0];
        var failure = policy.GetProperty("failure-details")[0];

        Assert.Multiple(() => {
            Assert.That(json.GetProperty("organization-name").GetString(),                               Is.EqualTo("Hermod conformance"));
            Assert.That(json.GetProperty("date-range").GetProperty("start-datetime").GetString(),        Does.Match(@"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)$"));
            Assert.That(json.GetProperty("date-range").GetProperty("end-datetime").GetString(),          Does.Match(@"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)$"));
            Assert.That(json.GetProperty("contact-info").GetString(),                                    Is.Not.Empty);
            Assert.That(json.GetProperty("report-id").GetString(),                                       Is.Not.Empty);
            Assert.That(policy.GetProperty("policy").GetProperty("policy-type").GetString(),             Is.EqualTo("sts"));
            Assert.That(policy.GetProperty("policy").GetProperty("policy-domain").GetString(),           Is.EqualTo("policy.test"));
            Assert.That(policy.GetProperty("summary").GetProperty("total-successful-session-count").GetInt64(), Is.EqualTo(2));
            Assert.That(policy.GetProperty("summary").GetProperty("total-failure-session-count").GetInt64(),    Is.EqualTo(1));
            Assert.That(failure.GetProperty("result-type").GetString(),                                  Is.EqualTo("certificate-expired"));
            Assert.That(failure.GetProperty("failed-session-count").GetInt64(),                          Is.EqualTo(1));
        });

    }


    [Test(Description = "RFC 8460 §4.4: the policy object has policy-type, policy-string, policy-domain and mx-host - none marked optional; policy-string the policy applied, a JSON array of strings")]
    [Property("Finding", "T-2")]
    public async Task Each_policy_says_which_policy_was_applied()
    {

        using var reporter = new Reporter().Publish("policy.test", "v=TLSRPTv1; rua=mailto:tlsrpt@policy.test");

        var policy = Json((await reporter.Report()).Single()).GetProperty("policies")[0].GetProperty("policy");

        Assert.That(policy.TryGetProperty("policy-string", out var text) && text.ValueKind == JsonValueKind.Array, Is.True, policy.ToString());

    }

    #endregion


    #region T-5 and T-6: where a report goes

    public static IEnumerable<TestCaseData> LineBreaksInRuaUris()
    {

        TestCaseData Case(String Name, String LineBreak)
            => new TestCaseData(LineBreak).SetName($"A line break in an rua URI makes no recipient and no header field of the report: {Name}")
                                          .SetProperty("Finding", "T-5");

        yield return Case("CR LF", "\r\n");
        yield return Case("LF",    "\n");

    }

    [TestCaseSource(nameof(LineBreaksInRuaUris))]
    [Description("RFC 8460 §3: rua is one or more URIs (RFC 3986), which have no CR and no LF; RFC 5322 §2.2: \"A field body MUST NOT include CR and LF except when used in 'folding' and 'unfolding'\" - the TLSRPT record is the recipient domain's to publish, and \"mailto:tlsrpt@policy.test<CR><LF>Bcc: victim@policy.test\", taken for an address, is a Bcc field of the report and a recipient with a line break in it")]
    public async Task A_line_break_in_an_rua_URI_makes_no_recipient_and_no_header_field(String LineBreak)
    {

        using var reporter = new Reporter().Publish("policy.test", $"v=TLSRPTv1; rua=mailto:tlsrpt@policy.test{LineBreak}Bcc: victim@policy.test");

        var queued = await reporter.Report();

        Assert.Multiple(() => {
            Assert.That(queued.SelectMany(mail => mail.EnvelopeTo), Has.None.Matches<String>(address => address.IndexOfAny([ '\r', '\n' ]) >= 0), "a recipient with a line break in it");
            Assert.That(queued.SelectMany(mail => Regex.Split(mail.MessageContent[..Math.Max(0, mail.MessageContent.IndexOf("\r\n\r\n", StringComparison.Ordinal))], "\r\n|\r|\n")),
                        Has.None.EqualTo("Bcc: victim@policy.test"));
        });

    }


    [TestCase("v=TLSRPTv1; rua=mailto:tls%21reports@policy.test",              "tls!reports@policy.test", TestName = "A percent-encoded character of an rua URI is decoded")]
    [TestCase("v=TLSRPTv1; rua=mailto:tlsrpt@policy.test?subject=TLS%20report", "tlsrpt@policy.test",      TestName = "The header fields of an rua URI are no part of its address")]
    [Description("RFC 8460 §3: \"In the case of \"mailto\", reports should be submitted to the specified email address [RFC6068]\"; RFC 6068 §2: mailtoURI = \"mailto:\" [ to ] [ hfields ], to = addr-spec, its characters percent-encoded - the report goes to the address the URI names")]
    [Property("Finding", "T-6")]
    public async Task A_report_goes_to_the_address_its_rua_URI_names(String Record, String Address)
    {

        using var reporter = new Reporter().Publish("policy.test", Record);

        var queued = await reporter.Report();

        Assert.That(queued.SelectMany(mail => mail.EnvelopeTo), Is.EqualTo(new[] { Address }));

    }

    #endregion

}
