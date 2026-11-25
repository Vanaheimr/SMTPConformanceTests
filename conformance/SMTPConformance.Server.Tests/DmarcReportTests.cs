using System.Net;
using System.Text.RegularExpressions;
using System.Xml.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 7489 §7 as Hermod's DMARC reporter writes reports: the aggregate report (§7.2, its
/// XML after Appendix C, its mail after §7.2.1.1), who may receive one (§7.1), and the
/// failure report (§7.3, RFC 6591). Driven through <see cref="DmarcReportService"/> directly -
/// the server feeds it the same evaluations - and read from the mail it queues.
/// </summary>
[TestFixture]
public sealed class DmarcReportTests
{

    #region Setup

    private static readonly IPAddress source = IPAddress.Parse("192.0.2.25");

    private sealed class Reporter : IDisposable
    {

        private readonly String           directory = Directory.CreateTempSubdirectory("dmarc-reports-").FullName;

        public  StubDnsClient             Dns    { get; } = new();
        public  CapturingMailQueue        Queue  { get; } = new();
        public  DmarcReportService        Service { get; }

        public Reporter()
        {
            var log  = new CapturingLogger();
            Service  = new DmarcReportService(new DmarcAggregator(Path.Combine(directory, "state.json"), log),
                                              Queue,
                                              new DNSVerifier(Dns, log),
                                              new DmarcReportingOptions("Hermod conformance", "DMARC Reports <dmarc-reports@mx.hermod.test>",
                                                                        "dmarc-reports@mx.hermod.test", "mx.hermod.test", TimeSpan.FromDays(1), EnableForensic: true),
                                              log);
        }

        /// <summary>
        /// Record the evaluations, send the aggregate reports, and return what was queued.
        /// </summary>
        public async Task<IReadOnlyList<QueuedMail>> Aggregate(params DmarcEvaluation[] Evaluations)
        {
            foreach (var evaluation in Evaluations)
                Service.RecordInbound(evaluation, source);
            await Service.GenerateAndSendAggregatesAsync(CancellationToken.None);
            return [ .. Queue.Queued ];
        }

        public void Authorize(String PolicyDomain, String DestinationDomain, String Record = "v=DMARC1")
        {
            var name = $"{PolicyDomain}._report._dmarc.{DestinationDomain}";
            Dns.Answer(name, DNSResourceRecordTypes.TXT, new TXT(DNSServiceName.Parse(name), DNSQueryClasses.IN, TimeSpan.FromHours(1), Record));
        }

        public void Dispose()
        {
            try { Directory.Delete(directory, recursive: true); } catch { }
        }

    }

    /// <summary>
    /// An evaluated message from policy.test under p=reject - by default one that passed on
    /// aligned SPF and DKIM.
    /// </summary>
    private static DmarcEvaluation Evaluation(String       Rua            = "mailto:dmarc@policy.test",
                                              String?      Ruf            = null,
                                              String?      Fo             = null,
                                              SPFResult    Spf            = SPFResult.Pass,
                                              Boolean      SpfAligned     = true,
                                              DkimResult   Dkim           = DkimResult.Pass,
                                              Boolean      DkimAligned    = true,
                                              DmarcResult  Result         = DmarcResult.Pass)

        => new ("policy.test", "policy.test", "reject", null, "reject", 100, false, false, Rua, Ruf, Fo,
                Spf, "policy.test", SpfAligned, Dkim, "policy.test", DkimAligned, Result,
                Result == DmarcResult.Fail ? DmarcDisposition.Reject : DmarcDisposition.None);

    private static XDocument Xml(QueuedMail Mail)
        => XDocument.Parse(ReportMail.Part(Mail.MessageContent, "application/gzip").Gunzipped());

    private static XElement? Element(XDocument Report, String Path)
        => Path.Split('/').Aggregate((XElement?) Report.Root, (element, name) => element?.Elements().FirstOrDefault(e => e.Name.LocalName == name));

    #endregion


    #region The aggregate report

    [Test(Description = "RFC 7489 §7.2.1.1: the report goes to the rua address, gzipped as application/gzip, its filename receiver \"!\" policy-domain \"!\" begin \"!\" end [\"!\" unique-id] \".\" extension, the extension \"xml.gz\"")]
    public async Task The_aggregate_report_is_a_gzipped_attachment_named_as_the_RFC_says()
    {

        using var reporter = new Reporter();

        var mail       = (await reporter.Aggregate(Evaluation())).Single();
        var attachment = ReportMail.Part(mail.MessageContent, "application/gzip");
        var filename   = ReportMail.Parameter(attachment.Headers.GetValueOrDefault("Content-Disposition") ?? "", "filename") ?? "";

        Assert.Multiple(() => {
            Assert.That(mail.EnvelopeTo,  Is.EqualTo(new[] { "dmarc@policy.test" }));
            Assert.That(filename,         Does.Match(@"^[^!]+!policy\.test!\d+!\d+(![^.!]+)?\.xml\.gz$"));
            Assert.That(() => Xml(mail),  Throws.Nothing, "a gzipped XML document");
        });

    }


    [Test(Description = "RFC 7489 §7.2.1.1: Subject: \"Report Domain:\" the policy domain \"Submitter:\" the reporter's domain")]
    public async Task The_subject_names_the_report_domain_and_the_submitter()
    {

        using var reporter = new Reporter();

        var mail = (await reporter.Aggregate(Evaluation())).Single();

        Assert.That(ReportMail.Headers(mail.MessageContent)["Subject"], Does.StartWith("Report Domain: policy.test Submitter: mx.hermod.test "));

    }


    [Test(Description = "RFC 7489 Appendix C: feedback, version 1.0 (\"MUST be the value 1.0\"), report_metadata, policy_published, and one record for two messages alike - with their count")]
    public async Task The_XML_has_the_report_of_Appendix_C()
    {

        using var reporter = new Reporter();

        var report = Xml((await reporter.Aggregate(Evaluation(), Evaluation())).Single());
        String? Value(String Path) => Element(report, Path)?.Value;

        Assert.Multiple(() => {
            Assert.That(report.Root?.Name.LocalName,                           Is.EqualTo("feedback"));
            Assert.That(Value("version"),                                      Is.EqualTo("1.0"));
            Assert.That(Value("report_metadata/org_name"),                     Is.EqualTo("Hermod conformance"));
            Assert.That(Value("report_metadata/email"),                        Is.EqualTo("dmarc-reports@mx.hermod.test"));
            Assert.That(Value("report_metadata/report_id"),                    Is.Not.Empty);
            Assert.That(Int64.Parse(Value("report_metadata/date_range/begin") ?? "x"),
                        Is.LessThanOrEqualTo(Int64.Parse(Value("report_metadata/date_range/end") ?? "x")));
            Assert.That(Value("policy_published/domain"),                      Is.EqualTo("policy.test"));
            Assert.That(Value("policy_published/p"),                           Is.EqualTo("reject"));
            Assert.That(Value("policy_published/pct"),                         Is.EqualTo("100"));
            Assert.That(report.Root!.Elements("record").Count(),               Is.EqualTo(1));
            Assert.That(Value("record/row/source_ip"),                         Is.EqualTo("192.0.2.25"));
            Assert.That(Value("record/row/count"),                             Is.EqualTo("2"));
            Assert.That(Value("record/row/policy_evaluated/disposition"),      Is.EqualTo("none"));
            Assert.That(Value("record/row/policy_evaluated/dkim"),             Is.EqualTo("pass"));
            Assert.That(Value("record/row/policy_evaluated/spf"),              Is.EqualTo("pass"));
            Assert.That(Value("record/identifiers/header_from"),               Is.EqualTo("policy.test"));
            Assert.That(Value("record/auth_results/spf/domain"),               Is.EqualTo("policy.test"));
            Assert.That(Value("record/auth_results/spf/result"),               Is.EqualTo("pass"));
        });

    }


    [TestCase("policy_published/sp",            TestName = "policy_published has sp")]
    [TestCase("policy_published/fo",            TestName = "policy_published has fo")]
    [TestCase("record/identifiers/envelope_from", TestName = "identifiers has envelope_from")]
    [TestCase("record/auth_results/spf/scope",  TestName = "spf has scope")]
    [Test(Description = "RFC 7489 Appendix C: PolicyPublishedType has sp and fo without minOccurs, IdentifierType envelope_from with minOccurs=\"1\", SPFAuthResultType scope with minOccurs=\"1\" - each required")]
    [Property("Finding", "R-1")]
    public async Task The_XML_has_every_element_the_schema_requires(String Path)
    {

        using var reporter = new Reporter();

        var report = Xml((await reporter.Aggregate(Evaluation())).Single());

        Assert.That(Element(report, Path), Is.Not.Null, report.ToString());

    }


    [Test(Description = "RFC 7489 §7.2.1.1: Report-ID is a msg-id (RFC 5322 §3.6.4): \"<\" id-left \"@\" id-right \">\"")]
    [Property("Finding", "R-3")]
    public async Task The_Report_ID_of_the_subject_is_a_msg_id()
    {

        using var reporter = new Reporter();

        var subject = ReportMail.Headers((await reporter.Aggregate(Evaluation())).Single().MessageContent)["Subject"];

        Assert.That(subject, Does.Match(@" Report-ID: <[^<>@\s]+@[^<>@\s]+>$"), subject);

    }

    #endregion

    #region Who receives it

    [Test(Description = "RFC 7489 §7.1: a destination outside the policy domain's organization receives reports only if it publishes <policy-domain>._report._dmarc.<destination> - without, none; with, one")]
    public async Task An_outside_destination_receives_reports_only_if_it_says_so()
    {

        using var without = new Reporter();
        using var with    = new Reporter();
        with.Authorize("policy.test", "reports.example");

        var refused   = await without.Aggregate(Evaluation(Rua: "mailto:dmarc@reports.example"));
        var accepted  = await with.   Aggregate(Evaluation(Rua: "mailto:dmarc@reports.example"));

        Assert.Multiple(() => {
            Assert.That(refused,                                     Is.Empty);
            Assert.That(accepted.Single().EnvelopeTo,                Is.EqualTo(new[] { "dmarc@reports.example" }));
        });

    }


    [Test(Description = "RFC 7489 §7.2.1: \"Any reporting URI that includes a size limitation exceeded by the generated report ... MUST NOT be used\" - rua=mailto:...!10 is ten octets")]
    [Property("Finding", "R-2")]
    public async Task A_destination_whose_size_limit_the_report_exceeds_receives_none()
    {

        using var reporter = new Reporter();

        var queued = await reporter.Aggregate(Evaluation(Rua: "mailto:dmarc@policy.test!10"));

        Assert.That(queued.Where(mail => mail.EnvelopeTo.Contains("dmarc@policy.test")), Is.Empty,
                    "a report of more than ten octets went to a destination that takes ten");

    }


    [Test(Description = "RFC 7489 §7.1: \"If a \"rua\" or \"ruf\" tag is thus discovered, replace the corresponding value extracted from the domain's DMARC policy record with the one found in this record\" - on the same host")]
    [Property("Finding", "R-4")]
    public async Task The_destinations_own_rua_replaces_the_policy_domains()
    {

        using var reporter = new Reporter();
        reporter.Authorize("policy.test", "reports.example", "v=DMARC1; rua=mailto:policy-test@reports.example");

        var queued = await reporter.Aggregate(Evaluation(Rua: "mailto:dmarc@reports.example"));

        Assert.That(queued.SelectMany(mail => mail.EnvelopeTo), Is.EqualTo(new[] { "policy-test@reports.example" }));

    }

    #endregion

    #region The failure report

    private static async Task<IReadOnlyList<QueuedMail>> FailureReport(Reporter Reporter, DmarcEvaluation Evaluation, IPAddress? Source = null, String EnvelopeFrom = "news@policy.test")
    {
        await Reporter.Service.SendForensicAsync(Evaluation, Source ?? source,
                                                 "From: <news@policy.test>\r\nTo: <alice@hermod.test>\r\nSubject: failed\r\n",
                                                 EnvelopeFrom,
                                                 "mx.hermod.test; dmarc=fail header.from=policy.test");
        return [ .. Reporter.Queue.Queued ];
    }


    [Test(Description = "RFC 7489 §7.3 / RFC 6591: a DMARC failure is reported to ruf as multipart/report; report-type=feedback-report with Feedback-Type: auth-failure and Auth-Failure: dmarc")]
    public async Task A_DMARC_failure_is_reported_in_the_ARF()
    {

        using var reporter = new Reporter();

        var mail     = (await FailureReport(reporter, Evaluation(Ruf: "mailto:ruf@policy.test", Spf: SPFResult.Fail, SpfAligned: false,
                                                                 Dkim: DkimResult.Fail, DkimAligned: false, Result: DmarcResult.Fail))).Single();
        var type     = ReportMail.Headers(mail.MessageContent)["Content-Type"];
        var feedback = ReportMail.Part(mail.MessageContent, "message/feedback-report").Text;

        Assert.Multiple(() => {
            Assert.That(mail.EnvelopeTo,                                   Is.EqualTo(new[] { "ruf@policy.test" }));
            Assert.That(type,                                              Does.StartWith("multipart/report"));
            Assert.That(ReportMail.Parameter(type, "report-type"),         Is.EqualTo("feedback-report"));
            Assert.That(feedback,                                          Does.Contain("Feedback-Type: auth-failure"));
            Assert.That(feedback,                                          Does.Contain("Auth-Failure: dmarc"));
        });

    }


    [TestCase("Identity-Alignment")]
    [TestCase("SPF-DNS")]
    [Test(Description = "RFC 7489 §7.3.1: in a DMARC failure report, \"Identity-Alignment (REQUIRED ...)\" and \"SPF-DNS (REQUIRED)\"")]
    [Property("Finding", "R-5")]
    public async Task The_failure_report_has_the_fields_RFC_7489_requires(String Field)
    {

        using var reporter = new Reporter();

        var mail     = (await FailureReport(reporter, Evaluation(Ruf: "mailto:ruf@policy.test", Spf: SPFResult.Fail, SpfAligned: false,
                                                                 Dkim: DkimResult.Fail, DkimAligned: false, Result: DmarcResult.Fail))).Single();
        var feedback = ReportMail.Part(mail.MessageContent, "message/feedback-report").Text;

        Assert.That(Regex.IsMatch(feedback, $@"^{Field}:", RegexOptions.Multiline | RegexOptions.IgnoreCase), Is.True, feedback);

    }


    [Test(Description = "RFC 7489 §6.3: fo=1 - \"Generate a DMARC failure report if any underlying authentication mechanism produced something other than an aligned \"pass\" result\" - DMARC passed on DKIM, SPF failed")]
    [Property("Finding", "R-6")]
    public async Task With_fo_1_a_failing_SPF_is_reported_although_DMARC_passed()
    {

        using var reporter = new Reporter();

        var queued = await FailureReport(reporter, Evaluation(Ruf: "mailto:ruf@policy.test", Fo: "1", Spf: SPFResult.Fail, SpfAligned: false));

        Assert.That(queued, Has.Count.EqualTo(1));

    }


    [Test(Description = "RFC 7489 §6.3: fo=0, the default - DMARC passed, so no failure report")]
    public async Task With_fo_0_a_message_that_passed_DMARC_is_not_reported()
    {

        using var reporter = new Reporter();

        var queued = await FailureReport(reporter, Evaluation(Ruf: "mailto:ruf@policy.test", Spf: SPFResult.Fail, SpfAligned: false));

        Assert.That(queued, Is.Empty);

    }

    #endregion


    #region R-8 to R-12: where a report goes, and what the failure report says of the message

    /// <summary>
    /// The lines of a message's header, split at CR LF, at a bare LF and at a bare CR - each
    /// a line end to some reader.
    /// </summary>
    private static IEnumerable<String> HeaderLines(String Message)
    {
        var end = Message.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        return Regex.Split(end >= 0 ? Message[..end] : Message, "\r\n|\r|\n");
    }

    private static DmarcEvaluation FailedEvaluation(String Ruf = "mailto:ruf@policy.test")
        => Evaluation(Ruf: Ruf, Spf: SPFResult.Fail, SpfAligned: false, Dkim: DkimResult.Fail, DkimAligned: false, Result: DmarcResult.Fail);

    private static async Task<String> FeedbackReport(DmarcEvaluation Evaluation, IPAddress? Source = null, String EnvelopeFrom = "news@policy.test")
    {
        using var reporter = new Reporter();
        var mail = (await FailureReport(reporter, Evaluation, Source, EnvelopeFrom)).Single();
        return ReportMail.Part(mail.MessageContent, "message/feedback-report").Text;
    }


    public static IEnumerable<TestCaseData> LineBreaksInReportUris()
    {

        TestCaseData Case(String Tag, String Name, String LineBreak)
            => new TestCaseData(Tag, LineBreak).SetName($"A line break in a {Tag} URI makes no recipient and no header field of the report: {Name}")
                                               .SetProperty("Finding", "R-8");

        yield return Case("rua", "CR LF", "\r\n");
        yield return Case("ruf", "CR LF", "\r\n");
        yield return Case("ruf", "LF",    "\n");

    }

    [TestCaseSource(nameof(LineBreaksInReportUris))]
    [Description("RFC 7489 §6.4: dmarc-uri = URI (RFC 3986), which has no CR and no LF; RFC 5322 §2.2: \"A field body MUST NOT include CR and LF except when used in 'folding' and 'unfolding'\" - the policy record is the sender's to publish, and \"mailto:dmarc@policy.test<CR><LF>Bcc: victim@policy.test\", taken for an address, is a Bcc field of the report and a recipient with a line break in it")]
    public async Task A_line_break_in_a_report_URI_makes_no_recipient_and_no_header_field(String Tag, String LineBreak)
    {

        using var reporter = new Reporter();

        var uri    = $"mailto:dmarc@policy.test{LineBreak}Bcc: victim@policy.test";
        var queued = Tag == "rua"
                         ? await reporter.Aggregate(Evaluation(Rua: uri))
                         : await FailureReport(reporter, FailedEvaluation(Ruf: uri));

        Assert.Multiple(() => {
            Assert.That(queued.SelectMany(mail => mail.EnvelopeTo),               Has.None.Matches<String>(address => address.IndexOfAny([ '\r', '\n' ]) >= 0), "a recipient with a line break in it");
            Assert.That(queued.SelectMany(mail => HeaderLines(mail.MessageContent)), Has.None.EqualTo("Bcc: victim@policy.test"));
        });

    }


    [TestCase("mailto:dmarc%21reports@policy.test",              "dmarc!reports@policy.test", TestName = "A percent-encoded character of a report URI is decoded")]
    [TestCase("mailto:dmarc@policy.test?subject=DMARC%20report", "dmarc@policy.test",         TestName = "The header fields of a report URI are no part of its address")]
    [Description("RFC 7489 §6.2: a comma or an exclamation point that is part of a DMARC URI \"MUST be encoded per Section 2.1 of [URI]\" - %2C and %21 - and a Mail Receiver \"MUST implement support for a \"mailto:\" URI\"; RFC 6068 §2: mailtoURI = \"mailto:\" [ to ] [ hfields ], to = addr-spec, its characters percent-encoded - the report goes to the address the URI names")]
    [Property("Finding", "R-9")]
    public async Task A_report_goes_to_the_address_its_URI_names(String Uri, String Address)
    {

        using var reporter = new Reporter();

        var queued = await reporter.Aggregate(Evaluation(Rua: Uri));

        Assert.That(queued.SelectMany(mail => mail.EnvelopeTo), Is.EqualTo(new[] { Address }));

    }


    [Test(Description = "RFC 7489 §6.2: a mailto URI of the usual kind, with a size limit - the report goes to its address; a guard for R-9")]
    public async Task A_report_URI_of_the_usual_kind_names_its_address()
    {

        using var reporter = new Reporter();

        var queued = await reporter.Aggregate(Evaluation(Rua: "mailto:dmarc+reports@policy.test!10m"));

        Assert.That(queued.SelectMany(mail => mail.EnvelopeTo), Is.EqualTo(new[] { "dmarc+reports@policy.test" }));

    }


    public static IEnumerable<TestCaseData> LineBreaksInSpfRecords()
    {

        TestCaseData Case(String Name, String LineBreak)
            => new TestCaseData(LineBreak).SetName($"A line break in the SPF record makes no field of the failure report: {Name}")
                                          .SetProperty("Finding", "R-10");

        yield return Case("CR LF", "\r\n");
        yield return Case("LF",    "\n");
        yield return Case("CR",    "\r");

    }

    [TestCaseSource(nameof(LineBreaksInSpfRecords))]
    [Description("RFC 6591 §4: spf-dns = \"SPF-DNS:\" [CFWS] ( \"txt\" / \"spf\" ) [CFWS] \":\" [CFWS] domain [CFWS] \":\" [CFWS] quoted-string [CFWS] CRLF, and a quoted-string (RFC 5322 §3.2.4) has no CR and no LF but in folding - the SPF record is the sender's to publish, and \"v=spf1 -all<CR><LF>Identity-Alignment: dkim, spf\", written as it is, is a field of the report that says both identities aligned - the escaped quote it ends with notwithstanding")]
    public async Task A_line_break_in_the_SPF_record_makes_no_field_of_the_failure_report(String LineBreak)
    {

        var feedback = await FeedbackReport(FailedEvaluation() with { SpfRecord = $"v=spf1 -all{LineBreak}Identity-Alignment: dkim, spf" });

        Assert.That(Regex.Split(feedback, "\r\n|\r|\n").Where(line => line.StartsWith("Identity-Alignment:", StringComparison.OrdinalIgnoreCase)),
                    Is.EqualTo(new[] { "Identity-Alignment: none" }), feedback);

    }


    [Test(Description = "RFC 6591 §4: SPF-DNS names the record type, the domain and the record as a quoted-string - an SPF record of the usual kind as it is; a guard for R-10")]
    public async Task An_SPF_record_of_the_usual_kind_is_the_quoted_string_of_SPF_DNS()
    {

        var feedback = await FeedbackReport(FailedEvaluation() with { SpfRecord = "v=spf1 ip4:192.0.2.0/24 -all" });

        Assert.That(Regex.Split(feedback, "\r\n"), Has.One.Matches<String>(line => Regex.IsMatch(line, @"^SPF-DNS:\s*txt\s*:\s*policy\.test\s*:\s*""v=spf1 ip4:192\.0\.2\.0/24 -all""\s*$")), feedback);

    }


    [Test(Description = "RFC 5965 §3.5: original-mail-from = \"Original-Mail-From:\" [CFWS] reverse-path [CFWS] CRLF; RFC 5321 §4.1.2: Reverse-path = Path / \"<>\", Path = \"<\" [ A-d-l \":\" ] Mailbox \">\" - the address in angle brackets")]
    [Property("Finding", "R-11")]
    public async Task Original_Mail_From_is_a_reverse_path()
    {

        var feedback = await FeedbackReport(FailedEvaluation());

        Assert.That(Regex.Split(feedback, "\r\n"), Has.One.EqualTo("Original-Mail-From: <news@policy.test>"), feedback);

    }


    [Test(Description = "RFC 5965 §3.5, RFC 5321 §4.1.2: the null reverse-path is \"<>\"; a guard for R-11")]
    public async Task For_a_null_reverse_path_Original_Mail_From_is_empty_angle_brackets()
    {

        var feedback = await FeedbackReport(FailedEvaluation(), EnvelopeFrom: "");

        Assert.That(Regex.Split(feedback, "\r\n"), Has.One.EqualTo("Original-Mail-From: <>"), feedback);

    }


    [Test(Description = "RFC 5965 §3.5: source-ip = \"Source-IP:\" [CFWS] ( IPv4-address-literal / IPv6-address-literal ) [CFWS] CRLF; RFC 5321 §4.1.3: IPv6-address-literal = \"IPv6:\" IPv6-addr")]
    [Property("Finding", "R-12")]
    public async Task An_IPv6_Source_IP_is_an_IPv6_address_literal()
    {

        var feedback = await FeedbackReport(FailedEvaluation(), IPAddress.Parse("2001:db8::25"));

        Assert.That(Regex.Split(feedback, "\r\n"), Has.One.EqualTo("Source-IP: IPv6:2001:db8::25"), feedback);

    }


    [Test(Description = "RFC 5965 §3.5, RFC 5321 §4.1.3: IPv4-address-literal = Snum 3(\".\" Snum); a guard for R-12")]
    public async Task An_IPv4_Source_IP_is_its_dotted_quad()
    {

        var feedback = await FeedbackReport(FailedEvaluation());

        Assert.That(Regex.Split(feedback, "\r\n"), Has.One.EqualTo("Source-IP: 192.0.2.25"), feedback);

    }

    #endregion

}
