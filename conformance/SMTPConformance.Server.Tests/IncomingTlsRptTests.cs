using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;
using org.GraphDefined.Vanaheimr.Hermod.SMTP.Server;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 8460 from the other end: the TLS reports other sending MTAs deliver to the rua
/// mailbox of a domain of this server, as Hermod's server reads them when
/// <c>EnableTlsRptIngestion</c> is on - the mail of §5.3 (multipart/report,
/// report-type="tlsrpt", application/tlsrpt+gzip or +json), its MIME (RFC 2045, RFC 2046,
/// RFC 2049) and the JSON of §4.4. Sent over the wire to the MTA port; what was read shows
/// in the server's log - "TLS-RPT report ingested from ..." with the counts - and the
/// reports it keeps. Hostile input too: a gzip bomb, deep JSON, broken gzip.
/// </summary>
[TestFixture]
public sealed class IncomingTlsRptTests : HermodServerTestBase
{

    protected override HermodSmtpServerFixtureOptions Options
        => new() { EnableTlsRptIngestion = true };


    #region Setup

    /// <summary>
    /// The JSON of RFC 8460 §4.4, with the values of the example in Appendix B: one MTA-STS
    /// policy, 5326 sessions that went well, 303 that did not - 100 of them for an expired
    /// certificate.
    /// </summary>
    private static String Json(String Organization)

        => $$"""
             {"organization-name":"{{Organization}}","date-range":{"start-datetime":"2016-04-01T00:00:00Z","end-datetime":"2016-04-01T23:59:59Z"},"contact-info":"sts-reporting@company-x.example","report-id":"5065427c-23d3-47ca-b6e0-946ea0e8c4be","policies":[{"policy":{"policy-type":"sts","policy-string":["version: STSv1","mode: testing","mx: *.mail.company-y.example","max_age: 86400"],"policy-domain":"company-y.example","mx-host":["*.mail.company-y.example"]},"summary":{"total-successful-session-count":5326,"total-failure-session-count":303},"failure-details":[{"result-type":"certificate-expired","sending-mta-ip":"2001:db8:abcd:0012::1","receiving-mx-hostname":"mx1.mail.company-y.example","failed-session-count":100},{"result-type":"starttls-not-supported","sending-mta-ip":"2001:db8:abcd:0013::1","receiving-mx-hostname":"mx2.mail.company-y.example","receiving-ip":"203.0.113.56","failed-session-count":200,"additional-information":"https://reports.company-x.example/report_info?id=5065427c-23d3#StarttlsNotSupported"},{"result-type":"validation-failure","sending-mta-ip":"198.51.100.62","receiving-ip":"203.0.113.58","receiving-mx-hostname":"mx-backup.mail.company-y.example","failed-session-count":3,"failure-reason-code":"X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED"}]}]}
             """;

    /// <summary>
    /// The report mail of RFC 8460 §5.3.1: multipart/report, report-type="tlsrpt", its
    /// Content-Type folded as in the example, a text/plain part and the report part.
    /// </summary>
    private static String Mail(String ReportPart, String Preamble = "This is a multipart message in MIME format.\r\n")

        => "From: tlsrpt@mail.sender.example\r\n" +
           "To: tlsrpt@hermod.test\r\n" +
           "Date: Fri, 09 May 2017 16:54:30 -0800\r\n" +
           $"Message-ID: <{Guid.NewGuid():N}@mail.sender.example>\r\n" +
           "Subject: Report Domain: hermod.test\r\n" +
           "    Submitter: mail.sender.example\r\n" +
           "    Report-ID: <735ff.e317+bf22029@mail.sender.example>\r\n" +
           "TLS-Report-Domain: hermod.test\r\n" +
           "TLS-Report-Submitter: mail.sender.example\r\n" +
           "MIME-Version: 1.0\r\n" +
           "Content-Type: multipart/report; report-type=\"tlsrpt\";\r\n" +
           "    boundary=\"----=_NextPart_000_024E_01CC9B0A.AFE54C00\"\r\n" +
           "\r\n" +
           Preamble +
           "\r\n" +
           "------=_NextPart_000_024E_01CC9B0A.AFE54C00\r\n" +
           "Content-Type: text/plain; charset=\"us-ascii\"\r\n" +
           "Content-Transfer-Encoding: 7bit\r\n" +
           "\r\n" +
           "This is an aggregate TLS report from mail.sender.example\r\n" +
           "\r\n" +
           "------=_NextPart_000_024E_01CC9B0A.AFE54C00\r\n" +
           ReportPart + "\r\n" +
           "------=_NextPart_000_024E_01CC9B0A.AFE54C00--\r\n";

    private static String GzipPart(Byte[] Gzipped)

        => "Content-Type: application/tlsrpt+gzip\r\n" +
           "Content-Transfer-Encoding: base64\r\n" +
           "Content-Disposition: attachment;\r\n" +
           "    filename=\"mail.sender.example!hermod.test!1459468800!1459555199.json.gz\"\r\n" +
           "\r\n" +
           Convert.ToBase64String(Gzipped, Base64FormattingOptions.InsertLineBreaks).Replace("\r\n", "\r\n").TrimEnd() + "\r\n";

    private static Byte[] Gzip(String Text)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
            gzip.Write(Encoding.UTF8.GetBytes(Text));
        return output.ToArray();
    }

    /// <summary>
    /// Quoted-printable (RFC 2045 §6.7): "=" as =3D, lines of at most 76 characters ending
    /// in a soft line break "=".
    /// </summary>
    private static String QuotedPrintable(String Text)
    {

        var output = new StringBuilder();
        var line   = 0;

        foreach (var c in Text)
        {
            var encoded = c == '=' ? "=3D" : c.ToString();
            if (line + encoded.Length > 75)
            {
                output.Append("=\r\n");
                line = 0;
            }
            output.Append(encoded);
            line += encoded.Length;
        }

        return output.ToString();

    }

    /// <summary>
    /// Send the report mail to tlsrpt@hermod.test; the final reply.
    /// </summary>
    private async Task<(SmtpReply Reply, RawSmtpClient Client)> SendAsync(String Message)
    {
        var client = await Server.ConnectAndEhloAsync("mail.sender.example");
        return (await client.SendMailAsync("tlsrpt@mail.sender.example", "tlsrpt@hermod.test", Message), client);
    }

    /// <summary>
    /// The log line that says the report of this organization was read - null if none came.
    /// </summary>
    private async Task<String?> IngestedAsync(String Organization, TimeSpan? Timeout = null)
    {

        var deadline = DateTime.UtcNow + (Timeout ?? TimeSpan.FromSeconds(5));

        while (true)
        {

            if (Server.Log.Lines.FirstOrDefault(line => line.Contains($"TLS-RPT report ingested from {Organization}:", StringComparison.Ordinal)) is { } found)
                return found;

            if (DateTime.UtcNow >= deadline)
                return null;

            await Task.Delay(20);

        }

    }

    private String ReceivedDirectory
        => Path.Combine(Server.Config.MailStoragePath, "tls-reports-received");

    #endregion


    #region The report mail

    [Test(Description = "RFC 8460 §5.3: multipart/report; report-type=\"tlsrpt\" with the report as \"application/tlsrpt+gzip\", base64, as the example of §5.3.1 - read: the counts of the summary and the failure-details of §4.4")]
    public async Task A_gzipped_report_as_the_example_of_5_3_1_is_read()
    {

        var organization          = Marker();
        var (reply, client)       = await SendAsync(Mail(GzipPart(Gzip(Json(organization)))));
        await using var _client   = client;
        var ingested              = await IngestedAsync(organization);

        Assert.That(reply.Code, Is.EqualTo(250), Explain(client));
        Assert.That(ingested,   Is.Not.Null, Explain(client));
        Assert.Multiple(() => {
            Assert.That(ingested,                                     Does.Contain(": 5326 successful, 303 failed session(s) across 1 policy block(s)"));
            Assert.That(Server.Log.Lines,                             Has.Some.Contains("[sts company-y.example]: certificate-expired × 100 (mx=mx1.mail.company-y.example, from=2001:db8:abcd:0012::1)"));
            Assert.That(Server.Log.Lines,                             Has.Some.Contains("[sts company-y.example]: validation-failure × 3 (mx=mx-backup.mail.company-y.example, from=198.51.100.62)"));
            Assert.That(Directory.GetFiles(ReceivedDirectory, $"*{organization}*.json"), Has.Length.EqualTo(1), "the report is kept");
        });

    }


    [Test(Description = "RFC 8460 §5.3: \"the second part is machine readable with a new media type defined called \"application/tlsrpt+json\"\" - an uncompressed report, 7bit in lines of its own, is read too")]
    public async Task An_uncompressed_report_is_read()
    {

        var organization          = Marker();
        var (reply, client)       = await SendAsync(Mail("Content-Type: application/tlsrpt+json\r\n\r\n" + Json(organization).Replace(",\"", ",\r\n \"") + "\r\n"));
        await using var _client   = client;

        Assert.That(reply.Code, Is.EqualTo(250), Explain(client));
        Assert.That(await IngestedAsync(organization) ?? "no report read", Does.Contain(": 5326 successful, 303 failed session(s)"), Explain(client));

    }


    [Test(Description = "RFC 8460 §5.3: application/tlsrpt+json; RFC 2049 §2: a MIME-conformant agent MUST \"decode all received data encoded by either quoted-printable or base64\" - a report in quoted-printable (its one JSON line is longer than the 998 octets RFC 5322 §2.1.1 allows, so it must be encoded) is read")]
    [Category(TestCategories.KnownIssue), Property("Finding", "I-3")]
    public async Task A_quoted_printable_report_is_read()
    {

        var organization          = Marker();
        var (reply, client)       = await SendAsync(Mail("Content-Type: application/tlsrpt+json\r\n" +
                                                         "Content-Transfer-Encoding: quoted-printable\r\n" +
                                                         "\r\n" +
                                                         QuotedPrintable(Json(organization)) + "\r\n"));
        await using var _client   = client;

        Assert.That(reply.Code, Is.EqualTo(250), Explain(client));
        Assert.That(await IngestedAsync(organization) ?? "no report read", Does.Contain(": 5326 successful, 303 failed session(s)"), Explain(client));

    }


    [Test(Description = "RFC 2046 §5.1.1: multipart-body := [preamble CRLF] dash-boundary ..., preamble := discard-text; \"implementations must ignore anything that appears before the first boundary delimiter line\" - a report written into the preamble is not the report")]
    [Category(TestCategories.KnownIssue), Property("Finding", "I-7")]
    public async Task The_preamble_is_not_read_as_a_report()
    {

        var organization          = Marker();
        var forged                = Marker();
        var (reply, client)       = await SendAsync(Mail(GzipPart(Gzip(Json(organization))),
                                                         Preamble: "Content-Type: application/tlsrpt+json\r\n\r\n" + Json(forged).Replace("5326", "1") + "\r\n"));
        await using var _client   = client;

        var real                  = await IngestedAsync(organization);
        var preamble              = await IngestedAsync(forged, TimeSpan.FromSeconds(1));

        Assert.That(reply.Code, Is.EqualTo(250), Explain(client));
        Assert.Multiple(() => {
            Assert.That(real,     Is.Not.Null, "the report in the report part is read");
            Assert.That(preamble, Is.Null,     "the one in the preamble is not");
        });

    }


    [Test(Description = "RFC 8460 §4.4: the JSON report - organization-name, date-range (RFC 3339), contact-info, report-id, policies with policy-type, policy-domain, mx-host, the summary's two counts and each failure-details entry - read field for field (TlsRptIngestor.Ingest, as the server calls it)")]
    public void The_fields_of_4_4_are_read()
    {

        var directory = Directory.CreateTempSubdirectory("tlsrpt-received-").FullName;

        try
        {

            var report = new TlsRptIngestor(directory, new CapturingLogger()).Ingest(EMailMessage.Parse(Mail(GzipPart(Gzip(Json("Company-X"))))));

            Assert.That(report, Is.Not.Null);
            Assert.Multiple(() => {
                Assert.That(report!.OrganizationName,  Is.EqualTo("Company-X"));
                Assert.That(report.ReportId,           Is.EqualTo("5065427c-23d3-47ca-b6e0-946ea0e8c4be"));
                Assert.That(report.ContactInfo,        Is.EqualTo("sts-reporting@company-x.example"));
                Assert.That(report.StartDateTime,      Is.EqualTo(new DateTimeOffset(2016, 4, 1, 0, 0, 0, TimeSpan.Zero)));
                Assert.That(report.EndDateTime,        Is.EqualTo(new DateTimeOffset(2016, 4, 1, 23, 59, 59, TimeSpan.Zero)));
                var policy = report.Policies.Single();
                Assert.That(policy.PolicyType,         Is.EqualTo("sts"));
                Assert.That(policy.PolicyDomain,       Is.EqualTo("company-y.example"));
                Assert.That(policy.MxHosts,            Is.EqualTo(new[] { "*.mail.company-y.example" }));
                Assert.That((policy.SuccessCount, policy.FailureCount), Is.EqualTo((5326L, 303L)));
                Assert.That(policy.Failures,           Has.Count.EqualTo(3));
                Assert.That(policy.Failures[1],        Is.EqualTo(new TlsRptReceivedFailure("starttls-not-supported", "2001:db8:abcd:0013::1", "mx2.mail.company-y.example", "203.0.113.56", 200)));
            });

        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch { }
        }

    }


    [Test(Description = "RFC 8460 §5.3, §4.4: the report Hermod's own TlsRptReportService sends is read back by Hermod's ingestor - the counts it reported")]
    public async Task The_report_Hermod_writes_is_read_back()
    {

        var directory = Directory.CreateTempSubdirectory("tlsrpt-roundtrip-").FullName;

        try
        {

            var log      = new CapturingLogger();
            var dns      = new StubDnsClient();
            var queue    = new CapturingMailQueue();
            var service  = new TlsRptReportService(new TlsRptAggregator(Path.Combine(directory, "state.json"), log),
                                                   new TlsRptResolver(dns, log),
                                                   queue,
                                                   new TlsRptReportingOptions("Hermod conformance", "TLS Reports <tls-reports@relay.hermod.test>",
                                                                              "tls-reports@relay.hermod.test", "relay.hermod.test",
                                                                              "mailto:postmaster@relay.hermod.test", TimeSpan.FromDays(1)),
                                                   log);

            var name = "_smtp._tls.policy.test";
            dns.Answer(name, org.GraphDefined.Vanaheimr.Hermod.DNS.DNSResourceRecordTypes.TXT,
                       new org.GraphDefined.Vanaheimr.Hermod.DNS.TXT(org.GraphDefined.Vanaheimr.Hermod.DNS.DNSServiceName.Parse(name),
                                                                    org.GraphDefined.Vanaheimr.Hermod.DNS.DNSQueryClasses.IN,
                                                                    TimeSpan.FromHours(1), "v=TLSRPTv1; rua=mailto:tlsrpt@policy.test"));

            service.Record(new TlsRptEvent("policy.test", TlsRptPolicyType.Sts, "mx.policy.test", "192.0.2.25", "198.51.100.1", true,  null));
            service.Record(new TlsRptEvent("policy.test", TlsRptPolicyType.Sts, "mx.policy.test", "192.0.2.25", "198.51.100.1", true,  null));
            service.Record(new TlsRptEvent("policy.test", TlsRptPolicyType.Sts, "mx.policy.test", "192.0.2.25", "198.51.100.1", false, "certificate-expired"));
            await service.GenerateAndSendAsync(CancellationToken.None);

            var mail   = queue.Queued.Single();
            var report = new TlsRptIngestor(Path.Combine(directory, "received"), log).Ingest(EMailMessage.Parse(mail.MessageContent));

            Assert.That(report, Is.Not.Null, mail.MessageContent);
            Assert.Multiple(() => {
                Assert.That(report!.OrganizationName,                       Is.EqualTo("Hermod conformance"));
                Assert.That((report.TotalSuccess, report.TotalFailure),     Is.EqualTo((2L, 1L)));
                Assert.That(report.Policies.Single().PolicyDomain,          Is.EqualTo("policy.test"));
                Assert.That(report.Policies.Single().Failures.Single().ResultType, Is.EqualTo("certificate-expired"));
            });

        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch { }
        }

    }

    #endregion

    #region Hostile reports

    [Test(Description = "RFC 8460 §6.5 (application/tlsrpt+gzip): \"Security considerations related to gzip compression are discussed in RFC 6713\", RFC 6713 §4: fields \"could contain anything. Applications should treat any data with due skepticism\" - 170 KiB of mail whose report unpacks to 128 MiB is not unpacked whole, before the reply to DATA, by a server anyone may send to")]
    [Category(TestCategories.KnownIssue), Property("Finding", "I-1")]
    [CancelAfter(120_000)]
    public async Task A_gzip_bomb_is_not_unpacked_whole()
    {

        Byte[] bomb;

        using (var output = new MemoryStream())
        {
            using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
            {
                gzip.Write("{\"organization-name\":\"bomb\""u8);
                var spaces = new Byte[1024 * 1024];
                Array.Fill(spaces, (Byte) ' ');
                for (var i = 0; i < 128; i++)
                    gzip.Write(spaces);
                gzip.Write("}"u8);
            }
            bomb = output.ToArray();
        }

        var message = Mail(GzipPart(bomb));

        GC.Collect();
        var before                = GC.GetTotalAllocatedBytes(precise: true);
        var (reply, client)       = await SendAsync(message);
        await using var _client   = client;
        var used                  = GC.GetTotalAllocatedBytes(precise: true) - before;
        var kept                  = Directory.Exists(ReceivedDirectory)
                                        ? Directory.GetFiles(ReceivedDirectory, "*bomb*").Select(file => new FileInfo(file).Length).DefaultIfEmpty(0).Max()
                                        : 0;

        Assert.That(reply.Code, Is.EqualTo(250), Explain(client));
        Assert.Multiple(() => {
            Assert.That(used, Is.LessThan(128L * 1024 * 1024), $"{used / 1048576} MiB allocated for {message.Length / 1024} KiB of mail");
            Assert.That(kept, Is.LessThan(128L * 1024 * 1024), $"{kept / 1048576} MiB kept on disk");
        });

    }


    public static IEnumerable<TestCaseData> Broken()
    {
        // In lines of 1000: JSON allows a line break between any two tokens.
        yield return new TestCaseData("Content-Type: application/tlsrpt+json\r\n\r\n" +
                                      String.Concat(Enumerable.Repeat(new String('[', 1000) + "\r\n", 100)) +
                                      String.Concat(Enumerable.Repeat(new String(']', 1000) + "\r\n", 100))).
                         SetName("JSON nested 100000 deep is no report");
        yield return new TestCaseData(GzipPart(Encoding.ASCII.GetBytes("\x1F\x8B this is not gzip at all"))).
                         SetName("Broken gzip is no report");
        yield return new TestCaseData("Content-Type: application/tlsrpt+json\r\n\r\n{\"organization-name\": \r\n").
                         SetName("Truncated JSON is no report");
        yield return new TestCaseData("Content-Type: application/tlsrpt+gzip\r\nContent-Transfer-Encoding: base64\r\n\r\n!!! not base64 !!!\r\n").
                         SetName("Broken base64 is no report");
    }

    [TestCaseSource(nameof(Broken))]
    [Description("RFC 8460 §7: \"An attacker could inject malicious code into the report, exploiting any vulnerabilities in the report-handling systems of the receiving domain\" - a broken report is taken as mail, read as no report, and the session goes on")]
    [CancelAfter(30_000)]
    public async Task A_broken_report_is_no_report_and_the_session_goes_on(String ReportPart)
    {

        Int32 Refused() => Server.Log.Lines.Count(line => line.Contains("TLS-RPT ingest", StringComparison.Ordinal));

        var before                = Refused();
        var (reply, client)       = await SendAsync(Mail(ReportPart));
        await using var _client   = client;
        var rset                  = await client.CommandAsync("RSET");

        Assert.Multiple(() => {
            Assert.That(reply.Code,  Is.EqualTo(250),        Explain(client));
            Assert.That(rset.Code,   Is.EqualTo(250),        Explain(client));
            Assert.That(Refused(),   Is.GreaterThan(before), "read as no report");
        });

    }


    [Test(Description = "RFC 8460 §4.4: \"failure-details\" - a report with 20000 entries, 2 MiB of JSON gzipped into a few KiB, is read in time, every entry")]
    [CancelAfter(60_000)]
    public async Task A_report_with_20000_failure_details_is_read()
    {

        var organization = Marker();
        var details      = String.Join(",", Enumerable.Range(0, 20_000).Select(i => $"{{\"result-type\":\"certificate-expired\",\"sending-mta-ip\":\"192.0.2.{i % 250}\",\"receiving-mx-hostname\":\"mx{i}.company-y.example\",\"failed-session-count\":1}}"));
        var json         = Regex.Replace(Json(organization), @"""failure-details"":\[.*\]\}\]\}$", $"\"failure-details\":[{details}]}}]}}");
        json             = json.Replace("\"total-failure-session-count\":303", "\"total-failure-session-count\":20000");

        var (reply, client)       = await SendAsync(Mail(GzipPart(Gzip(json))));
        await using var _client   = client;

        Assert.That(reply.Code, Is.EqualTo(250), Explain(client));
        Assert.That(await IngestedAsync(organization) ?? "no report read", Does.Contain(": 5326 successful, 20000 failed session(s)"), Explain(client));
        Assert.That(Server.Log.Lines.Count(line => line.Contains("mx19999.company-y.example", StringComparison.Ordinal)), Is.EqualTo(1));

    }

    #endregion

}
