using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// No failure report in answer to a report. RFC 6650 §6, for "reporting, using ARF (or
/// extensions to it), of messages that fail particular message authentication checks" - which
/// a DMARC failure report is (RFC 7489 §7.3, RFC 6591): "If the message under evaluation by the
/// Verifier is an ARF [RFC5965] message, a report MUST NOT be automatically generated". An ARF
/// message is a multipart/report whose report-type is "feedback-report" (RFC 5965 §2). Driven
/// over the wire: the server, set to send DMARC reports, takes a message that fails DMARC under
/// a policy with ruf=, and what it queues for relay is read.
/// </summary>
[TestFixture]
public sealed class FailureReportLoopTests : HermodServerTestBase
{

    protected override HermodSmtpServerFixtureOptions Options
        => new() { EnableDmarcReporting = true };


    #region Setup

    /// <summary>
    /// A domain of its own for one test - the server keeps a budget of failure reports per
    /// policy domain and hour - whose DMARC policy asks for failure reports to ruf@ the domain.
    /// No SPF record, no signature: DMARC fails on every message from it.
    /// </summary>
    private String PolicyDomain(String Prefix)
    {

        var domain = $"{Prefix}-{Guid.NewGuid():N}.test";
        var name   = "_dmarc." + domain;

        Server.Dns.Answer(name, DNSResourceRecordTypes.TXT, new TXT(DNSServiceName.Parse(name), DNSQueryClasses.IN, TimeSpan.FromHours(1),
                                                                    $"v=DMARC1; p=none; ruf=mailto:ruf@{domain}"));

        return domain;

    }

    /// <summary>
    /// A message from news@ the domain to alice@hermod.test, delivered by mx.client.example.
    /// </summary>
    private async Task Deliver(String Domain, String ContentType, String Body)
    {

        await using var client = await Server.ConnectAndEhloAsync("mx.client.example");

        Assert.That((await client.CommandAsync($"MAIL FROM:<news@{Domain}>")).Code,      Is.EqualTo(250), Explain(client));
        Assert.That((await client.CommandAsync("RCPT TO:<alice@hermod.test>")).Code,     Is.EqualTo(250), Explain(client));

        var (_, final) = await client.DataAsync($"From: <news@{Domain}>\r\n" +
                                                "To: <alice@hermod.test>\r\n" +
                                                "Subject: a message that fails DMARC\r\n" +
                                                "Date: Thu, 26 Nov 2026 10:00:00 +0000\r\n" +
                                                $"Message-ID: <{Guid.NewGuid():N}@{Domain}>\r\n" +
                                                "MIME-Version: 1.0\r\n" +
                                                $"Content-Type: {ContentType}\r\n" +
                                                "\r\n" +
                                                Body);

        Assert.That(final?.Code, Is.EqualTo(250), Explain(client));

    }

    /// <summary>
    /// The failure reports queued to ruf@ the domain.
    /// </summary>
    private IReadOnlyList<QueuedMail> ReportsTo(String Domain)
        => [ .. Server.Queue.Queued.Where(mail => mail.EnvelopeTo.Contains($"ruf@{Domain}", StringComparer.OrdinalIgnoreCase)) ];

    /// <summary>
    /// An ARF report about a message from hermod.test that failed DMARC - the kind of report a
    /// receiver sends a domain owner - with the feedback type given.
    /// </summary>
    private static String ArfBody(String FeedbackType)

        => "--arf\r\n" +
           "Content-Type: text/plain; charset=us-ascii\r\n" +
           "\r\n" +
           "This is an authentication failure report for a message from hermod.test.\r\n" +
           "\r\n" +
           "--arf\r\n" +
           "Content-Type: message/feedback-report\r\n" +
           "\r\n" +
           $"Feedback-Type: {FeedbackType}\r\n" +
           "User-Agent: SomeReporter/1.0\r\n" +
           "Version: 1\r\n" +
           "Original-Mail-From: <news@hermod.test>\r\n" +
           "Source-IP: 192.0.2.25\r\n" +
           "Reported-Domain: hermod.test\r\n" +
           (FeedbackType == "auth-failure" ? "Auth-Failure: dmarc\r\nIdentity-Alignment: none\r\n" : "") +
           "\r\n" +
           "--arf\r\n" +
           "Content-Type: text/rfc822-headers\r\n" +
           "\r\n" +
           "From: <news@hermod.test>\r\n" +
           "To: <someone@receiver.example>\r\n" +
           "Subject: reported\r\n" +
           "\r\n" +
           "--arf--\r\n";

    #endregion


    public static IEnumerable<TestCaseData> ArfMessages()
    {

        TestCaseData Case(String Name, String ContentType, String FeedbackType)
            => new TestCaseData(ContentType, FeedbackType).SetName($"No failure report in answer to an ARF report: {Name}")
                                                          .SetCategory(TestCategories.KnownIssue)
                                                          .SetProperty("Finding", "R-13");

        yield return Case("a DMARC failure report (Feedback-Type: auth-failure)",
                          "multipart/report; report-type=feedback-report;\r\n\tboundary=\"arf\"",              "auth-failure");

        yield return Case("an abuse report (Feedback-Type: abuse)",
                          "multipart/report; report-type=feedback-report; boundary=\"arf\"",                   "abuse");

        yield return Case("its media type in capitals, the report-type quoted",
                          "Multipart/Report; Report-Type=\"Feedback-Report\"; boundary=\"arf\"",               "auth-failure");

    }

    [TestCaseSource(nameof(ArfMessages))]
    [Description("RFC 6650 §6: \"If the message under evaluation by the Verifier is an ARF [RFC5965] message, a report MUST NOT be automatically generated\" - RFC 5965 §2: an ARF message is a multipart/report of report-type \"feedback-report\"; the media type and its parameter names are case-insensitive (RFC 2045 §5.1), the value of report-type too (RFC 6522 §3). A message that is no report, from a domain with the same policy, delivered after it, is reported - and once its report is queued, there is none about the ARF message")]
    public async Task No_failure_report_is_sent_in_answer_to_an_ARF_report(String ContentType, String FeedbackType)
    {

        var arfDomain  = PolicyDomain("arf");
        var newsDomain = PolicyDomain("news");

        await Deliver(arfDomain,  ContentType,                          ArfBody(FeedbackType));
        await Deliver(newsDomain, "text/plain; charset=us-ascii",       "Hello.\r\n");

        // Failure reports are queued after the end of data is answered: wait for the one about
        // the message that is no report, then a little longer.
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (ReportsTo(newsDomain).Count == 0 && DateTime.UtcNow < deadline)
            await Task.Delay(50);

        await Task.Delay(500);

        Assert.Multiple(() => {
            Assert.That(ReportsTo(newsDomain), Has.Count.EqualTo(1),  $"the message that is no report is reported (a guard)\n--- server log ---\n{Server.Log}");
            Assert.That(ReportsTo(arfDomain),  Is.Empty,              $"no report about the ARF report\n--- server log ---\n{Server.Log}");
        });

    }


    [Test(Description = "RFC 6650 §6 forbids a report in answer to an ARF message only: a delivery status notification (RFC 3464, report-type \"delivery-status\") that fails DMARC is reported as any other message (a guard for R-13)")]
    [Property("Finding", "R-13")]
    public async Task A_DSN_that_fails_DMARC_is_reported()
    {

        var domain = PolicyDomain("dsn");

        await Deliver(domain,
                      "multipart/report; report-type=delivery-status; boundary=\"dsn\"",
                      "--dsn\r\n" +
                      "Content-Type: text/plain; charset=us-ascii\r\n" +
                      "\r\n" +
                      "Your message could not be delivered.\r\n" +
                      "\r\n" +
                      "--dsn\r\n" +
                      "Content-Type: message/delivery-status\r\n" +
                      "\r\n" +
                      $"Reporting-MTA: dns; mx.{domain}\r\n" +
                      "\r\n" +
                      "Final-Recipient: rfc822; nobody@hermod.test\r\n" +
                      "Action: failed\r\n" +
                      "Status: 5.1.1\r\n" +
                      "\r\n" +
                      "--dsn--\r\n");

        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (ReportsTo(domain).Count == 0 && DateTime.UtcNow < deadline)
            await Task.Delay(50);

        Assert.That(ReportsTo(domain), Has.Count.EqualTo(1), $"\n--- server log ---\n{Server.Log}");

    }

}
