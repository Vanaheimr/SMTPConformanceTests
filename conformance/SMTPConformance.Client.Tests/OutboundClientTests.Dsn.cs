using System.Diagnostics;
using System.Text.RegularExpressions;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// The reports Hermod writes when it relays a message: bounces, "relayed" and "delayed"
/// notifications (RFC 3461 §5.2, §6), and their format (RFC 3464, RFC 6522). The message is
/// received by a Hermod server with the DSN parameters a client gave it, queued for relay, and
/// handed by the QueueProcessor to a scripted next hop; the reports land in a queue of their own.
/// </summary>
public sealed partial class OutboundClientTests
{

    #region Setup

    /// <summary>
    /// What a relay produced: the relayed message as it ended up in the queue, the reports queued
    /// for its sender, and the conversation with the Hermod server that received it.
    /// </summary>
    private sealed record RelayRun(QueuedMail                Relayed,
                                   IReadOnlyList<QueuedMail> Reports,
                                   String                    Received)
    {

        public IEnumerable<QueuedMail> ReportsFor(String Recipient)
            => Reports.Where(report => report.MessageContent.Contains($"Final-Recipient: rfc822; {Recipient}", StringComparison.OrdinalIgnoreCase) ||
                                       report.MessageContent.Contains($"Final-Recipient: rfc822;{Recipient}",  StringComparison.OrdinalIgnoreCase));

        public String Explain(ScriptedSmtpServer NextHop)
            => $"\n--- received by Hermod ---\n{Received}" +
               $"\n--- next hop (server side) ---\n{NextHop.Transcript}" +
               String.Concat(Reports.Select((report, i) => $"\n--- report {i + 1} (to {String.Join(", ", report.EnvelopeTo)}) ---\n{report.MessageContent}"));

    }


    /// <summary>
    /// Send one message to a Hermod server with the given MAIL and RCPT commands, then let a
    /// QueueProcessor relay what it queued through the scripted next hop.
    /// </summary>
    /// <param name="NextHop">The scripted next hop.</param>
    /// <param name="MailFrom">The MAIL command, parameters and all.</param>
    /// <param name="RcptTo">One RCPT command per recipient, parameters and all.</param>
    /// <param name="Body">The body lines of the message.</param>
    /// <param name="BeforeDelivery">A change to the queued message before the first attempt.</param>
    /// <param name="Config">The QueueProcessor's configuration.</param>
    private static async Task<RelayRun> RelayThroughHermod(ScriptedSmtpServer     NextHop,
                                                           String                 MailFrom,
                                                           String[]               RcptTo,
                                                           String[]?              Body             = null,
                                                           Action<QueuedMail>?    BeforeDelivery   = null,
                                                           QueueProcessorConfig?  Config           = null)
    {

        await using var hermod = await HermodSmtpServerFixture.StartAsync(new() { RequireAuthForRelay = false });
        await using var client = await hermod.ConnectAndEhloAsync();

        var marker  = $"marker-{Guid.NewGuid():N}";
        var replies = new List<SmtpReply> { await client.CommandAsync(MailFrom) };

        foreach (var rcpt in RcptTo)
            replies.Add(await client.CommandAsync(rcpt));

        var (_, final) = await client.DataAsync(RawSmtpClientExtensions.Message("app@client.example", "rcpt@outbound.test", marker,
                                                                               Body ?? [ "hello" ]));

        Assume.That(replies.Select(reply => reply.Code).Append(final?.Code ?? 0), Is.All.EqualTo(250),
                    "Hermod takes the message\n" + client.Transcript);

        var relayed = hermod.Queue.Queued.Single(mail => mail.MessageContent.Contains(marker));

        BeforeDelivery?.Invoke(relayed);

        var reports   = new CapturingMailQueue();
        var logger    = new CapturingLogger();
        var bounces   = new BounceHandler(new SMTPServerConfig { Hostname = "relay.hermod.test" }, reports, logger);
        var processor = new QueueProcessor(hermod.Queue, ClientFor(NextHop), bounces,
                                           Config ?? new QueueProcessorConfig { DomainCooldownSeconds = 0 }, logger);

        await processor.StartAsync();

        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < TimeSpan.FromSeconds(10) &&
               relayed.Status is QueueItemStatus.Pending or QueueItemStatus.Processing)
            await Task.Delay(50);

        await Task.Delay(300);      // let the reports be queued
        await processor.StopAsync();
        await processor.DisposeAsync();
        await NextHop.WhenIdleAsync();

        return new RelayRun(relayed, [.. reports.Queued], client.Transcript.ToString());

    }

    private static ScriptedSmtpServer NextHopRefusing(String Reply)
        => ScriptedSmtpServer.Start(new SmtpServerScript { RcptReply = _ => Reply });

    #endregion


    #region D-1: the report is a message - CR LF line ends

    [Test(Description = "RFC 5322 §2.3, RFC 5321 §2.3.8: a message's lines end in CR LF - a bounce has no CR that is not followed by LF, and no LF without its CR")]
    [Category(TestCategories.KnownIssue), Property("Finding", "D-1")]
    public async Task A_bounce_has_CR_LF_line_ends_only()
    {

        await using var nextHop = NextHopRefusing("550 5.1.1 No such user");

        var run    = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example>", [ "RCPT TO:<gone@outbound.test>" ]);
        var bounce = run.Reports.FirstOrDefault()?.MessageContent;

        Assert.That(bounce, Is.Not.Null, run.Explain(nextHop));
        Assert.Multiple(() => {
            Assert.That(Regex.Count(bounce!, "\r(?!\n)"),  Is.Zero, "CRs without LF" + run.Explain(nextHop));
            Assert.That(Regex.Count(bounce!, "(?<!\r)\n"), Is.Zero, "LFs without CR" + run.Explain(nextHop));
        });

    }

    #endregion

    #region D-2: every report is a message of its own - Message-ID and boundary

    [Test(Description = "RFC 5322 §3.6.4: a Message-ID is unique to its message; RFC 2046 §5.1.1: a boundary is made of bchars - two bounces have two Message-IDs, each well-formed")]
    [Category(TestCategories.KnownIssue), Property("Finding", "D-2")]
    public async Task Two_bounces_have_two_valid_Message_IDs_and_valid_boundaries()
    {

        await using var nextHop = ScriptedSmtpServer.Start(new SmtpServerScript {
                                      RcptReply = rcpt => rcpt.StartsWith("gone") ? "550 5.1.1 No such user" : "250 2.1.5 Ok"
                                  });

        var run = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example>",
                                           [ "RCPT TO:<here@outbound.test>", "RCPT TO:<gone1@outbound.test>", "RCPT TO:<gone2@outbound.test>" ]);

        var messageIds = run.Reports.Select(report => Regex.Match(report.MessageContent, @"^Message-ID: *(.*?)\r?$", RegexOptions.Multiline | RegexOptions.IgnoreCase).Groups[1].Value).ToArray();
        var boundaries = run.Reports.Select(report => Regex.Match(report.MessageContent, "boundary=\"([^\"]*)\"").Groups[1].Value).ToArray();

        // dot-atom-text "@" dot-atom-text (RFC 5322 §3.6.4, without the obsolete forms), and
        // 1*70 bchars not ending in a space (RFC 2046 §5.1.1).
        const String msgId    = @"^<[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*>$";
        const String boundary = @"^[0-9A-Za-z'()+_,./:=?-][0-9A-Za-z'()+_,./:=? -]{0,68}(?<! )$";

        Assert.That(run.Reports, Has.Count.EqualTo(2), "one bounce per refused recipient" + run.Explain(nextHop));
        Assert.Multiple(() => {
            Assert.That(messageIds,          Is.Unique,                      run.Explain(nextHop));
            Assert.That(messageIds,          Has.All.Matches(msgId),         run.Explain(nextHop));
            Assert.That(boundaries,          Has.All.Matches(boundary),      run.Explain(nextHop));
        });

    }

    #endregion

    #region D-3: NOTIFY decides whether a failure is reported

    public static IEnumerable<TestCaseData> NotifyWithoutFailure()
    {
        yield return new TestCaseData("NOTIFY=NEVER").SetName("No bounce for NOTIFY=NEVER");
        yield return new TestCaseData("NOTIFY=SUCCESS").SetName("No bounce for NOTIFY=SUCCESS");
        yield return new TestCaseData("NOTIFY=DELAY").SetName("No bounce for NOTIFY=DELAY");
    }

    [TestCaseSource(nameof(NotifyWithoutFailure))]
    [Description("RFC 3461 §5.2.6 (b), §5.2.2 (d): \"If a NOTIFY parameter was supplied for the recipient which did not contain the value FAILURE, a DSN MUST NOT be issued for that recipient\"")]
    [Category(TestCategories.KnownIssue), Property("Finding", "D-3")]
    public async Task A_failure_is_not_reported_when_NOTIFY_leaves_out_FAILURE(String Notify)
    {

        await using var nextHop = NextHopRefusing("550 5.1.1 No such user");

        var run = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example>", [ $"RCPT TO:<gone@outbound.test> {Notify}" ]);

        Assert.Multiple(() => {
            Assert.That(run.Relayed.Status, Is.EqualTo(QueueItemStatus.Failed), run.Explain(nextHop));
            Assert.That(run.Reports,        Is.Empty,                           run.Explain(nextHop));
        });

    }


    public static IEnumerable<TestCaseData> NotifyWithFailure()
    {
        yield return new TestCaseData("").SetName("A bounce without NOTIFY");
        yield return new TestCaseData(" NOTIFY=FAILURE").SetName("A bounce for NOTIFY=FAILURE");
        yield return new TestCaseData(" NOTIFY=SUCCESS,FAILURE").SetName("A bounce for NOTIFY=SUCCESS,FAILURE");
    }

    [TestCaseSource(nameof(NotifyWithFailure))]
    [Description("RFC 3461 §5.2.6 (a), (c): with FAILURE in NOTIFY, or no NOTIFY at all, \"a 'failed' DSN MUST be issued\" - a guard for D-3")]
    [Property("Finding", "D-3")]
    public async Task A_failure_is_reported_when_NOTIFY_asks_for_it_or_is_absent(String Notify)
    {

        await using var nextHop = NextHopRefusing("550 5.1.1 No such user");

        var run = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example>", [ $"RCPT TO:<gone@outbound.test>{Notify}" ]);

        Assert.That(run.ReportsFor("gone@outbound.test").ToArray(), Has.Length.EqualTo(1), run.Explain(nextHop));

    }

    #endregion

    #region D-4: what a message says about itself does not stop its bounce

    public static IEnumerable<TestCaseData> InnocentBodies()
    {
        yield return new TestCaseData((Object) new[] { "A DSN is a multipart/report with a message/delivery-status part." }).SetName("Bounced although it mentions multipart/report");
        yield return new TestCaseData((Object) new[] { "Your vacation reply said:", "Auto-Submitted: auto-replied" }).SetName("Bounced although it quotes Auto-Submitted");
        yield return new TestCaseData((Object) new[] { "The bounce I got:", "From: MAILER-DAEMON@example.org" }).SetName("Bounced although it quotes a bounce");
    }

    [TestCaseSource(nameof(InnocentBodies))]
    [Description("RFC 3461 §5.2.6 (c), RFC 5321 §6.1: a failed message whose reverse-path is not null is reported - whatever its body says")]
    [Category(TestCategories.KnownIssue), Property("Finding", "D-4")]
    public async Task A_failure_is_reported_whatever_the_message_says(String[] Body)
    {

        await using var nextHop = NextHopRefusing("550 5.1.1 No such user");

        var run = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example>", [ "RCPT TO:<gone@outbound.test>" ], Body);

        Assert.That(run.ReportsFor("gone@outbound.test").ToArray(), Has.Length.EqualTo(1), "the sender learns of the failure" + run.Explain(nextHop));

    }

    #endregion

    #region D-5: a message given up on has failed

    [Test(Description = "RFC 3461 §5.2.6: a message that cannot be delivered is reported as \"failed\" - also when the last attempt was refused for now, and the relay gives up")]
    [Category(TestCategories.KnownIssue), Property("Finding", "D-5")]
    public async Task A_message_given_up_on_is_reported_as_failed()
    {

        await using var nextHop = NextHopRefusing("451 4.3.0 Try again later");

        var run    = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example>", [ "RCPT TO:<later@outbound.test>" ],
                                              BeforeDelivery: mail => mail.RetryCount = RetryCalculator.MaxRetries - 1);
        var bounce = run.ReportsFor("later@outbound.test").FirstOrDefault()?.MessageContent;

        Assert.That(run.Relayed.Status, Is.EqualTo(QueueItemStatus.Failed), "the relay gives up" + run.Explain(nextHop));
        Assert.That(bounce,             Is.Not.Null,                        run.Explain(nextHop));
        Assert.Multiple(() => {
            Assert.That(bounce, Does.Match(@"(?m)^Action: failed\r?$"),     run.Explain(nextHop));
            Assert.That(bounce, Does.Not.Contain("Action: delayed"),        run.Explain(nextHop));
            Assert.That(bounce, Does.Not.Contain("will be retried"),        "it will not" + run.Explain(nextHop));
        });

    }

    #endregion

    #region D-6: the next hop's status and reply

    public static IEnumerable<TestCaseData> NextHopReplies()
    {
        yield return new TestCaseData("550 5.7.1 Relaying denied",          "5.7.1").SetName("Status 5.7.1 from 550 5.7.1");
        yield return new TestCaseData("553 5.1.3 Bad recipient syntax",     "5.1.3").SetName("Status 5.1.3 from 553 5.1.3");
        yield return new TestCaseData("552 5.2.2 Mailbox full",             "5.2.2").SetName("Status 5.2.2 from 552 5.2.2");
        yield return new TestCaseData("554 5.6.0 Content rejected",         "5.6.0").SetName("Status 5.6.0 from 554 5.6.0");
    }

    [TestCaseSource(nameof(NextHopReplies))]
    [Description("RFC 3461 §6.3 (g), (i), RFC 3464 §2.3.4, §2.3.6: the Status field is the status code the failure had, the Diagnostic-Code the next hop's reply as it was")]
    [Category(TestCategories.KnownIssue), Property("Finding", "D-6")]
    public async Task A_bounce_carries_the_status_and_reply_of_the_next_hop(String Reply, String Status)
    {

        await using var nextHop = NextHopRefusing(Reply);

        var run    = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example>", [ "RCPT TO:<gone@outbound.test>" ]);
        var bounce = run.ReportsFor("gone@outbound.test").FirstOrDefault()?.MessageContent;

        Assert.That(bounce, Is.Not.Null, run.Explain(nextHop));
        Assert.Multiple(() => {
            Assert.That(bounce, Does.Match($@"(?m)^Status: {Regex.Escape(Status)}\r?$"),                      run.Explain(nextHop));
            Assert.That(bounce, Does.Match($@"(?m)^Diagnostic-Code: smtp; ?{Regex.Escape(Reply)}\r?$"),        run.Explain(nextHop));
        });

    }

    #endregion

    #region D-7: Original-Recipient is ORCPT, or absent

    [Test(Description = "RFC 3461 §6.3 (d): \"If the ORCPT parameter was provided for this recipient, the Original-Recipient field MUST be supplied, with its value taken from the ORCPT parameter\"")]
    [Category(TestCategories.KnownIssue), Property("Finding", "D-7")]
    public async Task Original_Recipient_is_the_ORCPT_parameter()
    {

        await using var nextHop = NextHopRefusing("550 5.1.1 No such user");

        var run    = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example>", [ "RCPT TO:<gone@outbound.test> ORCPT=rfc822;Alias@Client.example" ]);
        var bounce = run.ReportsFor("gone@outbound.test").FirstOrDefault()?.MessageContent;

        Assert.That(bounce, Is.Not.Null, run.Explain(nextHop));
        Assert.That(bounce, Does.Match(@"(?m)^Original-Recipient: rfc822; ?Alias@Client\.example\r?$"), run.Explain(nextHop));

    }


    [Test(Description = "RFC 3461 §6.3 (d): \"If no ORCPT parameter was provided for this recipient, the Original-Recipient field MUST NOT appear\"")]
    [Category(TestCategories.KnownIssue), Property("Finding", "D-7")]
    public async Task Without_ORCPT_there_is_no_Original_Recipient()
    {

        await using var nextHop = NextHopRefusing("550 5.1.1 No such user");

        var run    = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example>", [ "RCPT TO:<gone@outbound.test>" ]);
        var bounce = run.ReportsFor("gone@outbound.test").FirstOrDefault()?.MessageContent;

        Assert.That(bounce, Is.Not.Null,                              run.Explain(nextHop));
        Assert.That(bounce, Does.Not.Contain("Original-Recipient:"),  run.Explain(nextHop));

    }

    #endregion

    #region D-8: Original-Envelope-Id is ENVID, decoded

    [Test(Description = "RFC 3461 §6.3 (a): with ENVID on the MAIL command \"an Original-Envelope-ID field MUST be supplied\" - its xtext decoded")]
    [Category(TestCategories.KnownIssue), Property("Finding", "D-8")]
    public async Task A_bounce_carries_the_ENVID()
    {

        await using var nextHop = NextHopRefusing("550 5.1.1 No such user");

        var run    = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example> ENVID=QQ+2B314159", [ "RCPT TO:<gone@outbound.test>" ]);
        var bounce = run.ReportsFor("gone@outbound.test").FirstOrDefault()?.MessageContent;

        Assert.That(bounce, Is.Not.Null, run.Explain(nextHop));
        Assert.That(bounce, Does.Match(@"(?mi)^Original-Envelope-Id: QQ\+314159\r?$"), run.Explain(nextHop));

    }

    #endregion

    #region D-9: RET=HDRS returns the header only

    [Test(Description = "RFC 3461 §4.3: \"HDRS requests that only the headers of the message be returned\" - the body stays out of the bounce")]
    [Category(TestCategories.KnownIssue), Property("Finding", "D-9")]
    public async Task With_RET_HDRS_the_bounce_returns_the_header_only()
    {

        await using var nextHop = NextHopRefusing("550 5.1.1 No such user");

        var run    = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example> RET=HDRS", [ "RCPT TO:<gone@outbound.test>" ],
                                              [ "The body of this message stays home." ]);
        var bounce = run.ReportsFor("gone@outbound.test").FirstOrDefault()?.MessageContent;

        Assert.That(bounce, Is.Not.Null, run.Explain(nextHop));
        Assert.Multiple(() => {
            Assert.That(bounce, Does.Not.Contain("stays home"),                        run.Explain(nextHop));
            Assert.That(bounce, Does.Contain("Content-Type: text/rfc822-headers"),     "RFC 6522 §4" + run.Explain(nextHop));
        });

    }

    #endregion

    #region D-10: delayed DSNs

    private static readonly QueueProcessorConfig DelayAtOnce = new() { DomainCooldownSeconds = 0, SendDelayNotifications = true, DelayNotificationAfter = TimeSpan.Zero };

    [Test(Description = "RFC 3461 §5.2.5, §6.2: a recipient that asked for NOTIFY=DELAY may get a \"delayed\" DSN - a multipart/report like every DSN, once the configured delay has passed")]
    [Category(TestCategories.KnownIssue), Property("Finding", "D-10")]
    public async Task A_delay_is_reported_as_a_delayed_DSN_when_asked_for()
    {

        await using var nextHop = NextHopRefusing("451 4.3.0 Try again later");

        var run    = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example>", [ "RCPT TO:<later@outbound.test> NOTIFY=DELAY,FAILURE" ],
                                              Config: DelayAtOnce);
        var report = run.Reports.FirstOrDefault()?.MessageContent;

        Assert.That(run.Relayed.Status, Is.EqualTo(QueueItemStatus.Deferred), run.Explain(nextHop));
        Assert.That(report,             Is.Not.Null,                           "DelayNotificationAfter is zero" + run.Explain(nextHop));
        Assert.Multiple(() => {
            Assert.That(report, Does.Contain("multipart/report; report-type=delivery-status"), run.Explain(nextHop));
            Assert.That(report, Does.Match(@"(?m)^Action: delayed\r?$"),                       run.Explain(nextHop));
            Assert.That(report, Does.Match(@"(?m)^Final-Recipient: rfc822; ?later@outbound\.test\r?$"), run.Explain(nextHop));
        });

    }


    [Test(Description = "RFC 3461 §5.2.5 (c): \"If the NOTIFY parameter was supplied which did not contain the DELAY keyword, a 'delayed' DSN MUST NOT be issued\"")]
    [Property("Finding", "D-10")]
    public async Task A_delay_is_not_reported_when_NOTIFY_leaves_out_DELAY()
    {

        await using var nextHop = NextHopRefusing("451 4.3.0 Try again later");

        var run = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example>", [ "RCPT TO:<later@outbound.test> NOTIFY=FAILURE" ],
                                           Config: DelayAtOnce);

        Assert.Multiple(() => {
            Assert.That(run.Relayed.Status, Is.EqualTo(QueueItemStatus.Deferred), run.Explain(nextHop));
            Assert.That(run.Reports,        Is.Empty,                              run.Explain(nextHop));
        });

    }

    #endregion

    #region D-11: "relayed" DSNs per recipient

    [Test(Description = "RFC 3461 §5.2.2 (b), (e): relayed to a next hop without DSN, a recipient with NOTIFY=SUCCESS gets a \"relayed\" DSN - and one without SUCCESS gets none")]
    [Category(TestCategories.KnownIssue), Property("Finding", "D-11")]
    public async Task Only_the_recipient_that_asked_gets_a_relayed_DSN()
    {

        await using var nextHop = ScriptedSmtpServer.Start(new SmtpServerScript { Extensions = [ "PIPELINING", "SIZE 10485760", "8BITMIME", "ENHANCEDSTATUSCODES" ] });

        var run = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example>",
                                           [ "RCPT TO:<asked@outbound.test> NOTIFY=SUCCESS", "RCPT TO:<quiet@outbound.test> NOTIFY=FAILURE" ]);

        Assert.Multiple(() => {
            Assert.That(run.Relayed.Status,                         Is.EqualTo(QueueItemStatus.Delivered), run.Explain(nextHop));
            Assert.That(run.ReportsFor("asked@outbound.test"),      Has.Exactly(1).Items,                  run.Explain(nextHop));
            Assert.That(run.ReportsFor("quiet@outbound.test"),      Is.Empty,                              run.Explain(nextHop));
        });

    }

    #endregion

    #region D-12: the relay passes on what it received - and nothing else

    [Test(Description = "RFC 3461 §5.2.1 (b): \"If no RET parameter was present in the MAIL command when the message was received, the RET parameter MUST NOT be supplied when the message is relayed\"")]
    [Category(TestCategories.KnownIssue), Property("Finding", "D-12")]
    public async Task A_relay_adds_no_RET_the_client_did_not_give()
    {

        var script = new SmtpServerScript();
        await using var nextHop = ScriptedSmtpServer.Start(script);

        var run = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example> ENVID=QQ314159", [ "RCPT TO:<bob@outbound.test> NOTIFY=SUCCESS,FAILURE" ]);

        var mailFrom = script.Transactions.FirstOrDefault()?.MailFromLine;

        Assert.That(mailFrom, Is.Not.Null,                                         run.Explain(nextHop));
        Assert.Multiple(() => {
            Assert.That(mailFrom, Does.Contain("ENVID=QQ314159"),                  "ENVID was given and is passed on" + run.Explain(nextHop));
            Assert.That(mailFrom, Does.Not.Contain("RET="),                        run.Explain(nextHop));
        });

    }


    [Test(Description = "RFC 3461 §5.2.1 (c): \"If no NOTIFY parameter was present in the RCPT command when the message was received, the NOTIFY parameter MUST NOT be supplied for that recipient when the message is relayed\"")]
    [Category(TestCategories.KnownIssue), Property("Finding", "D-12")]
    public async Task A_relay_adds_no_NOTIFY_the_client_did_not_give()
    {

        var script = new SmtpServerScript();
        await using var nextHop = ScriptedSmtpServer.Start(script);

        var run = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example>",
                                           [ "RCPT TO:<plain@outbound.test>", "RCPT TO:<never@outbound.test> NOTIFY=NEVER" ]);

        var rcpts = script.Transactions.FirstOrDefault()?.RcptToLines ?? [];

        Assert.That(rcpts, Has.Count.EqualTo(2), run.Explain(nextHop));
        Assert.Multiple(() => {
            Assert.That(rcpts.Single(rcpt => rcpt.Contains("plain@")), Does.Not.Contain("NOTIFY="),    run.Explain(nextHop));
            Assert.That(rcpts.Single(rcpt => rcpt.Contains("never@")), Does.Contain("NOTIFY=NEVER"),   "NEVER was given and is passed on" + run.Explain(nextHop));
            Assert.That(script.Transactions.First().MailFromLine, Does.Not.Contain("RET="),   run.Explain(nextHop));
        });

    }

    #endregion

}
