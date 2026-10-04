using System.Diagnostics;
using System.Text;

using NUnit.Framework;


using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;
using org.GraphDefined.Vanaheimr.Hermod.SMTP.Server;

using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// Hermod's <see cref="SMTPOutboundClient"/> - the relay side, which hands every queued
/// message to the next hop - against a scripted server set as its smart host: what it puts
/// on the wire, how it reads the replies, and what becomes of recipients the next hop refuses.
/// </summary>
[TestFixture]
public sealed partial class OutboundClientTests
{

    #region Setup

    private static SmtpOutboundConfig ConfigFor(ScriptedSmtpServer Server, UInt32 ReadTimeoutMs = 10_000)

        => new () {
               LocalHostname     = "relay.hermod.test",
               SmartHost         = "127.0.0.1",
               SmartHostPort     = Server.Port,
               ConnectTimeoutMs  = 3_000,
               ReadTimeoutMs     = ReadTimeoutMs,
               WriteTimeoutMs    = 3_000,
               // The scripted server's certificate is self-signed: trusted here, as an operator's
               // own CA would be.
               RemoteCertificateValidator = (_, _, _, _) => true
           };

    private static SMTPOutboundClient ClientFor(ScriptedSmtpServer Server, UInt32 ReadTimeoutMs = 10_000)
        => new (ConfigFor(Server, ReadTimeoutMs), null, new StubDnsClient(), new CapturingLogger());

    private static EMailEnvelop Envelope(String[] To, String Body = "hello", DsnParameters? Dsn = null, Boolean RequireTls = false)

        => new (EMail.Parse([
                    "From: app@client.example",
                    "To: " + String.Join(", ", To),
                    "Subject: outbound conformance",
                    "Content-Type: text/plain; charset=utf-8",
                    "",
                    Body
                ])) { Dsn = Dsn ?? DsnParameters.None, RequireTls = RequireTls };

    /// <summary>
    /// Deliver directly (MailSender.SendDirectAsync), bounded so that a client that hangs fails the
    /// test instead of stalling it.
    /// </summary>
    private static async Task<SendResult> SendDirect(ScriptedSmtpServer  Server,
                                                     EMailEnvelop        Envelope,
                                                     UInt32              ReadTimeoutMs  = 10_000,
                                                     TimeSpan?           Bound          = null)
    {

        var sender  = new MailSender(new CapturingMailQueue(), new CapturingLogger(), ClientFor(Server, ReadTimeoutMs));

        using var cts = new CancellationTokenSource(Bound ?? TimeSpan.FromSeconds(20));
        var results = await sender.SendDirectAsync(Envelope, cts.Token);

        await Server.WhenIdleAsync();

        return results.Single().Result;

    }

    private static String Explain(ScriptedSmtpServer Server)
        => "\n--- wire (server side) ---\n" + Server.Transcript;

    #endregion


    #region O-1: replies of more than one line

    public static IEnumerable<TestCaseData> MultiLineReplies()
    {

        TestCaseData Case(String Name, Func<SmtpServerScript> Script)
            => new TestCaseData(Script).SetName($"Multi-line reply: {Name}")
                                       .SetProperty("Finding", "O-1");

        yield return Case("the greeting",          () => new SmtpServerScript { Greeting       = "220-scripted.test ESMTP\r\n220 at your service" });
        yield return Case("MAIL",                  () => new SmtpServerScript { MailReply      = "250-2.1.0 sender\r\n250 2.1.0 ok" });
        yield return Case("RCPT",                  () => new SmtpServerScript { RcptReply      = _ => "250-2.1.5 recipient\r\n250 2.1.5 ok" });
        yield return Case("DATA",                  () => new SmtpServerScript { DataReply      = "354-go ahead\r\n354 end with <CRLF>.<CRLF>" });

        // Read one line short, this reply alone goes unnoticed: QUIT is next, and its reply is
        // not looked at. A guard, not a finding.
        yield return new TestCaseData((Func<SmtpServerScript>) (() => new SmtpServerScript { EndOfDataReply = "250-2.0.0 queued\r\n250 2.0.0 as 4711" }))
                         .SetName("Multi-line reply: the end of data");

    }


    [TestCaseSource(nameof(MultiLineReplies))]
    [Description("RFC 5321 §4.2.1: any reply may have several lines; the client reads to the line with a space after the code before it sends the next command")]
    public async Task A_multi_line_reply_is_read_whole(Func<SmtpServerScript> Script)
    {

        var script = Script();
        await using var server = ScriptedSmtpServer.Start(script);

        var result = await SendDirect(server, Envelope([ "you@outbound.test" ]));

        Assert.Multiple(() => {
            Assert.That(result.Status,                          Is.EqualTo(SendStatus.Success), Explain(server));
            Assert.That(script.Transactions.Single().DataLines, Is.Not.Empty,                   Explain(server));
        });

    }


    [Test(Description = "RFC 5321 §4.2.1: a refusal of several lines (as large providers send them) is one reply - the next RCPT is not answered by its second line")]
    [Property("Finding", "O-1")]
    public async Task A_multi_line_refusal_does_not_shift_the_replies()
    {

        var script = new SmtpServerScript {
                         RcptReply = rcpt => rcpt.StartsWith("first")
                                                 ? "550-5.1.1 The email account that you tried to reach does not exist.\r\n550 5.1.1 Please try again."
                                                 : "250 2.1.5 ok"
                     };
        await using var server = ScriptedSmtpServer.Start(script);

        await SendDirect(server, Envelope([ "first@outbound.test", "second@outbound.test" ]));

        // The second recipient was accepted, so the message goes to it - and only to it.
        Assert.That(script.Transactions.Single().DataLines, Is.Not.Empty, Explain(server));

    }

    #endregion

    #region O-2: what becomes of refused recipients

    /// <summary>
    /// Queue one message for two recipients, let the QueueProcessor deliver it through the scripted
    /// smart host, and return the queue afterwards.
    /// </summary>
    private static async Task<(CapturingMailQueue Queue, QueuedMail Original)> Relay(ScriptedSmtpServer Server, params String[] To)
    {

        var queue     = new CapturingMailQueue();
        var logger    = new CapturingLogger();
        var bounces   = new BounceHandler(new SMTPServerConfig { Hostname = "relay.hermod.test" }, queue, logger);
        var processor = new QueueProcessor(queue, ClientFor(Server), bounces, new QueueProcessorConfig { DomainCooldownSeconds = 0 }, logger);

        await processor.StartAsync();

        // The public way in: MailSender queues one message per recipient domain.
        var id       = (await new MailSender(queue, logger).SendAsync(Envelope(To))).Single();

        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < TimeSpan.FromSeconds(10) &&
               (await queue.GetByIdAsync(id))?.Status is null or QueueItemStatus.Pending or QueueItemStatus.Processing)
            await Task.Delay(50);

        await Task.Delay(500);      // let bounces be queued
        await processor.StopAsync();
        await processor.DisposeAsync();
        await Server.WhenIdleAsync();

        return (queue, (await queue.GetByIdAsync(id))!);

    }


    [Test(Description = "RFC 5321 §6.1: a relay that accepted a message must deliver it or report the failure - a recipient the next hop refuses (550) gets a bounce, the others the message")]
    [Property("Finding", "O-2")]
    public async Task A_recipient_refused_by_the_next_hop_is_bounced()
    {

        var script = new SmtpServerScript { RcptReply = rcpt => rcpt.StartsWith("gone") ? "550 5.1.1 No such user" : "250 2.1.5 ok" };
        await using var server = ScriptedSmtpServer.Start(script);

        var (queue, original) = await Relay(server, "here@outbound.test", "gone@outbound.test");

        var bounce = queue.Queued.FirstOrDefault(mail => mail.EnvelopeFrom.Length == 0 && mail.EnvelopeTo.Contains("app@client.example"));

        Assert.Multiple(() => {
            Assert.That(original.Status,          Is.EqualTo(QueueItemStatus.Delivered),            Explain(server));
            Assert.That(bounce,                   Is.Not.Null, "the sender learns that gone@ was refused" + Explain(server));
            // The report names gone@ as failed, and here@ not at all - the original headers it
            // quotes do mention here@, so the per-recipient fields are what counts (RFC 3464 §2.3).
            Assert.That(bounce?.MessageContent,   Does.Contain("Final-Recipient: rfc822; gone@outbound.test"),     Explain(server));
            Assert.That(bounce?.MessageContent,   Does.Not.Contain("Final-Recipient: rfc822; here@outbound.test"), "here@ was delivered" + Explain(server));
        });

    }


    [Test(Description = "RFC 5321 §4.2.5, §4.5.4.1: a recipient refused for now (450) is tried again later - not dropped, not bounced")]
    [Property("Finding", "O-2")]
    public async Task A_recipient_refused_for_now_is_retried()
    {

        var script = new SmtpServerScript { RcptReply = rcpt => rcpt.StartsWith("later") ? "450 4.2.1 Mailbox busy" : "250 2.1.5 ok" };
        await using var server = ScriptedSmtpServer.Start(script);

        var (queue, _) = await Relay(server, "now@outbound.test", "later@outbound.test");

        var retry = queue.Queued.FirstOrDefault(mail => mail.EnvelopeTo.Contains("later@outbound.test") &&
                                                        mail.Status is QueueItemStatus.Deferred or QueueItemStatus.Pending);

        Assert.Multiple(() => {
            Assert.That(retry,               Is.Not.Null, "later@ stays in the queue" + Explain(server));
            Assert.That(retry?.EnvelopeTo,   Is.EqualTo(new[] { "later@outbound.test" }), "and only later@: now@ has its copy" + Explain(server));
        });

    }

    #endregion

    #region O-3: SMTPUTF8 and 8BITMIME on relay

    [Test(Description = "RFC 6531 §3.4: a message with a non-ASCII address goes out with the SMTPUTF8 parameter")]
    [Property("Finding", "O-3")]
    public async Task A_UTF8_address_goes_out_with_SMTPUTF8()
    {

        var script = new SmtpServerScript();
        await using var server = ScriptedSmtpServer.Start(script);

        var result = await SendDirect(server, Envelope([ "jöran@outbound.test" ]));

        Assert.Multiple(() => {
            Assert.That(result.Status,                            Is.EqualTo(SendStatus.Success), Explain(server));
            Assert.That(script.Transactions.Single().MailFromLine, Does.Contain(" SMTPUTF8"),      Explain(server));
        });

    }


    [Test(Description = "RFC 6531 §3.2: a message that needs SMTPUTF8 is not handed to a server that does not offer it")]
    [Property("Finding", "O-3")]
    public async Task A_UTF8_address_is_not_sent_to_a_server_without_SMTPUTF8()
    {

        var script = new SmtpServerScript { Extensions = [ "PIPELINING", "SIZE 10485760", "8BITMIME", "ENHANCEDSTATUSCODES" ] };
        await using var server = ScriptedSmtpServer.Start(script);

        var result = await SendDirect(server, Envelope([ "jöran@outbound.test" ]));

        Assert.Multiple(() => {
            Assert.That(result.Status,       Is.EqualTo(SendStatus.PermFail), Explain(server));
            Assert.That(script.Transactions, Is.Empty, "no MAIL for a message the server cannot take" + Explain(server));
        });

    }


    [Test(Description = "RFC 6152 §3: 8-bit content goes out declared as BODY=8BITMIME")]
    [Property("Finding", "O-3")]
    public async Task Eight_bit_content_goes_out_as_BODY_8BITMIME()
    {

        var script = new SmtpServerScript();
        await using var server = ScriptedSmtpServer.Start(script);

        var result = await SendDirect(server, Envelope([ "you@outbound.test" ], "Grüße aus Köln"));

        Assert.Multiple(() => {
            Assert.That(result.Status,                             Is.EqualTo(SendStatus.Success), Explain(server));
            Assert.That(script.Transactions.Single().MailFromLine, Does.Contain(" BODY=8BITMIME"),  Explain(server));
        });

    }


    [Test(Description = "RFC 5321 §2.4, RFC 6152 §3: no octet with the high bit set to a server that did not offer 8BITMIME")]
    [Property("Finding", "O-3")]
    public async Task Eight_bit_content_is_not_sent_to_a_server_without_8BITMIME()
    {

        var script = new SmtpServerScript { Extensions = [ "PIPELINING", "SIZE 10485760", "ENHANCEDSTATUSCODES" ] };
        await using var server = ScriptedSmtpServer.Start(script);

        await SendDirect(server, Envelope([ "you@outbound.test" ], "Grüße aus Köln"));

        var eightBit = script.Transactions.SelectMany(t => t.DataLines).Where(l => l.Bytes.Any(b => b > 0x7F)).Select(l => l.Latin1);

        Assert.That(eightBit, Is.Empty, Explain(server));

    }

    #endregion

    #region O-4: REQUIRETLS on relay

    [Test(Description = "RFC 8689 §4.2.1: a REQUIRETLS message goes to the next hop over TLS, with the REQUIRETLS option on MAIL")]
    [Property("Finding", "O-4")]
    public async Task A_REQUIRETLS_message_goes_over_TLS_with_REQUIRETLS()
    {

        var script = new SmtpServerScript {
                         Certificate = TestCertificate.CreateServerCertificate(),
                         Extensions  = [ "PIPELINING", "SIZE 10485760", "8BITMIME", "ENHANCEDSTATUSCODES", "REQUIRETLS" ]
                     };
        await using var server = ScriptedSmtpServer.Start(script);

        var result      = await SendDirect(server, Envelope([ "you@outbound.test" ], RequireTls: true));
        var transaction = script.Transactions.SingleOrDefault();

        Assert.Multiple(() => {
            Assert.That(result.Status,              Is.EqualTo(SendStatus.Success), Explain(server));
            Assert.That(transaction?.Tls,           Is.True,                        Explain(server));
            Assert.That(transaction?.MailFromLine,  Does.Contain(" REQUIRETLS"),     Explain(server));
        });

    }


    [Test(Description = "RFC 8689 §4.2.1: a REQUIRETLS message is not handed to a next hop that does not offer REQUIRETLS - 5.7.30")]
    [Property("Finding", "O-4")]
    public async Task A_REQUIRETLS_message_is_not_sent_to_a_next_hop_without_REQUIRETLS()
    {

        var script = new SmtpServerScript { Certificate = TestCertificate.CreateServerCertificate() };
        await using var server = ScriptedSmtpServer.Start(script);

        var result = await SendDirect(server, Envelope([ "you@outbound.test" ], RequireTls: true));

        Assert.Multiple(() => {
            Assert.That(result.Status,       Is.EqualTo(SendStatus.PermFail),   Explain(server));
            Assert.That(result.ResponseText, Does.StartWith("5.7.30 "),         Explain(server));
            Assert.That(script.Transactions, Is.Empty, "no MAIL for a message the next hop cannot keep on TLS" + Explain(server));
        });

    }

    #endregion

    #region O-5: a silent server

    [Test(Description = "RFC 5321 §4.5.3.2: the client gives up on a server that does not answer - ReadTimeoutMs is honoured")]
    [Property("Finding", "O-5")]
    public async Task A_silent_server_is_given_up_on_after_the_read_timeout()
    {

        // A server that accepts the connection and says nothing at all.
        await using var server = ScriptedSmtpServer.Start(async session => await Task.Delay(TimeSpan.FromSeconds(30)));

        var stopwatch = Stopwatch.StartNew();
        SendResult? result = null;

        try
        {
            result = await SendDirect(server, Envelope([ "you@outbound.test" ]), ReadTimeoutMs: 1_000, Bound: TimeSpan.FromSeconds(15));
        }
        catch (OperationCanceledException)
        {
            // the test's own bound, not the client's timeout
        }

        Assert.Multiple(() => {
            Assert.That(result?.Status,      Is.EqualTo(SendStatus.TempFail),                 "a silent server is a temporary failure");
            Assert.That(stopwatch.Elapsed,   Is.LessThan(TimeSpan.FromSeconds(8)),            "within the 1 s read timeout, not the test's 15 s bound");
        });

    }

    #endregion

    #region O-6: every session ends with QUIT

    public static IEnumerable<TestCaseData> FailedRelays()
    {

        TestCaseData Case(String Name, Func<SmtpServerScript> Script)
            => new TestCaseData(Script).SetName($"Outbound QUIT after: {Name}")
                                       .SetProperty("Finding", "O-6");

        yield return Case("a refused MAIL",           () => new SmtpServerScript { MailReply      = "550 5.7.1 Sender rejected" });
        yield return Case("every RCPT refused",       () => new SmtpServerScript { RcptReply      = _ => "550 5.1.1 No such user" });
        yield return Case("a refused DATA",           () => new SmtpServerScript { DataReply      = "554 5.5.1 No valid recipients" });

    }


    [TestCaseSource(nameof(FailedRelays))]
    [Description("RFC 5321 §4.1.1.10: \"The sender MUST NOT intentionally close the transmission channel until it sends a QUIT command\"")]
    public async Task A_failed_relay_ends_with_QUIT(Func<SmtpServerScript> Script)
    {

        var script = Script();
        await using var server = ScriptedSmtpServer.Start(script);

        var result = await SendDirect(server, Envelope([ "you@outbound.test" ]));

        Assert.Multiple(() => {
            Assert.That(result.Status,                                     Is.Not.EqualTo(SendStatus.Success), Explain(server));
            Assert.That(script.Commands.Select(c => c.Line).LastOrDefault(), Is.EqualTo("QUIT"),              Explain(server));
        });

    }


    [Test(Description = "RFC 5321 §4.1.1.10: a delivered message ends with QUIT as well")]
    public async Task A_delivered_relay_ends_with_QUIT()
    {

        var script = new SmtpServerScript();
        await using var server = ScriptedSmtpServer.Start(script);

        var result = await SendDirect(server, Envelope([ "you@outbound.test" ]));

        Assert.Multiple(() => {
            Assert.That(result.Status,                                       Is.EqualTo(SendStatus.Success), Explain(server));
            Assert.That(script.Commands.Select(c => c.Line).LastOrDefault(), Is.EqualTo("QUIT"),             Explain(server));
        });

    }

    #endregion

    #region O-7: EHLO keywords, not substrings

    [Test(Description = "RFC 5321 §4.1.1.1: an extension is a keyword at the start of an EHLO line - \"DSN\" in the server's name is no DSN extension")]
    [Property("Finding", "O-7")]
    public async Task A_server_named_dsn_does_not_get_DSN_parameters()
    {

        var script = new SmtpServerScript {
                         EhloReply = [ "250-dsn.outbound.test Hello", "250-PIPELINING", "250-8BITMIME", "250 ENHANCEDSTATUSCODES" ]
                     };
        await using var server = ScriptedSmtpServer.Start(script);

        await SendDirect(server, Envelope([ "you@outbound.test" ], Dsn: new DsnParameters(DsnNotify.Failure | DsnNotify.Delay, DsnRet.Hdrs, "env-4711")));

        var transaction = script.Transactions.Single();

        Assert.Multiple(() => {
            Assert.That(transaction.MailFromLine,  Does.Not.Contain("RET=").And.Not.Contain("ENVID="),   Explain(server));
            Assert.That(transaction.RcptToLines,   Has.None.Contains("NOTIFY="),                          Explain(server));
        });

    }

    #endregion

    #region O-8: a 421 to EHLO

    [Test(Description = "RFC 5321 §3.2: HELO is the fallback for an EHLO the server does not know (500, 501, 502, 504, 550) - a 421 closes the session")]
    [Property("Finding", "O-8")]
    public async Task A_421_to_EHLO_is_not_answered_with_HELO()
    {

        var script = new SmtpServerScript { EhloReply = [ "421 4.3.2 Service shutting down" ] };
        await using var server = ScriptedSmtpServer.Start(script);

        var result = await SendDirect(server, Envelope([ "you@outbound.test" ]));

        Assert.Multiple(() => {
            Assert.That(result.Status,                         Is.EqualTo(SendStatus.TempFail), Explain(server));
            Assert.That(script.Commands.Select(c => c.Line),   Has.None.StartsWith("HELO"),     Explain(server));
        });

    }

    #endregion

    #region Guards

    [Test(Description = "RFC 5321 §2.3.8: a bare LF in the message goes out as CR LF - the relay does not pass on what it would refuse")]
    public async Task A_bare_LF_in_the_message_goes_out_as_CRLF()
    {

        var script = new SmtpServerScript();
        await using var server = ScriptedSmtpServer.Start(script);

        await SendDirect(server, Envelope([ "you@outbound.test" ], "first\nsecond"));

        var data = script.Transactions.Single().DataLines;

        Assert.That(data.Where(l => l.Terminator != LineTerminator.CRLF || l.ContainsBareCR).Select(l => l.ToString()), Is.Empty, Explain(server));

    }

    #endregion

}
