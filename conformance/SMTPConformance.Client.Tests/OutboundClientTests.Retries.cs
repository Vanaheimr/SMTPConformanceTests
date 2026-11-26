using System.Diagnostics;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// When the relay tries again, and how many copies it sends: RFC 5321 §4.5.4.1, the sending
/// strategy - the delay before a destination that failed is tried again, the retry interval, the
/// parameters of the retry algorithm, and one copy of a message for the recipients one server
/// takes. The messages are queued as an application queues them (MailSender) or as the Hermod
/// server queues what it relays, and handed by the QueueProcessor to a scripted next hop.
/// </summary>
public sealed partial class OutboundClientTests
{

    #region Setup

    /// <summary>
    /// A QueueProcessor relaying through the scripted next hop, and the queue it reads.
    /// </summary>
    private sealed class RetryRelay(ScriptedSmtpServer NextHop, QueueProcessorConfig Config) : IAsyncDisposable
    {

        public  readonly CapturingMailQueue Queue     = new();
        private readonly CapturingLogger    logger    = new();
        private          QueueProcessor?    processor;

        public async Task<RetryRelay> StartAsync()
        {
            processor = new QueueProcessor(Queue, ClientFor(NextHop), new BounceHandler(new SMTPServerConfig { Hostname = "relay.hermod.test" }, Queue, logger),
                                           Config, logger);
            await processor.StartAsync();
            return this;
        }

        /// <summary>
        /// Queue the message as an application does, and wait until the relay has done with every
        /// copy of it: delivered, deferred or failed.
        /// </summary>
        public async Task<QueuedMail[]> SendAsync(EMailEnvelop Envelope)
        {

            var ids      = await new MailSender(Queue, logger).SendAsync(Envelope);

            var deadline = Stopwatch.StartNew();
            while (deadline.Elapsed < TimeSpan.FromSeconds(10) &&
                   ids.Any(id => Queue.Queued.FirstOrDefault(mail => mail.Id == id)?.Status is null or QueueItemStatus.Pending or QueueItemStatus.Processing))
                await Task.Delay(50);

            await Task.Delay(300);      // a held back copy, a bounce
            await NextHop.WhenIdleAsync();

            return [.. ids.Select(id => Queue.Queued.First(mail => mail.Id == id))];

        }

        public async ValueTask DisposeAsync()
        {
            if (processor is not null)
            {
                await processor.StopAsync();
                await processor.DisposeAsync();
            }
        }

    }

    /// <summary>
    /// The relay's configuration for these tests: no cooldown and no limit per domain - what is
    /// held back is held back by the retry strategy.
    /// </summary>
    private static QueueProcessorConfig NoRateLimit()
        => new() { DomainCooldownSeconds = 0, MaxDeliveriesPerDomain = 1000, SendDelayNotifications = false };

    #endregion


    #region O-28: a destination that failed is not tried again at once

    public static IEnumerable<TestCaseData> FailedDestinations()
    {

        yield return new TestCaseData(new SmtpServerScript { Greeting = "421 4.3.2 Service not available, closing transmission channel" })
                         .SetName("A next hop that greeted with 421 is not tried again at once for the next message")
                         .SetProperty("Finding", "O-28");

        yield return new TestCaseData(new Object?[] { null })
                         .SetName("A next hop that closed the connection unasked is not tried again at once for the next message")
                         .SetProperty("Finding", "O-28");

    }

    [TestCaseSource(nameof(FailedDestinations))]
    [Description("RFC 5321 §4.5.4.1: \"The sender MUST delay retrying a particular destination after one attempt has failed\"; \"A client SHOULD keep a list of hosts it cannot reach\" - the next message for a next hop that refused the session for now waits as the first one does")]
    public async Task A_destination_that_failed_is_not_tried_again_at_once(SmtpServerScript? Script)
    {

        await using var nextHop = Script is not null
                                      ? ScriptedSmtpServer.Start(Script)
                                      : ScriptedSmtpServer.Start(session => { session.Abort(); return Task.CompletedTask; });
        await using var relay   = await new RetryRelay(nextHop, NoRateLimit()).StartAsync();

        var first     = (await relay.SendAsync(Envelope([ "first@outbound.test"  ]))).Single();
        var sessions  = nextHop.Sessions.Count;

        Assume.That(first.Status, Is.EqualTo(QueueItemStatus.Deferred), "the first message waits for its retry" + Explain(nextHop));
        Assume.That(sessions,     Is.GreaterThan(0),                     "the first message was tried" + Explain(nextHop));

        var second    = (await relay.SendAsync(Envelope([ "second@outbound.test" ]))).Single();

        Assert.Multiple(() => {
            Assert.That(nextHop.Sessions.Count, Is.EqualTo(sessions),                 "the next hop is not tried again before the first message's retry" + Explain(nextHop));
            Assert.That(second.Status,          Is.EqualTo(QueueItemStatus.Deferred), "the second message waits, and is not lost" + Explain(nextHop));
        });

    }


    [Test(Description = "RFC 5321 §4.5.4.1 (a guard): a recipient refused for now is the recipient's failure, not the destination's - the next message for another recipient goes at once")]
    [Property("Finding", "O-28")]
    public async Task A_recipient_refused_for_now_does_not_hold_back_the_next_message()
    {

        var script = new SmtpServerScript { RcptReply = rcpt => rcpt.Contains("busy@") ? "450 4.2.1 Mailbox busy, try again later" : "250 2.1.5 Ok" };
        await using var nextHop = ScriptedSmtpServer.Start(script);
        await using var relay   = await new RetryRelay(nextHop, NoRateLimit()).StartAsync();

        var first  = (await relay.SendAsync(Envelope([ "busy@outbound.test" ]))).Single();
        var second = (await relay.SendAsync(Envelope([ "here@outbound.test" ]))).Single();

        Assert.Multiple(() => {
            Assert.That(first.Status,  Is.EqualTo(QueueItemStatus.Deferred),  Explain(nextHop));
            Assert.That(second.Status, Is.EqualTo(QueueItemStatus.Delivered), "delivered at once" + Explain(nextHop));
        });

    }


    [Test(Description = "RFC 5321 §4.5.4.1 (a guard): a next hop that took a message is used again for the next one at once")]
    [Property("Finding", "O-28")]
    public async Task A_destination_that_took_a_message_takes_the_next_one_at_once()
    {

        await using var nextHop = ScriptedSmtpServer.Start(new SmtpServerScript());
        await using var relay   = await new RetryRelay(nextHop, NoRateLimit()).StartAsync();

        var first  = (await relay.SendAsync(Envelope([ "first@outbound.test"  ]))).Single();
        var second = (await relay.SendAsync(Envelope([ "second@outbound.test" ]))).Single();

        Assert.That(new[] { first.Status, second.Status }, Is.All.EqualTo(QueueItemStatus.Delivered), Explain(nextHop));

    }

    #endregion

    #region O-29: the parameters of the retry algorithm are the operator's

    [Test(Description = "RFC 5321 §4.5.4.1: \"The parameters to the retry algorithm MUST be configurable\" - a give-up time of the operator's (QueueProcessorConfig.GiveUpAfter): with none left, a message refused for now has failed and is bounced")]
    [Property("Finding", "O-29")]
    public async Task The_give_up_time_is_configurable()
    {

        var config  = NoRateLimit();
        var giveUp  = typeof(QueueProcessorConfig).GetProperty("GiveUpAfter");

        Assert.That(giveUp?.PropertyType, Is.EqualTo(typeof(TimeSpan)), "QueueProcessorConfig has a give-up time, GiveUpAfter");

        giveUp!.SetValue(config, TimeSpan.Zero);

        await using var nextHop = NextHopRefusing("451 4.3.0 Try again later");
        await using var relay   = await new RetryRelay(nextHop, config).StartAsync();

        var mail    = (await relay.SendAsync(Envelope([ "later@outbound.test" ]))).Single();
        var bounce  = relay.Queue.Queued.FirstOrDefault(report => report.EnvelopeFrom.Length == 0);

        Assert.Multiple(() => {
            Assert.That(mail.Status, Is.EqualTo(QueueItemStatus.Failed), "given up on" + Explain(nextHop));
            Assert.That(bounce,      Is.Not.Null,                        "the sender learns of it" + Explain(nextHop));
        });

    }


    [Test(Description = "RFC 5321 §4.5.4.1: \"The parameters to the retry algorithm MUST be configurable\" - retry intervals of the operator's (QueueProcessorConfig.RetryIntervals): with three hours, a message refused for now is tried again in three hours")]
    [Property("Finding", "O-29")]
    public async Task The_retry_intervals_are_configurable()
    {

        var config     = NoRateLimit();
        var intervals  = typeof(QueueProcessorConfig).GetProperty("RetryIntervals");

        Assert.That(intervals?.PropertyType.IsAssignableFrom(typeof(TimeSpan[])), Is.True, "QueueProcessorConfig has retry intervals, RetryIntervals");

        intervals!.SetValue(config, new[] { TimeSpan.FromHours(3) });

        await using var nextHop = NextHopRefusing("451 4.3.0 Try again later");
        await using var relay   = await new RetryRelay(nextHop, config).StartAsync();

        var start  = DateTimeOffset.UtcNow;
        var mail   = (await relay.SendAsync(Envelope([ "later@outbound.test" ]))).Single();
        var end    = DateTimeOffset.UtcNow;

        Assert.Multiple(() => {
            Assert.That(mail.Status,    Is.EqualTo(QueueItemStatus.Deferred),                                  Explain(nextHop));
            Assert.That(mail.NextRetry, Is.InRange(start + TimeSpan.FromHours(2.5), end + TimeSpan.FromHours(3.5)), "tried again in about three hours" + Explain(nextHop));
        });

    }


    [Test(Description = "RFC 5321 §4.5.4.1 (a guard): \"Retries continue until the message is transmitted or the sender gives up\" - by default a message refused for now is kept for its retry")]
    [Property("Finding", "O-29")]
    public async Task By_default_a_message_refused_for_now_is_kept()
    {

        await using var nextHop = NextHopRefusing("451 4.3.0 Try again later");
        await using var relay   = await new RetryRelay(nextHop, NoRateLimit()).StartAsync();

        var mail = (await relay.SendAsync(Envelope([ "later@outbound.test" ]))).Single();

        Assert.Multiple(() => {
            Assert.That(mail.Status,                                                     Is.EqualTo(QueueItemStatus.Deferred), Explain(nextHop));
            Assert.That(relay.Queue.Queued.Where(report => report.EnvelopeFrom.Length == 0), Is.Empty, "no bounce" + Explain(nextHop));
        });

    }

    #endregion

    #region O-30: a retry no sooner than 30 minutes

    [Test(Description = "RFC 5321 §4.5.4.1: \"In general, the retry interval SHOULD be at least 30 minutes\" - none of 20 messages refused for now is tried again sooner")]
    [Property("Finding", "O-30")]
    public async Task No_retry_comes_sooner_than_30_minutes()
    {

        await using var nextHop = NextHopRefusing("451 4.3.0 Try again later");
        await using var relay   = await new RetryRelay(nextHop, NoRateLimit()).StartAsync();

        // One message for 20 domains: 20 copies, each refused for now, each with its retry.
        var start  = DateTimeOffset.UtcNow;
        var mails  = await relay.SendAsync(Envelope([.. Enumerable.Range(1, 20).Select(i => $"later@d{i}.outbound.test")]));

        Assume.That(mails, Has.Length.EqualTo(20).And.All.Property(nameof(QueuedMail.Status)).EqualTo(QueueItemStatus.Deferred), Explain(nextHop));

        var soonest = mails.Min(mail => mail.NextRetry) - start;

        Assert.That(soonest, Is.GreaterThanOrEqualTo(TimeSpan.FromMinutes(30)), $"the soonest retry, after {soonest.TotalMinutes:F1} minutes" + Explain(nextHop));

    }

    #endregion

    #region O-31: one copy for one domain

    /// <summary>
    /// Send one message to a Hermod server for the given recipients, and return what it queued for
    /// relay: a copy per next hop.
    /// </summary>
    private static async Task<(QueuedMail[] Copies, String Transcript)> QueuedForRelay(Boolean SmtpUtf8, params String[] Recipients)
    {

        await using var hermod = await HermodSmtpServerFixture.StartAsync(new() { RequireAuthForRelay = false });
        await using var client = await hermod.ConnectAndEhloAsync();

        var marker  = $"marker-{Guid.NewGuid():N}";
        var replies = new List<SmtpReply> { await client.CommandAsync("MAIL FROM:<app@client.example>" + (SmtpUtf8 ? " SMTPUTF8" : "")) };

        foreach (var recipient in Recipients)
            replies.Add(await client.CommandAsync($"RCPT TO:<{recipient}>"));

        var (_, final) = await client.DataAsync(RawSmtpClientExtensions.Message("app@client.example", "rcpt@outbound.test", marker, [ "hello" ]));

        Assume.That(replies.Select(reply => reply.Code).Append(final?.Code ?? 0), Is.All.EqualTo(250), "Hermod takes the message\n" + client.Transcript);

        return ([.. hermod.Queue.Queued.Where(mail => mail.MessageContent.Contains(marker))], client.Transcript.ToString());

    }

    public static IEnumerable<TestCaseData> OneDomainTwoSpellings()
    {

        // RFC 5321 §2.4: "Mailbox domains follow normal DNS rules and are hence not case sensitive."
        yield return new TestCaseData(false, new[] { "first@outbound.test", "second@OUTBOUND.test" })
                         .SetName("Two recipients at outbound.test and OUTBOUND.test get one copy")
                         .SetProperty("Finding", "O-31");

        // RFC 5890 §2.3.2.1: a U-label and its A-label are the same label - one domain, one MX.
        yield return new TestCaseData(true, new[] { "first@bücher.test", "second@xn--bcher-kva.test" })
                         .SetName("Two recipients at bücher.test and xn--bcher-kva.test get one copy")
                         .SetProperty("Finding", "O-31");

        yield return new TestCaseData(false, new[] { "first@outbound.test", "second@outbound.test" })
                         .SetName("Two recipients at outbound.test get one copy (a guard)")
                         .SetProperty("Finding", "O-31");

    }

    [TestCaseSource(nameof(OneDomainTwoSpellings))]
    [Description("RFC 5321 §4.5.4.1: one copy for the recipients of one server - \"the SMTP client SHOULD use the command sequence: MAIL, RCPT, RCPT, ..., RCPT, DATA\"; §2.4: a domain is not case sensitive, RFC 5890 §2.3.2.1: nor its form - the relay queues one copy, for both")]
    public async Task Recipients_at_one_domain_get_one_copy(Boolean SmtpUtf8, String[] Recipients)
    {

        var (copies, transcript) = await QueuedForRelay(SmtpUtf8, Recipients);

        Assert.That(copies, Has.Length.EqualTo(1), $"one copy, not {copies.Length}: " +
                                                   String.Join("; ", copies.Select(copy => $"{copy.TargetDomain} for {String.Join(", ", copy.EnvelopeTo)}")) + "\n" + transcript);
        Assert.That(copies[0].EnvelopeTo, Is.EquivalentTo(Recipients), "for both recipients\n" + transcript);

    }


    [Test(Description = "RFC 5321 §4.5.4.1 (a guard): recipients at two domains get a copy each")]
    [Property("Finding", "O-31")]
    public async Task Recipients_at_two_domains_get_two_copies()
    {

        var (copies, transcript) = await QueuedForRelay(false, "first@outbound.test", "second@other.test");

        Assert.That(copies, Has.Length.EqualTo(2), transcript);

    }

    #endregion

}
