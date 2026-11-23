using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

public sealed partial class OutboundClientTests
{

    #region O-15: a reply code is read by its first digit

    // RFC 5321 §4.2.1: "a sender-SMTP MUST be prepared to handle codes not specified in this
    // document and MUST do so by interpreting the first digit only." A 2yz is "Positive
    // Completion", a 3yz "Positive Intermediate": the transaction goes on.

    [Test(Description = "RFC 5321 §4.2.1: MAIL answered with a 2yz other than 250 is accepted - the relay goes on with RCPT and DATA, and does not report the message delivered unsent")]
    [Property("Finding", "O-15")]
    public async Task MAIL_answered_with_another_2yz_goes_on_to_the_message()
    {

        var script = new SmtpServerScript { MailReply = "252 2.1.0 Sender accepted" };
        await using var server = ScriptedSmtpServer.Start(script);

        var result = await SendDirect(server, Envelope([ "you@outbound.test" ]));

        Assert.Multiple(() => {
            Assert.That(script.Transactions.Single().RcptToLines, Is.Not.Empty, "RCPT after a 2yz to MAIL" + Explain(server));
            Assert.That(script.Transactions.Single().DataLines,   Is.Not.Empty, "the message was not sent" + Explain(server));
            Assert.That(result.Status,                            Is.EqualTo(SendStatus.Success), Explain(server));
        });

    }


    [Test(Description = "RFC 5321 §4.2.1: DATA answered with a 3yz other than 354 is the go-ahead - the relay sends the message")]
    [Property("Finding", "O-15")]
    public async Task DATA_answered_with_another_3yz_sends_the_message()
    {

        var script = new SmtpServerScript { DataReply = "350 Send the message, end with <CRLF>.<CRLF>" };
        await using var server = ScriptedSmtpServer.Start(script);

        var result = await SendDirect(server, Envelope([ "you@outbound.test" ]));

        Assert.Multiple(() => {
            Assert.That(script.Transactions.Single().DataLines, Is.Not.Empty, Explain(server));
            Assert.That(result.Status,                          Is.EqualTo(SendStatus.Success), Explain(server));
        });

    }


    [Test(Description = "RFC 5321 §4.2.1: RCPT answered with a 2yz other than 250 and 251 accepts the recipient (a guard)")]
    [Property("Finding", "O-15")]
    public async Task RCPT_answered_with_another_2yz_accepts_the_recipient()
    {

        var script = new SmtpServerScript { RcptReply = _ => "252 2.1.5 Recipient accepted" };
        await using var server = ScriptedSmtpServer.Start(script);

        var result = await SendDirect(server, Envelope([ "you@outbound.test" ]));

        Assert.Multiple(() => {
            Assert.That(script.Transactions.Single().DataLines, Is.Not.Empty, Explain(server));
            Assert.That(result.Status,                          Is.EqualTo(SendStatus.Success), Explain(server));
        });

    }


    [Test(Description = "RFC 5321 §4.2.1: the end of data answered with a 2yz other than 250 is a delivery (a guard)")]
    [Property("Finding", "O-15")]
    public async Task The_end_of_data_answered_with_another_2yz_is_a_delivery()
    {

        var script = new SmtpServerScript { EndOfDataReply = "251 2.0.0 Queued as 4711" };
        await using var server = ScriptedSmtpServer.Start(script);

        var result = await SendDirect(server, Envelope([ "you@outbound.test" ]));

        Assert.That(result.Status, Is.EqualTo(SendStatus.Success), Explain(server));

    }


    public static IEnumerable<TestCaseData> BareCodes()
    {

        TestCaseData Case(String Name, Func<SmtpServerScript> Script)
            => new TestCaseData(Script).SetName($"Relay, a code without text: {Name}");

        yield return Case("MAIL",             () => new SmtpServerScript { MailReply      = "250" });
        yield return Case("RCPT",             () => new SmtpServerScript { RcptReply      = _ => "250 " });
        yield return Case("DATA",             () => new SmtpServerScript { DataReply      = "354" });
        yield return Case("the end of data",  () => new SmtpServerScript { EndOfDataReply = "250" });

    }


    [TestCaseSource(nameof(BareCodes))]
    [Description("RFC 5321 §4.2: \"clients that do not receive it SHOULD be prepared to process the code alone (with or without a trailing space character)\" (a guard)")]
    public async Task A_code_without_text_is_read(Func<SmtpServerScript> Script)
    {

        var script = Script();
        await using var server = ScriptedSmtpServer.Start(script);

        var result = await SendDirect(server, Envelope([ "you@outbound.test" ]));

        Assert.Multiple(() => {
            Assert.That(script.Transactions.Single().DataLines, Is.Not.Empty, Explain(server));
            Assert.That(result.Status,                          Is.EqualTo(SendStatus.Success), Explain(server));
        });

    }

    #endregion

    #region O-16: 552 to RCPT, too many recipients

    [Test(Description = "RFC 5321 §4.5.3.1.10: \"Clients SHOULD treat a 552 code in this case as a temporary, rather than permanent, failure\" - a recipient refused with 552 5.5.3 (too many recipients) is tried again in a later transaction, not bounced")]
    [Property("Finding", "O-16")]
    public async Task A_recipient_refused_with_552_too_many_recipients_is_retried_not_bounced()
    {

        var script = new SmtpServerScript { RcptReply = rcpt => rcpt.StartsWith("second") ? "552 5.5.3 Too many recipients" : "250 2.1.5 ok" };
        await using var server = ScriptedSmtpServer.Start(script);

        var (queue, original) = await Relay(server, "first@outbound.test", "second@outbound.test");

        var bounce = queue.Queued.FirstOrDefault(mail => mail.EnvelopeFrom.Length == 0);
        var retry  = queue.Queued.FirstOrDefault(mail => mail.Id != original.Id && mail.EnvelopeTo.Contains("second@outbound.test") && mail.EnvelopeFrom.Length > 0);

        Assert.Multiple(() => {
            Assert.That(original.Status, Is.EqualTo(QueueItemStatus.Delivered),                       Explain(server));
            Assert.That(bounce,          Is.Null,     "second@ was bounced: " + bounce?.MessageContent + Explain(server));
            Assert.That(retry,           Is.Not.Null, "second@ is not queued again" + Explain(server));
            Assert.That(retry?.Status,   Is.EqualTo(QueueItemStatus.Deferred),                        Explain(server));
        });

    }


    [Test(Description = "RFC 5321 §4.5.3.1.10 and RFC 3463 §3.6: 552 to RCPT after recipients were accepted is the RFC 821 code of a full recipients buffer - retried, not bounced")]
    [Property("Finding", "O-16")]
    public async Task A_recipient_refused_with_a_bare_552_after_others_were_accepted_is_retried()
    {

        var script = new SmtpServerScript { RcptReply = rcpt => rcpt.StartsWith("second") ? "552 Too many recipients" : "250 2.1.5 ok" };
        await using var server = ScriptedSmtpServer.Start(script);

        var (queue, original) = await Relay(server, "first@outbound.test", "second@outbound.test");

        var bounce = queue.Queued.FirstOrDefault(mail => mail.EnvelopeFrom.Length == 0);
        var retry  = queue.Queued.FirstOrDefault(mail => mail.Id != original.Id && mail.EnvelopeTo.Contains("second@outbound.test") && mail.EnvelopeFrom.Length > 0);

        Assert.Multiple(() => {
            Assert.That(bounce, Is.Null,     "second@ was bounced: " + bounce?.MessageContent + Explain(server));
            Assert.That(retry,  Is.Not.Null, "second@ is not queued again" + Explain(server));
        });

    }


    [Test(Description = "RFC 5321 §4.2.1: 550 to RCPT stays a permanent refusal - bounced, not retried (a guard)")]
    [Property("Finding", "O-16")]
    public async Task A_recipient_refused_with_550_is_still_bounced()
    {

        var script = new SmtpServerScript { RcptReply = rcpt => rcpt.StartsWith("second") ? "550 5.1.1 No such user" : "250 2.1.5 ok" };
        await using var server = ScriptedSmtpServer.Start(script);

        var (queue, original) = await Relay(server, "first@outbound.test", "second@outbound.test");

        var bounce = queue.Queued.FirstOrDefault(mail => mail.EnvelopeFrom.Length == 0);

        Assert.That(bounce, Is.Not.Null, Explain(server));

    }

    #endregion

}
