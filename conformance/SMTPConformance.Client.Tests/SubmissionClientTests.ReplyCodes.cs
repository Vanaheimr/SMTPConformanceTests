using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

public sealed partial class SubmissionClientTests
{

    #region C-15: a reply code is read by its first digit

    // RFC 5321 §4.2.1: "a sender-SMTP MUST be prepared to handle codes not specified in this
    // document and MUST do so by interpreting the first digit only."

    public static IEnumerable<TestCaseData> OtherPositiveCodes()
    {

        TestCaseData Case(String Name, Func<SmtpServerScript> Script)
            => new TestCaseData(Script).SetName($"Submission, another positive code: {Name}")
                                       .SetCategory(TestCategories.KnownIssue)
                                       .SetProperty("Finding", "C-15");

        yield return Case("252 to MAIL",                  () => new SmtpServerScript { MailReply      = "252 2.1.0 Sender accepted" });
        yield return Case("252 to RCPT",                  () => new SmtpServerScript { RcptReply      = _ => "252 2.1.5 Recipient accepted" });
        yield return Case("350 to DATA",                  () => new SmtpServerScript { DataReply      = "350 Send the message, end with <CRLF>.<CRLF>" });
        yield return Case("251 to the end of data",       () => new SmtpServerScript { EndOfDataReply = "251 2.0.0 Queued as 4711" });
        yield return Case("252 to MAIL, no PIPELINING",   () => new SmtpServerScript { MailReply      = "252 2.1.0 Sender accepted", Extensions = [ "8BITMIME", "ENHANCEDSTATUSCODES" ] });

    }


    [TestCaseSource(nameof(OtherPositiveCodes))]
    [Description("RFC 5321 §4.2.1: a 2yz is \"Positive Completion\", a 3yz \"Positive Intermediate\" - whatever the other two digits, the client goes on, and a message the server took is sent")]
    public async Task Another_positive_code_is_read_by_its_first_digit(Func<SmtpServerScript> Script)
    {

        var script = Script();
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        var result = await client.Send(Message("hello"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        Assert.Multiple(() => {
            Assert.That(script.Transactions.Single().DataLines, Is.Not.Empty,                  Explain(server));
            Assert.That(result,                                 Is.EqualTo(MailSentStatus.ok), Explain(server));
        });

    }


    public static IEnumerable<TestCaseData> SubmissionBareCodes()
    {

        TestCaseData Case(String Name, Func<SmtpServerScript> Script)
            => new TestCaseData(Script).SetName($"Submission, a code without text: {Name}");

        yield return Case("MAIL",             () => new SmtpServerScript { MailReply      = "250" });
        yield return Case("RCPT",             () => new SmtpServerScript { RcptReply      = _ => "250 " });
        yield return Case("DATA",             () => new SmtpServerScript { DataReply      = "354" });
        yield return Case("the end of data",  () => new SmtpServerScript { EndOfDataReply = "250" });

    }


    [TestCaseSource(nameof(SubmissionBareCodes))]
    [Description("RFC 5321 §4.2: \"clients that do not receive it SHOULD be prepared to process the code alone (with or without a trailing space character)\" (a guard)")]
    public async Task A_code_without_text_is_read(Func<SmtpServerScript> Script)
    {

        var script = Script();
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        var result = await client.Send(Message("hello"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        Assert.Multiple(() => {
            Assert.That(script.Transactions.Single().DataLines, Is.Not.Empty,                  Explain(server));
            Assert.That(result,                                 Is.EqualTo(MailSentStatus.ok), Explain(server));
        });

    }

    #endregion

}
