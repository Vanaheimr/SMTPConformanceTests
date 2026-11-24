using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// SMTPUTF8 (RFC 6531) as the submission client uses it: an internationalized message goes only
/// to a server that offers SMTPUTF8 (§3.2, §3.5), and the parameter goes only with a message that
/// needs it (§3.4) - not with one whose only non-ASCII octets are in an 8-bit body, which is
/// 8BITMIME's (RFC 6152).
/// </summary>
public sealed partial class SubmissionClientTests
{

    #region Setup

    private static readonly String[] WithoutSmtpUtf8 = [ "PIPELINING", "SIZE 10485760", "8BITMIME", "ENHANCEDSTATUSCODES", "DSN" ];
    private static readonly String[] WithSmtpUtf8    = [ .. WithoutSmtpUtf8, "SMTPUTF8" ];

    private static EMailEnvelop Utf8Message(String From, String To, String Subject, String Body = "hello")

        => new (EMail.Parse([
                    $"From: {From}",
                    $"To: {To}",
                    $"Subject: {Subject}",
                    "Content-Type: text/plain; charset=utf-8",
                    "Content-Transfer-Encoding: 8bit",
                    "",
                    Body
                ]));

    private static Boolean NonAscii(String Text)
        => Text.Any(c => c > '\x7F');

    /// <summary>
    /// The lines of the header the server received, up to the empty line.
    /// </summary>
    private static IEnumerable<String> HeaderLines(SmtpServerScript Script)
    {
        lock (Script.Transactions)
            return [ .. Script.Transactions.SelectMany(transaction => transaction.DataLines.Select(line => line.Latin1).TakeWhile(line => line.Length > 0)) ];
    }

    #endregion


    #region C-20: an internationalized message, a server without SMTPUTF8

    public static IEnumerable<TestCaseData> InternationalizedMessages()
    {

        TestCaseData Case(String Name, String From, String To, String Subject)
            => new TestCaseData(From, To, Subject).SetName($"No server without SMTPUTF8 gets an internationalized message: {Name}")
                                                  .SetCategory(TestCategories.KnownIssue)
                                                  .SetProperty("Finding", "C-20");

        yield return Case("a recipient with a UTF-8 local-part",  "app@client.example",  "jörg@scripted.test",  "hello");
        yield return Case("a sender with a UTF-8 local-part",     "jörg@client.example", "you@scripted.test",   "hello");
        yield return Case("a recipient in U-labels",              "app@client.example",  "you@bücher.test",     "hello");
        yield return Case("a Subject in UTF-8",                   "app@client.example",  "you@scripted.test",   "Grüße aus Köln");

    }

    [TestCaseSource(nameof(InternationalizedMessages))]
    [Description("RFC 6531 §3.2: \"If the SMTPUTF8 SMTP extension is not offered by the SMTP server, the SMTPUTF8-aware SMTP client MUST NOT transmit an internationalized email address and MUST NOT transmit a mail message containing internationalized mail headers\"; §3.5: \"An SMTPUTF8-aware SMTP client MUST NOT send an internationalized message to an SMTP server that does not support SMTPUTF8\" - the domain in A-labels is \"not considered to be internationalized\", nothing else is")]
    public async Task No_server_without_SMTPUTF8_gets_an_internationalized_message(String From, String To, String Subject)
    {

        var script = new SmtpServerScript { Extensions = WithoutSmtpUtf8 };
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        await client.Send(Utf8Message(From, To, Subject), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        List<String> commands;
        lock (script.Commands)
            commands = [ .. script.Commands.Select(command => command.Line) ];

        Assert.Multiple(() => {
            Assert.That(commands.Where(NonAscii),          Is.Empty, "no command with UTF-8 in it" + Explain(server));
            Assert.That(HeaderLines(script).Where(NonAscii), Is.Empty, "no header with UTF-8 in it" + Explain(server));
        });

    }

    [Test(Description = "RFC 6531 §3.4: \"If the envelope or message being sent requires the capabilities of the SMTPUTF8 extension, the SMTPUTF8-aware SMTP client MUST supply the SMTPUTF8 parameter with the MAIL command\" - to a server that offers it, a guard")]
    [Property("Finding", "C-20")]
    public async Task An_internationalized_message_goes_with_SMTPUTF8_to_a_server_that_offers_it()
    {

        var script = new SmtpServerScript { Extensions = WithSmtpUtf8 };
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        var result = await client.Send(Utf8Message("app@client.example", "jörg@scripted.test", "hello"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        var transaction = script.Transactions.SingleOrDefault();

        Assert.Multiple(() => {
            Assert.That(result,                     Is.EqualTo(MailSentStatus.ok), Explain(server));
            Assert.That(transaction?.MailFromLine,  Does.Contain(" SMTPUTF8"),     Explain(server));
        });

    }

    #endregion

    #region C-21: SMTPUTF8 for an 8-bit body

    [Test(Description = "RFC 6531 §3.4: \"If the SMTPUTF8-aware SMTP client is aware that neither the envelope nor the message being sent requires any of the SMTPUTF8 extension capabilities, it SHOULD NOT supply the SMTPUTF8 parameter\"; §3.6 - an 8-bit body is BODY=8BITMIME's (RFC 6152), not SMTPUTF8's")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "C-21")]
    public async Task An_8bit_body_alone_goes_without_SMTPUTF8()
    {

        var script = new SmtpServerScript { Extensions = WithSmtpUtf8 };
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        var result = await client.Send(Utf8Message("app@client.example", "you@scripted.test", "plain", "Grüße aus Köln"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        var transaction = script.Transactions.SingleOrDefault();

        Assume.That(transaction?.DataLines.Any(line => line.Bytes.Any(b => b > 0x7F)), Is.True, "the body went as 8-bit octets" + Explain(server));

        Assert.Multiple(() => {
            Assert.That(result,                     Is.EqualTo(MailSentStatus.ok),       Explain(server));
            Assert.That(transaction?.MailFromLine,  Does.Contain(" BODY=8BITMIME"),      Explain(server));
            Assert.That(transaction?.MailFromLine,  Does.Not.Contain("SMTPUTF8"),        Explain(server));
        });

    }

    [Test(Description = "RFC 6152 §3: an 8-bit body with ASCII header and envelope goes to a server with 8BITMIME and without SMTPUTF8 - it is no internationalized message, a guard")]
    [Property("Finding", "C-21")]
    public async Task An_8bit_body_alone_goes_to_a_server_without_SMTPUTF8()
    {

        var script = new SmtpServerScript { Extensions = WithoutSmtpUtf8 };
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        var result = await client.Send(Utf8Message("app@client.example", "you@scripted.test", "plain", "Grüße aus Köln"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        Assert.That(result, Is.EqualTo(MailSentStatus.ok), Explain(server));

    }

    #endregion

}
