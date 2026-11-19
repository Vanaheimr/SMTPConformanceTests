using System.Collections.Concurrent;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;
using org.GraphDefined.Vanaheimr.Hermod.SMTP.Server;

using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 6409: the mail of a client that signed in, handed to the application that takes
/// submissions - its sender checked at MAIL (§6.1), the whole message with its trace field
/// (RFC 5321 §4.4), the application's refusal as the answer, and a failure that loses
/// nothing (RFC 5321 §6.1).
/// </summary>
[TestFixture]
public sealed class MailSubmissionTests : HermodServerTestBase
{

    private sealed record Submission(String Raw, String User, String EnvelopeFrom, IReadOnlyList<String> EnvelopeTo);

    /// <summary>
    /// The application: alice may send as alice@hermod.test only; a subject that says so is
    /// refused, or makes it throw; everything else is taken and kept.
    /// </summary>
    private sealed class Application : IMailSubmission
    {

        public readonly ConcurrentQueue<Submission> Submissions = new();

        public Task<SMTPRefusal?> CheckSenderAsync(String User, String EnvelopeFrom, CancellationToken CancellationToken = default)

            => Task.FromResult(EnvelopeFrom.Equals(User + "@hermod.test", StringComparison.OrdinalIgnoreCase)
                                   ? null
                                   : new SMTPRefusal(550, "5.7.1 Not an address of yours"));

        public async Task<SMTPRefusal?> SubmitAsync(EMailMessage           Message,
                                                     String                 User,
                                                     String                 EnvelopeFrom,
                                                     IReadOnlyList<String>  EnvelopeTo,
                                                     CancellationToken      CancellationToken = default)
        {

            await Task.Yield();

            if (Message.RawMessage.Contains("refuse-me", StringComparison.Ordinal))
                return new SMTPRefusal(554, "5.7.1 The application says no");

            if (Message.RawMessage.Contains("throw-me", StringComparison.Ordinal))
                throw new IOException("The test's application is down.");

            Submissions.Enqueue(new Submission(Message.RawMessage, User, EnvelopeFrom, EnvelopeTo));
            return null;

        }

        public async Task<Submission?> WaitForMarkerAsync(String Marker)
        {
            for (var i = 0; i < 250; i++)
            {
                var match = Submissions.FirstOrDefault(submission => submission.Raw.Contains(Marker, StringComparison.Ordinal));
                if (match is not null)
                    return match;
                await Task.Delay(20);
            }
            return null;
        }

    }

    private readonly Application application = new();

    protected override HermodSmtpServerFixtureOptions Options
        => new() { EnableTls = true, MailSubmission = application };


    [Test(Description = "RFC 6409 §3, RFC 5321 §4.4: a submitted message goes to the application whole - every recipient, local and remote, in order, the account, and this server's Received: at the beginning")]
    public async Task A_submitted_message_goes_to_the_application_whole()
    {

        await using var client = await Server.ConnectSignedInAsync();

        var marker = Marker();
        var (mail, rcpts) = await client.EnvelopeAsync("alice@hermod.test", "bob@elsewhere.example", "carol@hermod.test");
        var (_, final)    = await client.DataAsync(RawSmtpClientExtensions.Message("alice@hermod.test", "bob@elsewhere.example", marker, "x"));
        var submission    = await application.WaitForMarkerAsync(marker);

        Assert.Multiple(() => {
            Assert.That(mail.Code,                                Is.EqualTo(250),                                                       Explain(client));
            Assert.That(rcpts.Select(rcpt => rcpt.Code),          Is.EqualTo(new[] { 250, 250 }),                                        Explain(client));
            Assert.That(final?.Code,                              Is.EqualTo(250),                                                       Explain(client));
            Assert.That(submission?.User,                         Is.EqualTo("alice"));
            Assert.That(submission?.EnvelopeFrom,                 Is.EqualTo("alice@hermod.test"));
            Assert.That(submission?.EnvelopeTo,                   Is.EqualTo(new[] { "bob@elsewhere.example", "carol@hermod.test" }));
            Assert.That(submission?.Raw,                          Does.StartWith("Received:"),                                           "trace field first");
            Assert.That(Server.Storage.CountWithMarker(marker),   Is.Zero,                                                               "not stored by the server as well");
            Assert.That(Server.Queue.Queued.Any(queued => queued.EnvelopeTo.Contains("bob@elsewhere.example") && queued.EnvelopeFrom == "alice@hermod.test"),
                        Is.False, "not queued by the server as well");
        });

    }


    [Test(Description = "RFC 6409 §6.1: \"The MSA MAY issue an error response to a MAIL command if the address in MAIL FROM ... is not authorized with the authentication used\" - 550, 5.7.1")]
    public async Task A_sender_the_account_may_not_use_is_refused_at_MAIL()
    {

        await using var client = await Server.ConnectSignedInAsync();

        var reply = await client.CommandAsync("MAIL FROM:<ceo@hermod.test>");

        Assert.Multiple(() => {
            Assert.That(reply.Code,          Is.EqualTo(550),      Explain(client));
            Assert.That(reply.EnhancedCode,  Is.EqualTo("5.7.1"),  Explain(client));
        });

    }


    [Test(Description = "RFC 5321 §4.2.5: the application's refusal of a message is the reply to the end of data, and nothing of it is delivered")]
    public async Task The_applications_refusal_is_the_reply_to_the_end_of_data()
    {

        await using var client = await Server.ConnectSignedInAsync();

        var marker = Marker();
        await client.EnvelopeAsync("alice@hermod.test", "bob@elsewhere.example");
        var (_, final) = await client.DataAsync(RawSmtpClientExtensions.Message("alice@hermod.test", "bob@elsewhere.example", marker + " refuse-me", "x"));

        Assert.Multiple(() => {
            Assert.That(final?.Code,                              Is.EqualTo(554),      Explain(client));
            Assert.That(final?.EnhancedCode,                      Is.EqualTo("5.7.1"),  Explain(client));
            Assert.That(Server.Storage.CountWithMarker(marker),   Is.Zero,              "not stored instead");
        });

    }


    [Test(Description = "RFC 5321 §6.1: an application that fails has not taken the message - a transient failure (4yz), so the client keeps it and tries again")]
    public async Task An_application_that_fails_is_a_transient_failure()
    {

        await using var client = await Server.ConnectSignedInAsync();

        var marker = Marker();
        await client.EnvelopeAsync("alice@hermod.test", "bob@elsewhere.example");
        var (_, final) = await client.DataAsync(RawSmtpClientExtensions.Message("alice@hermod.test", "bob@elsewhere.example", marker + " throw-me", "x"));

        Assert.That(final?.Class, Is.EqualTo(4), Explain(client));

    }


    [Test(Description = "RFC 6409 §3.1: mail that arrives from another server, not signed in, is not a submission - it is delivered locally, not handed to the application (a guard)")]
    public async Task Mail_from_another_server_is_not_a_submission()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var marker = Marker();
        var final  = await client.SendMailAsync("sender@client.example", "alice@hermod.test",
                                                RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", marker, "x"));

        Assert.Multiple(async () => {
            Assert.That(final.Code,                                          Is.EqualTo(250),  Explain(client));
            Assert.That(await Server.Storage.WaitForMarkerAsync(marker),     Is.Not.Null,      "stored");
            Assert.That(application.Submissions.Any(submission => submission.Raw.Contains(marker)), Is.False, "not submitted");
        });

    }

}
