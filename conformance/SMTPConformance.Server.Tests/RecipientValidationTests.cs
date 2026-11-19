using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SMTP.Server;

using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 5321 §3.3, §4.5.1, §6.1 and RFC 3463: what the server answers at RCPT once it knows
/// its mailboxes - one that does not exist, one that is full, a question that cannot be
/// answered now, the postmaster - and at the end of data when its storage fails.
/// </summary>
[TestFixture]
public sealed class RecipientValidationTests : HermodServerTestBase
{

    /// <summary>
    /// The mailboxes of hermod.test: alice exists, "full" has no room left, "busy" cannot be
    /// asked about now, "broken" makes the directory throw; nobody else exists.
    /// </summary>
    private sealed class Mailboxes : IRecipientValidator
    {
        public async Task<RecipientCheck> CheckAsync(String recipient, CancellationToken ct = default)
        {

            await Task.Yield();

            return recipient.Split('@')[0].ToLowerInvariant() switch {
                       "alice"   => RecipientCheck.Accept,
                       "full"    => RecipientCheck.Full,
                       "busy"    => RecipientCheck.TryLater,
                       "broken"  => throw new IOException("The test's mailbox directory is unreachable."),
                       _         => RecipientCheck.Unknown
                   };

        }
    }

    protected override HermodSmtpServerFixtureOptions Options
        => new() { RecipientValidator = new Mailboxes() };


    [Test(Description = "RFC 5321 §3.3: a recipient \"known not to be a deliverable address\" gets 550; RFC 3463 X.1.1 \"Bad destination mailbox address\"")]
    public async Task An_unknown_mailbox_is_refused_at_RCPT()
    {

        await using var client = await Server.ConnectAndEhloAsync();
        var (_, rcpts) = await client.EnvelopeAsync("sender@client.example", "nobody@hermod.test");

        Assert.Multiple(() => {
            Assert.That(rcpts[0].Code,          Is.EqualTo(550),      Explain(client));
            Assert.That(rcpts[0].EnhancedCode,  Is.EqualTo("5.1.1"),  Explain(client));
        });

    }


    [Test(Description = "RFC 3463 X.2.2: a full mailbox \"should be used as a persistent transient failure\" - 4.2.2 at RCPT, and the transaction goes on for the other recipients")]
    public async Task A_full_mailbox_is_a_transient_failure_and_the_transaction_goes_on()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var marker = Marker();
        var (_, rcpts) = await client.EnvelopeAsync("sender@client.example", "full@hermod.test", "alice@hermod.test");
        var (_, final) = await client.DataAsync(RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", marker, "x"));
        var stored     = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.Multiple(() => {
            Assert.That(rcpts[0].Class,         Is.EqualTo(4),                             Explain(client));
            Assert.That(rcpts[0].EnhancedCode,  Is.EqualTo("4.2.2"),                       Explain(client));
            Assert.That(rcpts[1].Code,          Is.EqualTo(250),                           Explain(client));
            Assert.That(final?.Code,            Is.EqualTo(250),                           Explain(client));
            Assert.That(stored?.EnvelopeTo,     Is.EqualTo(new[] { "alice@hermod.test" }), "only the recipient that was taken");
        });

    }


    [TestCase("busy@hermod.test",   TestName = "A mailbox the directory cannot answer for now")]
    [TestCase("broken@hermod.test", TestName = "A mailbox directory that fails")]
    [Test(Description = "RFC 5321 §4.2.1: a recipient that cannot be decided now is a transient failure (4yz) - not a refusal, and not a 250 for a message with nowhere to go")]
    public async Task A_recipient_that_cannot_be_decided_now_is_a_transient_failure(String Recipient)
    {

        await using var client = await Server.ConnectAndEhloAsync();
        var (_, rcpts) = await client.EnvelopeAsync("sender@client.example", Recipient);

        Assert.That(rcpts[0].Class, Is.EqualTo(4), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.5.1: postmaster at a served domain, and <Postmaster> without one, MUST be accepted - also by a server whose directory knows no such mailbox")]
    public async Task The_postmaster_is_accepted_whatever_the_directory_says()
    {

        await using var client = await Server.ConnectAndEhloAsync();
        var (_, rcpts) = await client.EnvelopeAsync("sender@client.example", "postmaster@hermod.test", "Postmaster");

        Assert.That(rcpts.Select(rcpt => rcpt.Code), Is.EqualTo(new[] { 250, 250 }), Explain(client));

    }


    [Test(Description = "RFC 5321 §6.1: with 250 at the end of data the server takes responsibility, and \"MUST NOT lose the message\" - a storage that fails is a transient failure, not a 250")]
    public async Task A_storage_that_fails_is_a_transient_failure()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var marker = Marker();
        Server.Storage.FailFor = marker;

        var (_, rcpts) = await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");
        var (_, final) = await client.DataAsync(RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", marker, "x"));

        Assert.Multiple(() => {
            Assert.That(rcpts[0].Code,  Is.EqualTo(250),  Explain(client));
            Assert.That(final?.Class,   Is.EqualTo(4),    Explain(client));
        });

    }

}


/// <summary>
/// RFC 5321 §6.1: a server without a queue has nowhere to put a relayed message.
/// </summary>
[TestFixture]
public sealed class RelayWithoutQueueTests : HermodServerTestBase
{

    protected override HermodSmtpServerFixtureOptions Options
        => new() { EnableTls = true, WithQueue = false };


    [Test(Description = "RFC 5321 §6.1: a relayed recipient the server has no way to deliver to is refused at RCPT - not taken with 250 and then lost")]
    public async Task A_relayed_recipient_with_nowhere_to_go_is_refused()
    {

        await using var client = await Server.ConnectSignedInAsync();
        var (mail, rcpts) = await client.EnvelopeAsync("alice@hermod.test", "bob@elsewhere.example");

        Assert.Multiple(() => {
            Assert.That(mail.Code,      Is.EqualTo(250),  Explain(client));
            Assert.That(rcpts[0].Class, Is.EqualTo(5),    Explain(client));
        });

    }

}
