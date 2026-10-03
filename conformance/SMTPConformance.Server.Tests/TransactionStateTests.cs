using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 5321 §3.3, §4.1.4 and §4.3.2: the order of commands within a transaction.
/// </summary>
[TestFixture]
public sealed class TransactionStateTests : HermodServerTestBase
{

    [Test(Description = "RFC 5321 §4.1.4, §4.3.2: MAIL before EHLO/HELO is a bad sequence (503)")]
    public async Task Mail_before_ehlo_is_503()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        var reply = await client.CommandAsync("MAIL FROM:<sender@client.example>");

        Assert.That(reply.Code, Is.EqualTo(503), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.3.2: RCPT without MAIL is a bad sequence (503)")]
    public async Task Rcpt_without_mail_is_503()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var reply = await client.CommandAsync("RCPT TO:<alice@hermod.test>");

        Assert.That(reply.Code, Is.EqualTo(503), Explain(client));

    }


    [Test(Description = "RFC 5321 §3.3, §4.3.2: DATA without an accepted recipient fails with 503 (or 554 'no valid recipients')")]
    public async Task Data_without_rcpt_fails()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        await client.CommandAsync("MAIL FROM:<sender@client.example>");
        var reply = await client.CommandAsync("DATA");

        Assert.That(reply.Code, Is.AnyOf(503, 554), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.4, §4.3.2: \"MAIL ... MUST NOT be sent if a mail transaction is already open\"; the server's answer to a second MAIL is 503")]
    [Property("Finding", "S-9")]
    public async Task A_second_mail_inside_a_transaction_is_503()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var first  = await client.CommandAsync("MAIL FROM:<first@client.example>");
        Assume.That(first.Code, Is.EqualTo(250), Explain(client));

        var second = await client.CommandAsync("MAIL FROM:<second@client.example>");

        Assert.That(second.Code, Is.EqualTo(503), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.1.5: RSET discards sender and recipients — DATA afterwards has nothing to send")]
    public async Task Rset_discards_the_transaction()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");
        var rset = await client.CommandAsync("RSET");
        var data = await client.CommandAsync("DATA");

        Assert.Multiple(() => {
            Assert.That(rset.Code, Is.EqualTo(250), Explain(client));
            Assert.That(data.Code, Is.AnyOf(503, 554), Explain(client));
        });

    }


    [Test(Description = "RFC 5321 §4.1.1.5: RSET with no transaction open is still 250")]
    public async Task Rset_without_a_transaction_is_250()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var reply = await client.CommandAsync("RSET");

        Assert.That(reply.Code, Is.EqualTo(250), Explain(client));

    }


    [Test(Description = "RFC 5321 §3.3: a session may carry several transactions; each is delivered")]
    public async Task Two_transactions_in_one_session_are_both_delivered()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var first   = Marker();
        var second  = Marker();

        var reply1  = await client.SendMailAsync("sender@client.example", "alice@hermod.test",
                                                 RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", first,  "one"));
        var reply2  = await client.SendMailAsync("sender@client.example", "alice@hermod.test",
                                                 RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", second, "two"));

        Assert.Multiple(async () => {
            Assert.That(reply1.Code, Is.EqualTo(250), Explain(client));
            Assert.That(reply2.Code, Is.EqualTo(250), Explain(client));
            Assert.That(await Server.Storage.WaitForMarkerAsync(first),  Is.Not.Null);
            Assert.That(await Server.Storage.WaitForMarkerAsync(second), Is.Not.Null);
        });

    }


    [Test(Description = "RFC 5321 §4.1.1.4: a completed DATA ends the transaction — RCPT afterwards finds none open (503)")]
    public async Task After_data_the_transaction_is_closed()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var final = await client.SendMailAsync("sender@client.example", "alice@hermod.test");
        Assume.That(final.Code, Is.EqualTo(250), Explain(client));

        var rcpt  = await client.CommandAsync("RCPT TO:<alice@hermod.test>");

        Assert.That(rcpt.Code, Is.EqualTo(503), Explain(client));

    }


    [Test(Description = "RFC 5321 §3.3: every accepted recipient receives the message; the envelope reaches storage unchanged")]
    public async Task Envelope_reaches_storage()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var marker          = Marker();
        var (mail, rcpts)   = await client.EnvelopeAsync("sender@client.example", "alice@hermod.test", "bob@hermod.test");
        var (data, final)   = await client.DataAsync(RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", marker, "body"));

        Assume.That(final?.Code, Is.EqualTo(250), Explain(client));

        var stored = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.That(stored, Is.Not.Null, Explain(client));
        Assert.Multiple(() => {
            Assert.That(stored!.EnvelopeFrom, Is.EqualTo("sender@client.example"));
            Assert.That(stored.EnvelopeTo,    Is.EquivalentTo(new[] { "alice@hermod.test", "bob@hermod.test" }));
        });

    }


    [Test(Description = "RFC 5321 §4.5.3.1.8: at least 100 recipients per transaction must be accepted")]
    public async Task One_hundred_recipients_are_accepted()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var (mail, rcpts) = await client.EnvelopeAsync("sender@client.example",
                                                       [.. Enumerable.Range(1, 100).Select(i => $"user{i}@hermod.test")]);

        Assert.That(rcpts.Select(r => r.Code), Is.All.EqualTo(250), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.5.3.1.10: recipients beyond the server's limit are answered with 452 (not 552, not 5xx)")]
    public async Task Recipients_beyond_the_limit_get_452()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var (mail, rcpts) = await client.EnvelopeAsync("sender@client.example",
                                                       [.. Enumerable.Range(1, Server.Config.MaxRecipients + 1).Select(i => $"user{i}@hermod.test")]);

        Assert.That(rcpts[^1].Code, Is.EqualTo(452), Explain(client));

    }

}
