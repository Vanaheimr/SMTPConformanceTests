using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 5321 §3.6.1, §4.5.1, §7.1: relaying and the reserved postmaster mailbox.
/// </summary>
[TestFixture]
public sealed class RelayAndPostmasterTests : HermodServerTestBase
{

    [Test(Description = "RFC 5321 §3.6.1, §7.1: an unauthenticated client cannot relay to a foreign domain (no open relay)")]
    public async Task Relay_to_a_foreign_domain_is_refused_without_authentication()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        await client.CommandAsync("MAIL FROM:<sender@client.example>");
        var reply = await client.CommandAsync("RCPT TO:<victim@elsewhere.example>");

        Assert.That(reply.Class, Is.EqualTo(5), Explain(client));

    }


    [Test(Description = "RFC 5321 §3.6.1: a refused relay recipient is not queued, even if the client goes on to DATA with another recipient")]
    public async Task A_refused_relay_recipient_is_never_queued()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var (_, rcpts) = await client.EnvelopeAsync("sender@client.example", "victim@elsewhere.example", "alice@hermod.test");
        await client.DataAsync(RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", Marker(), "x"));

        Assert.That(Server.Queue.Queued.SelectMany(q => q.EnvelopeTo), Does.Not.Contain("victim@elsewhere.example"), Explain(client));

    }


    [Test(Description = "RFC 5321 §2.4, §4.5.1: domain names are case-insensitive — a local domain in upper case is still local")]
    public async Task Local_domains_are_matched_case_insensitively()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        await client.CommandAsync("MAIL FROM:<sender@client.example>");
        var reply = await client.CommandAsync("RCPT TO:<alice@HERMOD.TEST>");

        Assert.That(reply.Code, Is.EqualTo(250), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.5.1: postmaster at a served domain MUST be accepted")]
    public async Task Postmaster_at_a_local_domain_is_accepted()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        await client.CommandAsync("MAIL FROM:<sender@client.example>");
        var reply = await client.CommandAsync("RCPT TO:<postmaster@hermod.test>");

        Assert.That(reply.Code, Is.EqualTo(250), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.5.1: \"the special case of 'RCPT TO:<Postmaster>' (with no domain specification), MUST be supported\"")]
    [Property("Finding", "S-10")]
    public async Task Postmaster_without_a_domain_is_accepted()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        await client.CommandAsync("MAIL FROM:<sender@client.example>");
        var reply = await client.CommandAsync("RCPT TO:<Postmaster>");

        Assert.That(reply.Code, Is.EqualTo(250), Explain(client));

    }

}
