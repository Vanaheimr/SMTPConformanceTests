using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 1870: SMTP Service Extension for Message Size Declaration.
/// </summary>
[TestFixture]
public sealed class SizeExtensionTests : HermodServerTestBase
{

    [Test(Description = "RFC 1870 §4: SIZE is advertised with the server's fixed maximum")]
    public async Task Size_is_advertised_with_the_limit()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        var (_, extensions) = await client.EhloAsync();

        Assert.That(extensions,          Does.ContainKey("SIZE"), Explain(client));
        Assert.That(extensions["SIZE"],  Is.EqualTo(Server.Config.MaxMessageSize.ToString()), Explain(client));

    }


    [Test(Description = "RFC 1870 §6.1: a declared SIZE= within the limit is accepted")]
    public async Task A_declared_size_within_the_limit_is_accepted()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var reply = await client.CommandAsync($"MAIL FROM:<sender@client.example> SIZE={Server.Config.MaxMessageSize / 2}");

        Assert.That(reply.Code, Is.EqualTo(250), Explain(client));

    }


    [Test(Description = "RFC 1870 §6.1: \"If the indicated size is larger than the server's fixed maximum message size, the server responds with code 552\" — at MAIL, before any data")]
    [Category(TestCategories.KnownIssue), Property("Finding", "S-7")]
    public async Task A_declared_size_above_the_limit_is_rejected_at_mail_with_552()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var reply = await client.CommandAsync($"MAIL FROM:<sender@client.example> SIZE={(Int64) Server.Config.MaxMessageSize + 1}");

        Assert.That(reply.Code, Is.EqualTo(552), Explain(client));

    }


    [Test(Description = "RFC 1870 §3, RFC 5321 §4.1.1.11: size-value ::= 1*20DIGIT — a non-numeric SIZE= is a parameter syntax error (501), not silently ignored")]
    [Category(TestCategories.KnownIssue), Property("Finding", "S-6")]
    public async Task A_non_numeric_size_is_rejected()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var reply = await client.CommandAsync("MAIL FROM:<sender@client.example> SIZE=huge");

        Assert.That(reply.Code, Is.AnyOf(501, 555), Explain(client));

    }


    [Test(Description = "RFC 1870 §6.3: a message that turns out larger than the limit is rejected with 552 after the end of data; the session stays usable")]
    public async Task An_oversized_message_is_rejected_with_552_after_data()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var body   = Enumerable.Repeat(new String('w', 900), Server.Config.MaxMessageSize / 900 + 10).ToArray();

        await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");
        var (_, final) = await client.DataAsync(RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", Marker(), body));
        var noop       = await client.CommandAsync("NOOP");

        Assert.Multiple(() => {
            Assert.That(final?.Code, Is.EqualTo(552), Explain(client));
            Assert.That(noop.Code,   Is.EqualTo(250), Explain(client));
        });

    }

}
