using System.Text.RegularExpressions;

using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 6710 MT-PRIORITY on the server: the EHLO keyword, the MAIL parameter's grammar -
/// priority-value = (["-"] NZDIGIT) / "0" (§7) - and what becomes of a priority: who may
/// raise one (§4.1), where it is written down (§4.1), what the relay queue carries on (§4.2).
/// </summary>
[TestFixture]
public sealed class PriorityTests : HermodServerTestBase
{

    // Relaying without AUTH: a client nobody vouches for - as on port 25 between servers.
    protected override HermodSmtpServerFixtureOptions Options
        => new() { RequireAuthForRelay = false };


    [Test(Description = "RFC 6710 §3: the server announces MT-PRIORITY in its EHLO reply")]
    public async Task EHLO_announces_MT_PRIORITY()
    {

        var (client, _)          = await Server.ConnectMtaAsync();
        await using var _client  = client;
        var (ehlo, extensions)   = await client.EhloAsync();

        Assert.That(extensions.Keys, Has.Member("MT-PRIORITY"), Explain(client));

    }


    [TestCase("-9")]
    [TestCase("-1")]
    [TestCase("0")]
    [TestCase("3")]
    [TestCase("9")]
    [Test(Description = "RFC 6710 §7: priority-value = ([\"-\"] NZDIGIT) / \"0\" - every value from -9 to 9 is taken")]
    public async Task Every_priority_from_minus_9_to_9_is_taken(String Value)
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var mail = await client.CommandAsync($"MAIL FROM:<sender@client.example> MT-PRIORITY={Value}");

        Assert.That(mail.Code, Is.EqualTo(250), Explain(client));

    }


    [TestCase("10")]
    [TestCase("-10")]
    [TestCase("high")]
    [TestCase("")]
    [Test(Description = "RFC 6710 §4.1: \"the server MUST return an error\" for a syntactically invalid value - outside -9..9, no number, none")]
    public async Task A_value_outside_the_grammar_is_refused(String Value)
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var mail = await client.CommandAsync($"MAIL FROM:<sender@client.example> MT-PRIORITY={Value}");

        Assert.That(mail.Code, Is.EqualTo(501), Explain(client));

    }


    [TestCase("+3",  Description = "no plus sign")]
    [TestCase("-0",  Description = "no minus zero")]
    [TestCase("05",  Description = "no leading zero")]
    [Test(Description = "RFC 6710 §7: priority-value = ([\"-\"] NZDIGIT) / \"0\" - no \"+\", no \"-0\", no leading zero; §4.1: a syntactically invalid value MUST be refused")]
    [Category(TestCategories.KnownIssue), Property("Finding", "Q-1")]
    public async Task A_value_the_grammar_does_not_produce_is_refused(String Value)
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var mail = await client.CommandAsync($"MAIL FROM:<sender@client.example> MT-PRIORITY={Value}");

        Assert.That(mail.Code, Is.EqualTo(501), Explain(client));

    }


    [Test(Description = "RFC 6710 §4.1: the server MUST return an error \"if there is more than one MT-PRIORITY parameter\" - the same value twice too")]
    [Category(TestCategories.KnownIssue), Property("Finding", "Q-2")]
    public async Task MT_PRIORITY_twice_is_refused()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var mail = await client.CommandAsync("MAIL FROM:<sender@client.example> MT-PRIORITY=3 MT-PRIORITY=3");

        Assert.That(mail.Code, Is.EqualTo(501), Explain(client));

    }


    [Test(Description = "RFC 6710 §4.1: \"MUST NOT allow \"upgraded\" (positive) priorities from untrusted\" senders - a client that did not sign in relays at 0 at most")]
    [Category(TestCategories.KnownIssue), Property("Finding", "Q-3")]
    public async Task A_client_nobody_vouches_for_does_not_raise_its_priority()
    {

        var marker = Marker();

        await using var client = await Server.ConnectAndEhloAsync("mx.client.example");

        var mail   = await client.CommandAsync("MAIL FROM:<sender@client.example> MT-PRIORITY=7");
        var rcpt   = await client.CommandAsync("RCPT TO:<bob@remote.example>");
        var (_, final) = await client.DataAsync($"Subject: {marker}\r\n\r\nurgent, says who?\r\n");

        Assert.That(final?.Code, Is.EqualTo(250), Explain(client));

        var queued = Server.Queue.Queued.Single(mail => mail.MessageContent.Contains(marker));

        Assert.That(queued.Priority, Is.LessThanOrEqualTo(0), Explain(client));

    }


    [Test(Description = "RFC 6710 §4.1: an MTA SHOULD write the priority into the Received field - Pri = CFWS \"PRIORITY\" FWS priority-value")]
    [Category(TestCategories.KnownIssue), Property("Finding", "Q-4")]
    public async Task The_Received_field_names_the_priority()
    {

        var marker = Marker();

        await using var client = await Server.ConnectAndEhloAsync("mx.client.example");

        await client.CommandAsync("MAIL FROM:<sender@client.example> MT-PRIORITY=-3");
        await client.CommandAsync("RCPT TO:<alice@hermod.test>");
        var (_, final) = await client.DataAsync($"Subject: {marker}\r\n\r\nno hurry\r\n");

        Assert.That(final?.Code, Is.EqualTo(250), Explain(client));

        var stored   = await Server.Storage.WaitForMarkerAsync(marker);
        var received = Regex.Match(stored!.Raw, @"^Received:(?<value>[^\r\n]*(?:\r\n[ \t][^\r\n]*)*)", RegexOptions.Multiline).Groups["value"].Value;

        Assert.That(Regex.IsMatch(received, @"\sPRIORITY\s+-3(\s|;|$)"), Is.True, "Received:" + received);

    }

}


/// <summary>
/// RFC 6710 §4.2: what a client that signed in asked for, the relay queue carries on to the next hop.
/// </summary>
[TestFixture]
public sealed class PriorityOfSignedInClientsTests : HermodServerTestBase
{

    protected override HermodSmtpServerFixtureOptions Options
        => new() { EnableTls = true };


    [TestCase(7)]
    [TestCase(-4)]
    [Test(Description = "RFC 6710 §4.2: the priority \"as determined in Section 4.1\" goes with the message to the next hop - for a client that signed in, the one it asked for")]
    public async Task The_relay_queue_carries_the_priority_a_signed_in_client_asked_for(Int32 Priority)
    {

        var marker = Marker();

        await using var client = await Server.ConnectSignedInAsync();

        await client.CommandAsync($"MAIL FROM:<alice@hermod.test> MT-PRIORITY={Priority}");
        await client.CommandAsync("RCPT TO:<bob@remote.example>");
        var (_, final) = await client.DataAsync($"From: <alice@hermod.test>\r\nSubject: {marker}\r\n\r\nhello\r\n");

        Assert.That(final?.Code, Is.EqualTo(250), Explain(client));

        var queued = Server.Queue.Queued.Single(mail => mail.MessageContent.Contains(marker));

        Assert.That((Int32) queued.Priority, Is.EqualTo(Priority));

    }

}
