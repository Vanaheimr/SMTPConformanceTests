using System.Text.RegularExpressions;

using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 5321 §3.1, §4.1.1.1, §4.2 and §4.3.1: the opening of a session.
/// </summary>
[TestFixture]
public sealed partial class GreetingAndEhloTests : HermodServerTestBase
{

    // RFC 5321 §4.1.1.1: ehlo-keyword = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")
    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9-]*$")]
    private static partial Regex EhloKeyword();


    [Test(Description = "RFC 5321 §3.1, §4.3.1: the greeting is a 220 reply, well formed")]
    public async Task Greeting_is_a_well_formed_220()
    {

        var (client, greeting) = await Server.ConnectMtaAsync();
        await using var _ = client;

        Assert.That(greeting.Code,       Is.EqualTo(220), Explain(client));
        Assert.That(greeting.Violations, Is.Empty,        Explain(client));

    }


    [Test(Description = "RFC 5321 §4.2: Greeting = \"220 \" (Domain / address-literal) [ SP textstring ] CRLF — the server identifies itself first")]
    public async Task Greeting_names_the_server_first()
    {

        var (client, greeting) = await Server.ConnectMtaAsync();
        await using var _ = client;

        Assert.That(greeting.Text.Split(' ')[0], Is.EqualTo(Server.Config.Hostname), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.1.1: EHLO is answered with 250, the first line naming the server")]
    public async Task Ehlo_reply_is_250_and_names_the_server()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        var (reply, _) = await client.EhloAsync();

        Assert.That(reply.Code,                  Is.EqualTo(250), Explain(client));
        Assert.That(reply.Violations,            Is.Empty,        Explain(client));
        Assert.That(reply.Lines[0].Split(' ')[0], Is.EqualTo(Server.Config.Hostname), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.1.1: every ehlo-line starts with a syntactically valid ehlo-keyword")]
    public async Task Every_ehlo_line_has_a_valid_keyword()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        var (reply, _) = await client.EhloAsync();

        foreach (var line in reply.Lines.Skip(1))
            Assert.That(line.Split(' ')[0], Does.Match(EhloKeyword()), $"ehlo-line \"{line}\"" + Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.1.1: HELO is answered with 250")]
    public async Task Helo_is_accepted()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        var reply = await client.CommandAsync("HELO client.example");

        Assert.That(reply.Code, Is.EqualTo(250), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.1.1, §4.1.4: an address literal is a valid EHLO argument")]
    public async Task Ehlo_with_an_address_literal_is_accepted()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        var (reply, _) = await client.EhloAsync("[127.0.0.1]");

        Assert.That(reply.Code, Is.EqualTo(250), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.1.1: ehlo = \"EHLO\" SP ( Domain / address-literal ) CRLF — EHLO without an argument is a syntax error (501)")]
    [Category(TestCategories.KnownIssue), Property("Finding", "S-8")]
    public async Task Ehlo_without_a_domain_is_rejected_with_501()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        var reply = await client.CommandAsync("EHLO");

        Assert.That(reply.Code, Is.EqualTo(501), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.1.1: helo = \"HELO\" SP Domain CRLF — HELO without an argument is a syntax error (501)")]
    [Category(TestCategories.KnownIssue), Property("Finding", "S-8")]
    public async Task Helo_without_a_domain_is_rejected_with_501()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        var reply = await client.CommandAsync("HELO");

        Assert.That(reply.Code, Is.EqualTo(501), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.4: a second EHLO is permitted, and is answered like the first")]
    public async Task A_second_ehlo_is_permitted()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        await client.EhloAsync();
        var (second, _) = await client.EhloAsync();

        Assert.That(second.Code, Is.EqualTo(250), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.4: an EHLO issued later in the session has the same effect as RSET — the open transaction is gone")]
    public async Task A_second_ehlo_aborts_the_open_transaction()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        await client.EhloAsync();
        var mail = await client.CommandAsync("MAIL FROM:<sender@client.example>");
        Assume.That(mail.Code, Is.EqualTo(250), Explain(client));

        await client.EhloAsync();

        var rcpt = await client.CommandAsync("RCPT TO:<alice@hermod.test>");

        Assert.That(rcpt.Code, Is.EqualTo(503), "RCPT after EHLO must find no open transaction" + Explain(client));

    }


    [Test(Description = "RFC 5321 §2.4: command verbs are case-insensitive")]
    public async Task Command_verbs_are_case_insensitive()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        var ehlo = await client.CommandAsync("eHlO client.example");
        var mail = await client.CommandAsync("mail from:<sender@client.example>");
        var rcpt = await client.CommandAsync("Rcpt To:<alice@hermod.test>");

        Assert.Multiple(() => {
            Assert.That(ehlo.Code, Is.EqualTo(250), Explain(client));
            Assert.That(mail.Code, Is.EqualTo(250), Explain(client));
            Assert.That(rcpt.Code, Is.EqualTo(250), Explain(client));
        });

    }

}
