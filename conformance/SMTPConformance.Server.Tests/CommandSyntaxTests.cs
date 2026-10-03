using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 5321 §4.1.1, §4.1.2, §4.5.3.1: the syntax of individual commands and their limits.
/// </summary>
[TestFixture]
public sealed class CommandSyntaxTests : HermodServerTestBase
{

    [Test(Description = "RFC 5321 §4.2.4: an unrecognised command is answered with 500")]
    public async Task Unknown_command_is_rejected_with_500()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var reply = await client.CommandAsync("FROBNICATE now");

        Assert.That(reply.Code, Is.EqualTo(500), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.1.9: NOOP is answered with 250, and a parameter is ignored")]
    public async Task Noop_with_a_parameter_is_still_250()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var plain = await client.CommandAsync("NOOP");
        var param = await client.CommandAsync("NOOP whatever this is");

        Assert.Multiple(() => {
            Assert.That(plain.Code, Is.EqualTo(250), Explain(client));
            Assert.That(param.Code, Is.EqualTo(250), Explain(client));
        });

    }


    [Test(Description = "RFC 5321 §3.5.3, §4.5.1: VRFY is implemented; 250, 251, 252 or 550/551/553 are the permitted answers, not 500/502")]
    public async Task Vrfy_is_implemented()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var reply = await client.CommandAsync("VRFY alice");

        Assert.That(reply.Code, Is.AnyOf(250, 251, 252, 550, 551, 553), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.5.3.1.4: a command line of 512 octets including CRLF must be accepted")]
    public async Task A_512_octet_command_line_is_accepted()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        // "NOOP " + padding + CRLF = 512 octets
        var line  = "NOOP " + new String('x', 512 - 5 - 2);
        var reply = await client.CommandAsync(line);

        Assert.That(reply.Code, Is.EqualTo(250), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.5.3.1.4, §4.2.2: a command line longer than the server accepts is answered with 500, and the session goes on")]
    public async Task An_overlong_command_line_is_rejected_and_the_session_survives()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var tooLong = await client.CommandAsync("NOOP " + new String('x', Server.Config.MaxCommandLineLength + 10));
        var after   = await client.CommandAsync("NOOP");

        Assert.Multiple(() => {
            Assert.That(tooLong.Code, Is.EqualTo(500), Explain(client));
            Assert.That(after.Code,   Is.EqualTo(250), "the line after the overlong one must be read as a command" + Explain(client));
        });

    }


    [Test(Description = "RFC 5321 §4.1.1.2, §4.5.5: the null reverse-path MAIL FROM:<> is accepted")]
    public async Task Null_reverse_path_is_accepted()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var reply = await client.CommandAsync("MAIL FROM:<>");

        Assert.That(reply.Code, Is.EqualTo(250), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.1.3, §4.1.2: Forward-path is not optional — RCPT TO:<> is a syntax error")]
    public async Task Empty_forward_path_is_rejected()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        await client.CommandAsync("MAIL FROM:<sender@client.example>");
        var reply = await client.CommandAsync("RCPT TO:<>");

        Assert.That(reply.Code, Is.AnyOf(501, 553), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.1.2: MAIL without angle brackets is a syntax error")]
    public async Task Mail_without_angle_brackets_is_rejected_with_501()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var reply = await client.CommandAsync("MAIL FROM:sender@client.example");

        Assert.That(reply.Code, Is.EqualTo(501), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.1.11: \"If the server SMTP does not recognize or cannot implement one or more of the parameters associated with a particular MAIL FROM or RCPT TO command, it will return code 555.\"")]
    [Property("Finding", "S-6")]
    public async Task Unknown_mail_parameter_is_rejected_with_555()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var reply = await client.CommandAsync("MAIL FROM:<sender@client.example> X-NO-SUCH-PARAM=1");

        Assert.That(reply.Code, Is.EqualTo(555), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.1.11: an unrecognised RCPT TO parameter is answered with 555")]
    [Property("Finding", "S-6")]
    public async Task Unknown_rcpt_parameter_is_rejected_with_555()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        await client.CommandAsync("MAIL FROM:<sender@client.example>");
        var reply = await client.CommandAsync("RCPT TO:<alice@hermod.test> X-NO-SUCH-PARAM=1");

        Assert.That(reply.Code, Is.EqualTo(555), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.1.4: DATA takes no argument — DATA with one is a syntax error (501)")]
    [Category(TestCategories.KnownIssue), Property("Finding", "S-8")]
    public async Task Data_with_an_argument_is_rejected_with_501()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");
        var reply = await client.CommandAsync("DATA please");

        Assert.That(reply.Code, Is.EqualTo(501), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.1.10, §3.8: QUIT is answered with 221, after which the server closes the connection")]
    public async Task Quit_is_221_and_the_server_closes()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var reply  = await client.CommandAsync("QUIT");
        var closed = await client.ClosesWithinAsync(TimeSpan.FromSeconds(3));

        Assert.Multiple(() => {
            Assert.That(reply.Code, Is.EqualTo(221), Explain(client));
            Assert.That(closed,     Is.True, "the server must close the channel after 221" + Explain(client));
        });

    }


    [Test(Description = "RFC 5321 §4.2: every reply the server sends is syntactically valid — checked across a whole session")]
    public async Task Every_reply_in_a_session_is_well_formed()
    {

        var (client, greeting) = await Server.ConnectMtaAsync();
        await using var _ = client;

        var replies = new List<SmtpReply> { greeting };

        replies.Add((await client.EhloAsync()).Reply);
        replies.Add(await client.CommandAsync("NOOP"));
        replies.Add(await client.CommandAsync("VRFY alice"));
        replies.Add(await client.CommandAsync("MAIL FROM:<sender@client.example>"));
        replies.Add(await client.CommandAsync("RCPT TO:<alice@hermod.test>"));
        replies.Add(await client.CommandAsync("RSET"));
        replies.Add(await client.CommandAsync("FROBNICATE"));
        replies.Add(await client.CommandAsync("QUIT"));

        foreach (var reply in replies)
            Assert.That(reply.Violations, Is.Empty, $"reply \"{reply}\"" + Explain(client));

    }

}
