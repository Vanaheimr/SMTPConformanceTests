using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 5321 §3.5, §4.1.1.6 to §4.1.1.8, §4.2.4 and §7.3: HELP, EXPN and VRFY - commands of the
/// protocol, which a server may decline to carry out, but recognizes.
/// </summary>
[TestFixture]
public sealed class HelpExpnVrfyTests : HermodServerTestBase
{

    [Test(Description = "RFC 5321 §4.1.1.8: \"SMTP servers SHOULD support HELP without arguments\"; §4.2.2: 214 \"Help message\" (or 211 \"System status, or system help reply\")")]
    [Property("Finding", "S-33")]
    public async Task HELP_without_an_argument_is_answered_with_help()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var reply = await client.CommandAsync("HELP");

        Assert.That(reply.Code, Is.AnyOf(211, 214), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.1.7: EXPN is a command of SMTP; §7.3: \"If a site disables these commands for security reasons, the SMTP server MUST return a 252 response\"; §4.2.4: \"502 SHOULD be used when the command is actually recognized by the SMTP server, but not implemented. If the command is not recognized, code 500 SHOULD be returned\" - not 500, and not 250 (§3.5.3)")]
    [Property("Finding", "S-33")]
    public async Task EXPN_is_answered_as_a_command_that_is_known()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var reply = await client.CommandAsync("EXPN staff");

        Assert.That(reply.Code, Is.AnyOf(252, 502), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.1.6: vrfy = \"VRFY\" SP String CRLF - a VRFY without its string is a syntax error, 501 (§4.2.2: \"Syntax error in parameters or arguments\"), not a 252 for nobody")]
    [Property("Finding", "S-33")]
    public async Task VRFY_without_an_argument_is_a_syntax_error()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var reply = await client.CommandAsync("VRFY");

        Assert.That(reply.Code, Is.EqualTo(501), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.1.8: HELP \"may be issued at any time\" and \"has no effect on the reverse-path buffer, the forward-path buffer, or the mail data buffer\" - a transaction goes on after it")]
    public async Task HELP_in_a_transaction_leaves_it_open()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        await client.CommandAsync("MAIL FROM:<sender@client.example>");
        await client.CommandAsync("RCPT TO:<alice@hermod.test>");
        await client.CommandAsync("HELP");

        var data = await client.CommandAsync("DATA");

        Assert.That(data.Code, Is.EqualTo(354), Explain(client));

    }

}
