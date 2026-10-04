using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Tls.Tests;

/// <summary>
/// RFC 3207 §4: a server that requires TLS "SHOULD return the reply code
/// 530 Must issue a STARTTLS command first to every command other than NOOP,
/// EHLO, STARTTLS, or QUIT."
/// </summary>
[TestFixture]
public sealed class RequireStartTlsTests : HermodServerTestBase
{

    protected override HermodSmtpServerFixtureOptions Options
        => new() { EnableTls = true, RequireStartTls = true };


    public static IEnumerable<TestCaseData> GatedCommands()
    {
        yield return new TestCaseData("MAIL FROM:<sender@client.example>") .SetName("Before STARTTLS, MAIL is 530");
        yield return new TestCaseData("AUTH SCRAM-SHA-256")                .SetName("Before STARTTLS, AUTH is 530").SetProperty("Finding", "S-13");
        yield return new TestCaseData("VRFY alice")                        .SetName("Before STARTTLS, VRFY is 530").SetProperty("Finding", "S-13");
        yield return new TestCaseData("RSET")                              .SetName("Before STARTTLS, RSET is 530").SetProperty("Finding", "S-13");
    }


    [TestCaseSource(nameof(GatedCommands))]
    public async Task Commands_before_starttls_get_530(String Command)
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        await client.EhloAsync();
        var reply = await client.CommandAsync(Command);

        Assert.That(reply.Code, Is.EqualTo(530), Explain(client));

    }


    public static IEnumerable<TestCaseData> ExemptCommands()
    {
        yield return new TestCaseData("NOOP").SetName("Before STARTTLS, NOOP is still answered");
        yield return new TestCaseData("QUIT").SetName("Before STARTTLS, QUIT is still answered");
    }


    [TestCaseSource(nameof(ExemptCommands))]
    public async Task Exempt_commands_are_answered(String Command)
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        await client.EhloAsync();
        var reply = await client.CommandAsync(Command);

        Assert.That(reply.Class, Is.EqualTo(2), Explain(client));

    }


    [Test(Description = "RFC 3207 §4: after STARTTLS the same transaction goes through")]
    public async Task After_starttls_mail_is_accepted()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        await client.EhloAsync();
        await client.StartTlsAsync();
        await client.EhloAsync();
        var final = await client.SendMailAsync("sender@client.example", "alice@hermod.test");

        Assert.That(final.Code, Is.EqualTo(250), Explain(client));

    }

}
