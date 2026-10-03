using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 3461: SMTP Service Extension for Delivery Status Notifications — the parameters.
/// </summary>
[TestFixture]
public sealed class DsnParameterTests : HermodServerTestBase
{

    [Test(Description = "RFC 3461 §4: DSN is advertised")]
    public async Task Dsn_is_advertised()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        var (_, extensions) = await client.EhloAsync();

        Assert.That(extensions.Keys, Does.Contain("DSN"), Explain(client));

    }


    [Test(Description = "RFC 3461 §4.3, §4.4: RET=HDRS and ENVID=xtext on MAIL are accepted")]
    public async Task Ret_and_envid_are_accepted()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var reply = await client.CommandAsync("MAIL FROM:<sender@client.example> RET=HDRS ENVID=QQ314159+2B42");

        Assert.That(reply.Code, Is.EqualTo(250), Explain(client));

    }


    [Test(Description = "RFC 3461 §4.1, §4.2: NOTIFY=SUCCESS,FAILURE and ORCPT=rfc822;… on RCPT are accepted")]
    public async Task Notify_and_orcpt_are_accepted()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        await client.CommandAsync("MAIL FROM:<sender@client.example>");
        var reply = await client.CommandAsync("RCPT TO:<alice@hermod.test> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;alice@hermod.test");

        Assert.That(reply.Code, Is.EqualTo(250), Explain(client));

    }


    [Test(Description = "RFC 3461 §4.1: \"the NEVER keyword MUST appear by itself\" — NOTIFY=NEVER,SUCCESS is a parameter error")]
    [Property("Finding", "S-6")]
    public async Task Notify_never_combined_with_another_value_is_rejected()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        await client.CommandAsync("MAIL FROM:<sender@client.example>");
        var reply = await client.CommandAsync("RCPT TO:<alice@hermod.test> NOTIFY=NEVER,SUCCESS");

        Assert.That(reply.Code, Is.AnyOf(501, 555), Explain(client));

    }


    [Test(Description = "RFC 3461 §4.3: ret-value = \"FULL\" / \"HDRS\" — any other RET= value is a parameter error")]
    [Property("Finding", "S-6")]
    public async Task An_unknown_ret_value_is_rejected()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var reply = await client.CommandAsync("MAIL FROM:<sender@client.example> RET=BODY");

        Assert.That(reply.Code, Is.AnyOf(501, 555), Explain(client));

    }

}
