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


    #region S-42: a parameter that may be given once, given twice

    public static IEnumerable<TestCaseData> ParametersGivenTwice()
    {

        TestCaseData Case(String Name, String Mail, String Rcpt)
            => new TestCaseData(Mail, Rcpt).SetName($"Given twice with the same value: {Name}")
                                           .SetCategory(TestCategories.KnownIssue)
                                           .SetProperty("Finding", "S-42");

        yield return Case("RET",     "MAIL FROM:<sender@client.example> RET=HDRS RET=HDRS",         "");
        yield return Case("ENVID",   "MAIL FROM:<sender@client.example> ENVID=QQ314159 ENVID=QQ314159", "");
        yield return Case("SIZE",    "MAIL FROM:<sender@client.example> SIZE=1000 SIZE=1000",       "");
        yield return Case("NOTIFY",  "MAIL FROM:<sender@client.example>",                           "RCPT TO:<alice@hermod.test> NOTIFY=FAILURE NOTIFY=FAILURE");
        yield return Case("ORCPT",   "MAIL FROM:<sender@client.example>",                           "RCPT TO:<alice@hermod.test> ORCPT=rfc822;alice@hermod.test ORCPT=rfc822;alice@hermod.test");

    }


    [TestCaseSource(nameof(ParametersGivenTwice))]
    [Description("RFC 3461 §4.5: \"The RET and ENVID parameters MUST NOT appear more than once each in any single MAIL command. If more than one of either of these parameters appears in a MAIL command, the ESMTP server SHOULD respond with \"501 syntax error in parameters or arguments\"\" - and the same for NOTIFY and ORCPT on RCPT; RFC 1870 §6: \"Only one SIZE parameter may be specified in a single MAIL command\"")]
    public async Task A_parameter_given_twice_is_501(String Mail, String Rcpt)
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var mail  = await client.CommandAsync(Mail);

        if (Rcpt.Length == 0)
        {
            Assert.That(mail.Code, Is.EqualTo(501), Explain(client));
            return;
        }

        Assume.That(mail.Code, Is.EqualTo(250), Explain(client));

        var rcpt  = await client.CommandAsync(Rcpt);

        Assert.That(rcpt.Code, Is.EqualTo(501), Explain(client));

    }


    [Test(Description = "RFC 3461 §4.3 to §4.4, RFC 1870 §6: the same parameters, each once, are taken - a guard for S-42")]
    public async Task Each_parameter_once_is_taken()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var mail = await client.CommandAsync("MAIL FROM:<sender@client.example> RET=HDRS ENVID=QQ314159 SIZE=1000");
        var rcpt = await client.CommandAsync("RCPT TO:<alice@hermod.test> NOTIFY=FAILURE ORCPT=rfc822;alice@hermod.test");

        Assert.Multiple(() => {
            Assert.That(mail.Code, Is.EqualTo(250), Explain(client));
            Assert.That(rcpt.Code, Is.EqualTo(250), Explain(client));
        });

    }

    #endregion

}
