using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 2034 §4 and RFC 3463 §2: once ENHANCEDSTATUSCODES is advertised, "the text
/// part of all 2xx, 4xx, and 5xx SMTP responses other than the initial greeting and
/// any response to HELO or EHLO are prefaced with a status code".
/// </summary>
/// <remarks>
/// One test case per command, so a finding names the reply that lacks its code
/// instead of drowning in a single red test.
/// </remarks>
[TestFixture]
public sealed class EnhancedStatusCodeTests : HermodServerTestBase
{

    [Test(Description = "RFC 2034 §3: ENHANCEDSTATUSCODES is advertised")]
    public async Task Enhancedstatuscodes_is_advertised()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        var (_, extensions) = await client.EhloAsync();

        Assert.That(extensions.Keys, Does.Contain("ENHANCEDSTATUSCODES"), Explain(client));

    }


    /// <summary>
    /// Each case: the commands that set the scene, then the one whose reply is checked.
    /// </summary>
    public static IEnumerable<TestCaseData> Replies()
    {
        TestCaseData Case(String name, String[] setup, String command)
            => new TestCaseData(setup, command).SetName($"Enhanced code on: {name}");

        yield return Case("NOOP",                          [],                                                                    "NOOP").SetProperty("Finding", "S-4");
        yield return Case("RSET",                          [],                                                                    "RSET").SetProperty("Finding", "S-4");
        yield return Case("VRFY",                          [],                                                                    "VRFY alice").SetProperty("Finding", "S-4");
        yield return Case("MAIL accepted",                 [],                                                                    "MAIL FROM:<sender@client.example>");
        yield return Case("RCPT accepted",                 [ "MAIL FROM:<sender@client.example>" ],                               "RCPT TO:<alice@hermod.test>");
        yield return Case("RCPT relay denied",             [ "MAIL FROM:<sender@client.example>" ],                               "RCPT TO:<x@elsewhere.example>");
        yield return Case("RCPT without MAIL (503)",       [],                                                                    "RCPT TO:<alice@hermod.test>");
        yield return Case("DATA without RCPT (503)",       [ "MAIL FROM:<sender@client.example>" ],                               "DATA");
        yield return Case("MAIL syntax error (501)",       [],                                                                    "MAIL FROM:nobrackets@client.example");
        yield return Case("unknown command (500)",         [],                                                                    "FROBNICATE").SetProperty("Finding", "S-4");
        yield return Case("unknown AUTH mechanism (504)",  [],                                                                    "AUTH NO-SUCH-MECHANISM").SetProperty("Finding", "S-5");
        yield return Case("AUTH without a mechanism (501)", [],                                                                   "AUTH");
        yield return Case("cancelled AUTH (501)",          [ "AUTH SCRAM-SHA-256" ],                                              "*");
        yield return Case("QUIT",                          [],                                                                    "QUIT").SetProperty("Finding", "S-4");
    }


    [TestCaseSource(nameof(Replies))]
    public async Task Every_reply_carries_a_matching_enhanced_code(String[] Setup, String Command)
    {

        await using var client = await Server.ConnectAndEhloAsync();

        foreach (var line in Setup)
            await client.CommandAsync(line);

        var reply = await client.CommandAsync(Command);

        Assume.That(reply.Class, Is.AnyOf(2, 4, 5), Explain(client));

        Assert.That(reply.EveryLineHasEnhancedCode, Is.True,
                    $"\"{reply}\" must begin its text with an x.y.z code of class {reply.Class}" + Explain(client));

    }


    [Test(Description = "RFC 2034 §4: the end-of-data reply carries an enhanced code")]
    public async Task End_of_data_reply_carries_an_enhanced_code()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var final = await client.SendMailAsync("sender@client.example", "alice@hermod.test");

        Assert.That(final.EveryLineHasEnhancedCode, Is.True, $"\"{final}\"" + Explain(client));

    }

}
