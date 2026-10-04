using NUnit.Framework;

using SMTPConformance.Core.Fixtures;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 5321 §4.5.3.2: the server waits a while for the next command, then gives up. §3.8 lets
/// it close the connection after such a timeout; saying why first - 421, as §3.8 has it for a
/// server that must end the session - tells the client the difference between "the server gave
/// up on me" and "the network broke", which decides whether it retries at once.
/// </summary>
[TestFixture]
public sealed class SessionTimeoutTests : HermodServerTestBase
{

    protected override HermodSmtpServerFixtureOptions Options
        => new() { SessionTimeout = TimeSpan.FromSeconds(2) };


    [Test(Description = "RFC 5321 §3.8, §4.5.3.2: an idle session is closed after the timeout, with a 421 first")]
    [Property("Finding", "S-19")]
    public async Task An_idle_session_is_closed_with_421()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        await client.EhloAsync();

        var reply  = await client.TryReadReplyAsync(TimeSpan.FromSeconds(10));
        var closed = await client.ClosesWithinAsync(TimeSpan.FromSeconds(3));

        Assert.Multiple(() => {
            Assert.That(reply?.Code, Is.EqualTo(421), "a 421 before the close" + Explain(client));
            Assert.That(closed,      Is.True,         "the server closes the connection" + Explain(client));
        });

    }


    [Test(Description = "RFC 5321 §4.5.3.2: the timeout is for an idle client — one that keeps talking is not cut off")]
    public async Task A_client_that_keeps_talking_is_not_timed_out()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        await client.EhloAsync();

        for (var i = 0; i < 4; i++)
        {
            await Task.Delay(TimeSpan.FromSeconds(1));
            Assert.That((await client.CommandAsync("NOOP")).Code, Is.EqualTo(250), Explain(client));
        }

    }

}
