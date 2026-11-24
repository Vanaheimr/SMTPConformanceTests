using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 5321 §3.8: a server ends a session only after the client's QUIT, after a timeout, or
/// "after detecting the need to shut down the SMTP service and returning a 421 response code".
/// A server that is stopped while clients are connected says 421 to each of them before it
/// closes - so that a client knows the server went away, and tries again later, rather than
/// guessing at a broken network. Every test here stops a server of its own.
/// </summary>
[TestFixture]
public sealed class ServerShutdownTests
{

    #region S-41: a server that shuts down says 421 first

    public static IEnumerable<TestCaseData> Moments()
    {

        TestCaseData Case(String Name, Func<RawSmtpClient, Task> Before)
            => new TestCaseData(Before).SetName($"Stopped with a client connected: {Name}")
                                       .SetCategory(TestCategories.KnownIssue)
                                       .SetProperty("Finding", "S-41");

        yield return Case("after the greeting",          _      => Task.CompletedTask);

        yield return Case("after EHLO",                  async client => await client.EhloAsync());

        yield return Case("in a mail transaction",       async client => {
                                                             await client.EhloAsync();
                                                             var (mail, rcpts) = await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");
                                                             Assume.That(rcpts.Single().Code, Is.EqualTo(250), "the recipient is accepted");
                                                         });

        yield return Case("in the middle of DATA",       async client => {
                                                             await client.EhloAsync();
                                                             await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");
                                                             var data = await client.CommandAsync("DATA");
                                                             Assume.That(data.Code, Is.EqualTo(354), "the server waits for the message");
                                                             await client.WriteLineAsync("Subject: half a message");
                                                         });

    }


    [TestCaseSource(nameof(Moments))]
    [Description("RFC 5321 §3.8: \"An SMTP server MUST NOT intentionally close the connection under normal operational circumstances (see Section 7.8) except: ... After detecting the need to shut down the SMTP service and returning a 421 response code. This response code can be issued after the server receives any command or, if necessary, asynchronously from command receipt\"")]
    public async Task A_server_that_shuts_down_says_421_before_it_closes(Func<RawSmtpClient, Task> Before)
    {

        var server = await HermodSmtpServerFixture.StartAsync();
        await using var _ = server;

        var (client, greeting) = await server.ConnectMtaAsync();
        await using var __ = client;

        Assume.That(greeting.Code, Is.EqualTo(220), "the session is open");

        await Before(client);

        var stopping = server.Server.Stop();

        var reply    = await client.TryReadReplyAsync(TimeSpan.FromSeconds(10));
        var closed   = await client.ClosesWithinAsync(TimeSpan.FromSeconds(10));

        await stopping.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Multiple(() => {
            Assert.That(reply?.Code, Is.EqualTo(421), $"a 421 before the close\n--- wire ---\n{client.Transcript}\n--- server log ---\n{server.Log}");
            Assert.That(closed,      Is.True,         "and the connection is closed");
            Assert.That(server.Storage.Messages,     Is.Empty, "nothing half received is delivered");
        });

    }

    #endregion

}
