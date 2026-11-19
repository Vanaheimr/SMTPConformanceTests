using System.Net.Sockets;
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SMTP.Server;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 5321 §4.5.3.1.8 and §4.5.3.1.10: how many recipients a message may have, and how
/// a server says there are too many.
/// </summary>
[TestFixture]
public sealed class RecipientLimitTests : HermodServerTestBase
{

    private static async Task<IReadOnlyList<Int32>> Recipients(RawSmtpClient Client, Int32 Count, String Prefix)
    {
        var codes = new List<Int32>();
        for (var i = 1; i <= Count; i++)
            codes.Add((await Client.CommandAsync($"RCPT TO:<alice+{Prefix}{i}@hermod.test>")).Code);
        return codes;
    }


    [Test(Description = "RFC 5321 §4.5.3.1.8: \"The minimum total number of recipients that MUST be buffered is 100\"; §4.5.3.1.10 - one more is refused with 452")]
    public async Task A_message_takes_100_recipients_and_refuses_the_101st_with_452()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        Assert.That((await client.CommandAsync("MAIL FROM:<sender@client.example>")).Code, Is.EqualTo(250));

        var hundred = await Recipients(client, 100, "a");
        var extra   = await client.CommandAsync("RCPT TO:<alice+a101@hermod.test>");

        Assert.Multiple(() => {
            Assert.That(hundred,                Has.All.EqualTo(250), Explain(client));
            Assert.That(extra.Code,             Is.EqualTo(452),      Explain(client));
            Assert.That(extra.EnhancedCode,     Is.EqualTo("4.5.3"),  Explain(client));
        });

    }


    [Test(Description = "RFC 5321 §4.5.3.1.8: 100 recipients MUST be buffered - for each message: a second transaction in the same session is not short of recipients because the first had some")]
    [Property("Finding", "L-1")]
    public async Task A_second_message_in_the_session_takes_its_own_recipients()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        Assert.That((await client.CommandAsync("MAIL FROM:<sender@client.example>")).Code, Is.EqualTo(250));
        var first  = await Recipients(client, 60, "b");
        Assert.That((await client.CommandAsync("RSET")).Code, Is.EqualTo(250));

        Assert.That((await client.CommandAsync("MAIL FROM:<sender@client.example>")).Code, Is.EqualTo(250));
        var second = await Recipients(client, 60, "c");

        Assert.Multiple(() => {
            Assert.That(first,   Has.All.EqualTo(250), Explain(client));
            Assert.That(second,  Has.All.EqualTo(250), "60 recipients of a second message " + Explain(client));
        });

    }

}


/// <summary>
/// Connections refused at accept: RFC 5321 §3.1 (554 instead of a greeting) and §3.8 / §4.2
/// (421, CRLF). The loopback is taken off the server's whitelist, so the limits apply to it.
/// </summary>
[TestFixture]
public sealed class ConnectionLimitTests : HermodServerTestBase
{

    protected override HermodSmtpServerFixtureOptions Options
        => new() {
               RateLimits = new RateLimitConfig {
                                AuthFailDelayMs               = 0,
                                MaxConnectionsPerIp           = 1,
                                MaxConnectionsPerIpPerMinute  = 10000,
                                MaxAuthAttemptsPerIpPerHour   = 10000,
                                MaxMessagesPerIpPerHour       = 10000,
                                WhitelistedIps                = []
                            }
           };

    /// <summary>
    /// Every octet a fresh connection receives until the server closes it, or 5 s pass.
    /// </summary>
    private async Task<String> Refusal()
    {

        using var tcp    = new TcpClient();
        await tcp.ConnectAsync(Server.Host, Server.MtaPort);

        var stream       = tcp.GetStream();
        var received     = new MemoryStream();
        var buffer       = new Byte[1024];
        using var cts    = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        try
        {
            Int32 read;
            while ((read = await stream.ReadAsync(buffer, cts.Token)) > 0)
                received.Write(buffer, 0, read);
        }
        catch (Exception e) when (e is OperationCanceledException or IOException)
        {
        }

        return Encoding.ASCII.GetString(received.ToArray());

    }


    [Test(Description = "RFC 5321 §3.8 / §4.2.4: a second connection over the server's limit per address gets 421 and is closed")]
    public async Task A_connection_over_the_limit_gets_421_and_is_closed()
    {

        var (first, greeting) = await Server.ConnectMtaAsync();
        await using var _first = first;
        Assert.That(greeting.Code, Is.EqualTo(220));

        var refusal = await Refusal();

        Assert.That(refusal, Does.StartWith("421 4.7.0 "));

    }


    [Test(Description = "RFC 5321 §2.3.8: \"Lines consist of zero or more data characters terminated by the sequence ASCII character \"CR\" (hex 0D) followed immediately by ASCII character \"LF\" (hex 0A)\" - the 421 of a refused connection too, on every platform")]
    [Property("Finding", "L-2")]
    public async Task The_421_of_a_refused_connection_ends_in_CRLF()
    {

        var (first, greeting) = await Server.ConnectMtaAsync();
        await using var _first = first;
        Assert.That(greeting.Code, Is.EqualTo(220));

        var refusal = await Refusal();

        Assert.Multiple(() => {
            Assert.That(refusal,                                  Does.EndWith("\r\n"), refusal.Replace("\r", "<CR>").Replace("\n", "<LF>"));
            Assert.That(refusal.Replace("\r\n", "").Contains('\n'), Is.False,            "a bare LF");
        });

    }

}


/// <summary>
/// RFC 5321 §3.1: a server that refuses a client with 554 instead of a greeting "MUST still
/// wait for the client to send a QUIT".
/// </summary>
[TestFixture]
public sealed class RefusedClientTests : HermodServerTestBase
{

    protected override HermodSmtpServerFixtureOptions Options
        => new() {
               RateLimits = new RateLimitConfig {
                                AuthFailDelayMs               = 0,
                                MaxConnectionsPerIpPerMinute  = 10000,
                                MaxAuthAttemptsPerIpPerHour   = 10000,
                                MaxMessagesPerIpPerHour       = 10000,
                                WhitelistedIps                = [],
                                BlacklistedIps                = [ "127.0.0.1" ]
                            }
           };


    [Test(Description = "RFC 5321 §3.1: after a 554 greeting the server \"MUST still wait for the client to send a QUIT ... before closing the connection and SHOULD respond to any intervening commands with \"503 bad sequence of commands\"\"")]
    [Property("Finding", "L-3")]
    public async Task After_554_the_server_waits_for_QUIT()
    {

        await using var client = await RawSmtpClient.ConnectAsync(Server.Host, Server.MtaPort);

        var greeting = await client.TryReadReplyAsync();
        var ehlo     = greeting?.Code == 554 ? await client.TryCommandAsync("EHLO client.example") : null;
        var quit     = ehlo is not null      ? await client.TryCommandAsync("QUIT")                : null;

        Assert.Multiple(() => {
            Assert.That(greeting?.Code, Is.EqualTo(554), client.Transcript.ToString());
            Assert.That(ehlo?.Code,     Is.EqualTo(503), "the connection is still there, and EHLO out of sequence " + client.Transcript);
            Assert.That(quit?.Code,     Is.EqualTo(221), client.Transcript.ToString());
        });

    }

}


/// <summary>
/// RFC 5321 §3.8: "the server ... MAY ... send a 421 ... and close the connection" - a 421 is
/// the server closing, also when it answers AUTH with it.
/// </summary>
[TestFixture]
public sealed class AuthenticationLimitTests : HermodServerTestBase
{

    protected override HermodSmtpServerFixtureOptions Options
        => new() {
               EnableTls  = true,
               RateLimits = new RateLimitConfig {
                                AuthFailDelayMs               = 0,
                                MaxConnectionsPerIpPerMinute  = 10000,
                                MaxAuthAttemptsPerIpPerHour   = 1,
                                MaxMessagesPerIpPerHour       = 10000,
                                WhitelistedIps                = []
                            }
           };


    [Test(Description = "RFC 5321 §3.8: a 421 means the server is closing the transmission channel - after a 421 to AUTH no further command is answered")]
    [Property("Finding", "L-4")]
    public async Task After_421_to_AUTH_the_connection_is_closed()
    {

        var (client, _) = await Server.ConnectSubmissionAsync();
        await using var _client = client;

        await client.EhloAsync();
        await client.StartTlsAsync();
        await client.EhloAsync();

        var wrong    = "AUTH PLAIN " + Convert.ToBase64String(Encoding.UTF8.GetBytes("\0alice\0wrong"));
        SmtpReply? limited = null;

        for (var i = 0; i < 5 && limited is null; i++)
        {
            var reply = await client.CommandAsync(wrong);
            if (reply.Code == 421)
                limited = reply;
        }

        Assert.That(limited, Is.Not.Null, "no 421 within five attempts " + client.Transcript);

        var after = await client.TryCommandAsync("NOOP");

        Assert.That(after, Is.Null, "answered after 421: " + client.Transcript);

    }

}
