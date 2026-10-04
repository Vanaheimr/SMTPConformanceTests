using System.Text;

using NUnit.Framework;


using org.GraphDefined.Vanaheimr.Hermod.SMTP;
using org.GraphDefined.Vanaheimr.Hermod.TLS;

using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// How the client ends a session, reads replies and uses the round trips it has: QUIT after
/// every attempt (RFC 5321 §4.1.1.10), replies decoded as a whole, PIPELINING (RFC 2920) and
/// CHUNKING (RFC 3030) when the server offers them.
/// </summary>
public sealed partial class SubmissionClientTests
{

    #region Every attempt ends with QUIT (C-8)

    public static IEnumerable<TestCaseData> FailedAttempts()
    {

        TestCaseData Case(String Name, Func<SmtpServerScript> Script, TLSUsage UseTLS = TLSUsage.NoTLS, String Body = "hello")
            => new TestCaseData(Script, UseTLS, Body).SetName($"QUIT after: {Name}").SetProperty("Finding", "C-8");

        yield return Case("a refused RCPT",                () => new SmtpServerScript { RcptReply = _ => "550 5.1.1 No such user" });
        yield return Case("a refused MAIL",                () => new SmtpServerScript { MailReply = "550 5.7.1 Sender rejected" });
        yield return Case("a refused DATA",                () => new SmtpServerScript { DataReply = "554 5.5.1 No valid recipients" });
        yield return Case("a refused message",             () => new SmtpServerScript { EndOfDataReply = "554 5.7.1 Message rejected" });
        yield return Case("STARTTLS refused with 454",     () => new SmtpServerScript { Certificate = TestCertificate.CreateServerCertificate(), StartTlsReply = "454 4.7.0 TLS not available" }, TLSUsage.STARTTLS);
        yield return Case("a message above the SIZE limit", () => new SmtpServerScript { Extensions = [ "SIZE 100", "8BITMIME" ] }, Body: new String('x', 500));
        yield return Case("8-bit content without 8BITMIME", () => new SmtpServerScript { Extensions = [ "SIZE 10485760" ] }, Body: "Grüße");

    }


    [TestCaseSource(nameof(FailedAttempts))]
    [Description("RFC 5321 §4.1.1.10: \"The sender MUST NOT intentionally close the transmission channel until it sends a QUIT command\" — also when the attempt failed")]
    public async Task A_failed_attempt_ends_with_QUIT(Func<SmtpServerScript> Script, TLSUsage UseTLS, String Body)
    {

        var script = Script();
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server, UseTLS);

        var result = await client.Send(Message(Body), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        Assert.Multiple(() => {
            Assert.That(result,                                            Is.Not.EqualTo(MailSentStatus.ok), Explain(server));
            Assert.That(script.Commands.Select(c => c.Line).LastOrDefault(), Is.EqualTo("QUIT"),             Explain(server));
        });

    }

    #endregion

    #region Replies are decoded as a whole (C-9)

    /// <summary>
    /// A minimal server whose end-of-data reply arrives in two TCP segments, split inside the
    /// two octets of the "ü" in "Grüße".
    /// </summary>
    private static async Task SplitReplyScript(ScriptedSmtpSession s)
    {

        await s.ReplyAsync("220 split.test ESMTP");

        while (await s.ReadCommandAsync() is { Terminator: not LineTerminator.EndOfStream } line)
        {

            var verb = line.Utf8.Split(' ')[0].ToUpperInvariant();

            if (verb == "EHLO")
                await s.ReplyAsync("250-split.test", "250-8BITMIME", "250 ENHANCEDSTATUSCODES");

            else if (verb == "DATA")
            {

                await s.ReplyAsync("354 go ahead");

                while (await s.ReadLineAsync(TimeSpan.FromSeconds(10)) is { } dataLine && dataLine.Bytes is not [ (Byte) '.' ])
                { }

                var reply = Encoding.UTF8.GetBytes("250 2.0.0 Grüße aus Köln\r\n");
                var cut   = Array.IndexOf(reply, (Byte) 0xC3) + 1;      // after the first octet of "ü"

                await s.WriteRawAsync(reply[..cut]);
                await Task.Delay(200);
                await s.WriteRawAsync(reply[cut..]);

            }

            else if (verb == "QUIT")
            {
                await s.ReplyAsync("221 2.0.0 Bye");
                return;
            }

            else
                await s.ReplyAsync("250 2.0.0 Ok");

        }

    }


    [Test(Description = "RFC 9293 §3.8.6: TCP is a stream, its segment boundaries mean nothing — a reply split inside a UTF-8 character is still read as the server wrote it")]
    [Property("Finding", "C-9")]
    public async Task A_reply_split_inside_a_UTF8_character_is_read_whole()
    {

        await using var server = ScriptedSmtpServer.Start(SplitReplyScript);
        using var client = ClientFor(server);

        var result = await client.SendWithResult(Message("hello"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        Assert.Multiple(() => {
            Assert.That(result.Status,   Is.EqualTo(MailSentStatus.ok),     Explain(server));
            Assert.That(result.Response, Does.Contain("Grüße aus Köln"),    Explain(server));
        });

    }

    #endregion

    #region PIPELINING and CHUNKING (C-10)

    /// <summary>
    /// A server that offers PIPELINING and, before it answers MAIL, waits to see whether the
    /// client sends its RCPT without waiting for that answer.
    /// </summary>
    private sealed class PipeliningProbe
    {

        public volatile Boolean RcptBeforeMailReply;

        public async Task RunAsync(ScriptedSmtpSession s)
        {

            await s.ReplyAsync("220 pipe.test ESMTP");

            while (await s.ReadCommandAsync() is { Terminator: not LineTerminator.EndOfStream } line)
            {

                var verb = line.Utf8.Split(' ')[0].ToUpperInvariant();

                switch (verb)
                {

                    case "EHLO":
                        await s.ReplyAsync("250-pipe.test", "250-PIPELINING", "250-8BITMIME", "250 SIZE 10485760");
                        break;

                    case "MAIL":
                        try
                        {
                            var next = await s.ReadCommandAsync(TimeSpan.FromMilliseconds(750));
                            RcptBeforeMailReply = next is not null && next.Utf8.StartsWith("RCPT", StringComparison.OrdinalIgnoreCase);
                            await s.ReplyAsync("250 2.1.0 Ok");
                            if (RcptBeforeMailReply)
                                await s.ReplyAsync("250 2.1.5 Ok");
                        }
                        catch (TimeoutException)
                        {
                            await s.ReplyAsync("250 2.1.0 Ok");
                        }
                        break;

                    case "DATA":
                        await s.ReplyAsync("354 go ahead");
                        while (await s.ReadLineAsync(TimeSpan.FromSeconds(10)) is { } dataLine && dataLine.Bytes is not [ (Byte) '.' ])
                        { }
                        await s.ReplyAsync("250 2.0.0 Ok: queued");
                        break;

                    case "QUIT":
                        await s.ReplyAsync("221 2.0.0 Bye");
                        return;

                    default:
                        await s.ReplyAsync("250 2.0.0 Ok");
                        break;

                }

            }

        }

    }


    [Test(Description = "RFC 2920 §3.1: with PIPELINING the client may send MAIL and its RCPTs without waiting for each reply — one round trip instead of one per command")]
    [Property("Finding", "C-10")]
    public async Task With_PIPELINING_MAIL_and_RCPT_go_out_together()
    {

        var probe = new PipeliningProbe();
        await using var server = ScriptedSmtpServer.Start(probe.RunAsync);
        using var client = ClientFor(server);

        var result = await client.Send(Message("hello"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        Assert.Multiple(() => {
            Assert.That(result,                     Is.EqualTo(MailSentStatus.ok), Explain(server));
            Assert.That(probe.RcptBeforeMailReply,  Is.True, "the RCPT should follow MAIL without waiting for its reply" + Explain(server));
        });

    }


    [Test(Description = "RFC 3030 §2: with CHUNKING the client may send the message as BDAT ... LAST — no 354 round trip, no dot-stuffing")]
    [Property("Finding", "C-10")]
    public async Task With_CHUNKING_the_message_goes_as_BDAT()
    {

        var script = new SmtpServerScript { Extensions = [ "PIPELINING", "SIZE 10485760", "8BITMIME", "ENHANCEDSTATUSCODES", "CHUNKING" ] };
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        var result = await client.Send(Message("line one", ".stuffed", "line three"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        var transaction = script.Transactions.Single();
        var content     = Encoding.UTF8.GetString(transaction.BdatContent.ToArray());

        Assert.Multiple(() => {
            Assert.That(result,                Is.EqualTo(MailSentStatus.ok), Explain(server));
            Assert.That(transaction.UsedBdat,  Is.True,                       Explain(server));
            Assert.That(content,               Does.Contain("\r\n.stuffed\r\n").And.EndWith("line three\r\n"),
                        "BDAT content is the message as it is: no dot-stuffing, every line with its CR LF" + Explain(server));
        });

    }

    #endregion

}
