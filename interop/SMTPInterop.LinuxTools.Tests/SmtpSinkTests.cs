using System.Diagnostics;
using System.Net.Sockets;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;
using org.GraphDefined.Vanaheimr.Hermod.TLS;

using SMTPConformance.Core;

namespace SMTPInterop.LinuxTools.Tests;

/// <summary>
/// The other direction: Hermod's <see cref="SMTPSubmissionClient"/> sending to
/// Postfix's <c>smtp-sink</c>, a server whose every quirk is a command-line switch.
/// </summary>
[TestFixture]
[Category(TestCategories.Wsl)]
public sealed class SmtpSinkTests
{

    private sealed class Sink : IDisposable
    {

        public required Process  Process   { get; init; }
        public required String   Host      { get; init; }
        public required UInt16   Port      { get; init; }
        public required String   DumpDir   { get; init; }

        /// <summary>
        /// Everything smtp-sink dumped so far, all transactions concatenated.
        /// </summary>
        public String Dumps()
            => Wsl.Run($"cat {DumpDir}/* 2>/dev/null", TimeSpan.FromSeconds(15)).StdOut;

        public void Dispose()
        {
            try { Process.Kill(entireProcessTree: true); } catch { }
            Wsl.Run($"pkill -f 'smtp-sink.*:{Port} ' ; rm -rf {DumpDir}", TimeSpan.FromSeconds(15));
        }

    }


    private static async Task<Sink> StartSink(String Options = "")
    {

        TestEnvironment.RequireWsl("smtp-sink");

        var host = Wsl.VmAddress ?? throw new InconclusiveException("Could not determine the WSL address as seen from the host.");

        for (var attempt = 0; attempt < 5; attempt++)
        {

            var port    = (UInt16) Random.Shared.Next(20000, 60000);
            var dumpDir = $"/tmp/smtp-sink-{Guid.NewGuid():N}";
            // smtp-sink refuses to run as root without -u — which is how a CI container
            // runs everything. "nobody" can write the dump directory because it is 777.
            var process = Wsl.StartDetached($"mkdir -p {dumpDir} && chmod 777 {dumpDir} && " +
                                            $"if [ \"$(id -u)\" = 0 ]; then U='-u nobody'; else U=''; fi && " +
                                            $"exec /usr/sbin/smtp-sink $U {Options} -d {dumpDir}/ 0.0.0.0:{port} 16",
                                            asRoot: false);

            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);

            while (DateTime.UtcNow < deadline && !process.HasExited)
            {
                try
                {
                    using var tcp = new TcpClient();
                    await tcp.ConnectAsync(host, port).WaitAsync(TimeSpan.FromSeconds(1));
                    return new Sink { Process = process, Host = host, Port = port, DumpDir = dumpDir };
                }
                catch
                {
                    await Task.Delay(100);
                }
            }

            try { process.Kill(entireProcessTree: true); } catch { }

        }

        Assert.Ignore($"smtp-sink did not become reachable on {host} — skipping.");
        throw new InvalidOperationException();

    }


    private static SMTPSubmissionClient ClientFor(Sink Sink)
        => new (DomainName.Parse(Sink.Host),
                IPPort.Parse(Sink.Port),
                LocalDomain:        "client.example",
                UseTLS:             TLSUsage.NoTLS,
                ConnectionTimeout:  TimeSpan.FromSeconds(5),
                CommandTimeout:     TimeSpan.FromSeconds(5));

    private static EMailEnvelop Message(String Subject, params String[] Body)
        => new (EMail.Parse([
                    "From: app@client.example",
                    "To: you@sink.example",
                    $"Subject: {Subject}",
                    "Content-Type: text/plain; charset=utf-8",
                    "",
                    .. Body
                ]));


    [Test(Description = "RFC 5321: Hermod's submission client delivers to Postfix smtp-sink")]
    public async Task Delivery_to_smtp_sink()
    {

        using var sink   = await StartSink();
        using var client = ClientFor(sink);

        var marker = $"marker-{Guid.NewGuid():N}";
        var result = await client.Send(Message(marker, "hello", ".leading period"), NumberOfRetries: 0);

        Assert.That(result, Is.EqualTo(MailSentStatus.ok));
        Assert.That(sink.Dumps(), Does.Contain(marker).And.Contain("\n.leading period"));

    }


    [Test(Description = "RFC 5321 §3.2, §4.1.4: against a server without ESMTP (smtp-sink -e), the client falls back to HELO")]
    [Category(TestCategories.KnownIssue), Property("Finding", "C-2")]
    public async Task Helo_fallback_against_a_non_esmtp_server()
    {

        using var sink   = await StartSink("-e");
        using var client = ClientFor(sink);

        var marker = $"marker-{Guid.NewGuid():N}";
        var result = await client.Send(Message(marker, "hello"), NumberOfRetries: 0);

        Assert.That(result, Is.EqualTo(MailSentStatus.ok));
        Assert.That(sink.Dumps(), Does.Contain(marker));

    }


    [Test(Description = "RFC 5321 §2.4, RFC 6152: to a server without 8BITMIME (smtp-sink -8) no octet with the high bit set is sent")]
    [Category(TestCategories.KnownIssue), Property("Finding", "C-4")]
    public async Task No_8bit_octets_without_8bitmime()
    {

        using var sink   = await StartSink("-8");
        using var client = ClientFor(sink);

        var marker = $"marker-{Guid.NewGuid():N}";
        var result = await client.Send(Message(marker, "Grüße aus Köln"), NumberOfRetries: 0);

        Assume.That(result, Is.EqualTo(MailSentStatus.ok));

        var dump = sink.Dumps();

        Assert.That(dump, Does.Contain(marker));
        Assert.That(dump.Any(c => c > '\x7F'), Is.False, "the message reached the server with 8-bit content");

    }


    [Test(Description = "RFC 5321 §3.8, §4.2.2: a 421 after DATA (smtp-sink -Q DATA) ends the attempt promptly and is not reported as success")]
    public async Task A_421_mid_transaction_is_a_failure()
    {

        using var sink   = await StartSink("-Q DATA");
        using var client = ClientFor(sink);

        var started = Stopwatch.StartNew();
        var result  = await client.Send(Message("421", "hello"), NumberOfRetries: 0);

        Assert.Multiple(() => {
            Assert.That(result,          Is.Not.EqualTo(MailSentStatus.ok));
            Assert.That(started.Elapsed, Is.LessThan(TimeSpan.FromSeconds(5)));
        });

    }

}
