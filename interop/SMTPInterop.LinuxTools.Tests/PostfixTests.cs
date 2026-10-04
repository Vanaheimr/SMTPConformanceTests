using System.Diagnostics;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;

namespace SMTPInterop.LinuxTools.Tests;

/// <summary>
/// Postfix, both directions: the MTA Hermod meets most often.
/// <list type="bullet">
/// <item>Postfix → Hermod: Postfix's smtp client delivers to Hermod as the next hop, as a
/// Postfix MX relaying to Hermod would - plain, SMTPUTF8, and over enforced STARTTLS.</item>
/// <item>Hermod → Postfix: Hermod's <see cref="SMTPOutboundClient"/> relays through a strict
/// Postfix smtpd (no bare LFs, FQDN HELO, RFC 821 envelopes), which passes the message on to
/// smtp-sink - whose dump shows the MAIL and RCPT parameters as Postfix received and forwarded
/// them - or, for SMTPUTF8, to Hermod's own server.</item>
/// </list>
/// </summary>
[TestFixture]
public sealed class PostfixTests : LinuxToolTestBase
{

    #region Helpers

    private static String Marker()
        => $"marker-{Guid.NewGuid():N}";

    private static String Message(String Marker, String To, String Body = "hello")

        => $"From: postfix-sender@interop.test\nTo: {To}\nSubject: {Marker}\nContent-Type: text/plain; charset=utf-8\n\n{Body}\n";


    /// <summary>
    /// smtp-sink inside the Linux side, as the final hop behind Postfix.
    /// </summary>
    private sealed class Sink : IDisposable
    {

        public required Process  Process  { get; init; }
        public required UInt16   Port     { get; init; }
        public required String   DumpDir  { get; init; }

        public String Dumps()
            => Wsl.Run($"cat {DumpDir}/* 2>/dev/null", TimeSpan.FromSeconds(15)).StdOut;

        public async Task<String?> WaitForAsync(String Marker, TimeSpan Within)
        {
            var deadline = DateTime.UtcNow + Within;
            while (DateTime.UtcNow < deadline)
            {
                var dumps = Dumps();
                if (dumps.Contains(Marker, StringComparison.Ordinal))
                    return dumps;
                await Task.Delay(500);
            }
            return null;
        }

        public void Dispose()
        {
            try { Process.Kill(entireProcessTree: true); } catch { }
            Wsl.Run($"pkill -f 'smtp-sink.*:{Port} ' ; rm -rf {DumpDir}", TimeSpan.FromSeconds(15));
        }

    }

    private static async Task<Sink> StartSink()
    {

        TestEnvironment.RequireWsl("smtp-sink");

        var port    = (UInt16) Random.Shared.Next(20000, 60000);
        var dumpDir = $"/tmp/smtp-sink-{Guid.NewGuid():N}";
        var process = Wsl.StartDetached($"mkdir -p {dumpDir} && chmod 777 {dumpDir} && " +
                                        $"if [ \"$(id -u)\" = 0 ]; then U='-u nobody'; else U=''; fi && " +
                                        $"exec /usr/sbin/smtp-sink $U -d {dumpDir}/ 127.0.0.1:{port} 16",
                                        asRoot: false);

        await Task.Delay(1000);
        return new Sink { Process = process, Port = port, DumpDir = dumpDir };

    }


    /// <summary>
    /// Hand an envelope to Hermod's outbound client, with the given Postfix as its smart host.
    /// </summary>
    private static async Task<SendResult> RelayThrough(PostfixInstance Postfix, EMailEnvelop Envelope)
    {

        var client  = new SMTPOutboundClient(new SmtpOutboundConfig {
                                                 LocalHostname     = "relay.hermod.test",
                                                 SmartHost         = Postfix.Host,
                                                 SmartHostPort     = Postfix.Port,
                                                 ConnectTimeoutMs  = 5_000,
                                                 ReadTimeoutMs     = 10_000,
                                                 WriteTimeoutMs    = 10_000
                                             },
                                             null,
                                             new StubDnsClient(),
                                             new CapturingLogger());

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        return (await new MailSender(new CapturingMailQueue(), new CapturingLogger(), client).SendDirectAsync(Envelope, cts.Token)).Single().Result;

    }

    private static EMailEnvelop Envelope(String Marker, String To, String Body = "hello", DsnParameters? Dsn = null)

        => new (EMail.Parse([
                    "From: app@client.example",
                    $"To: {To}",
                    $"Subject: {Marker}",
                    "Content-Type: text/plain; charset=utf-8",
                    "",
                    Body
                ])) { Dsn = Dsn ?? DsnParameters.None };

    #endregion


    #region Postfix → Hermod

    [Test(Description = "RFC 5321: Postfix delivers to Hermod as its next hop")]
    public async Task Postfix_delivers_to_Hermod()
    {

        Require("postfix");
        using var postfix = await PostfixInstance.StartAsync($"[{LinuxSideHost}]:{Server.MtaPort}");

        var marker   = Marker();
        var injected = postfix.Inject("postfix-sender@interop.test", [ "bob@hermod.test" ], Message(marker, "bob@hermod.test"));
        Assume.That(injected.Success, injected.ToString());

        var stored   = await Server.Storage.WaitForMarkerAsync(marker, TimeSpan.FromSeconds(30));

        Assert.That(stored, Is.Not.Null, "Postfix's log:\n" + postfix.Log + "\n--- Hermod ---\n" + Server.Log);

    }


    [Test(Description = "RFC 2920, RFC 5321 §3.3: Postfix pipelines one message to two recipients, and Hermod gets it once for both")]
    public async Task Postfix_delivers_one_message_to_two_recipients()
    {

        Require("postfix");
        using var postfix = await PostfixInstance.StartAsync($"[{LinuxSideHost}]:{Server.MtaPort}");

        var marker   = Marker();
        var injected = postfix.Inject("postfix-sender@interop.test", [ "bob@hermod.test", "carol@hermod.test" ], Message(marker, "bob@hermod.test, carol@hermod.test"));
        Assume.That(injected.Success, injected.ToString());

        var stored   = await Server.Storage.WaitForMarkerAsync(marker, TimeSpan.FromSeconds(30));

        Assert.That(stored?.EnvelopeTo, Is.EquivalentTo(new[] { "bob@hermod.test", "carol@hermod.test" }),
                    "Postfix's log:\n" + postfix.Log);

    }


    [Test(Description = "RFC 6531: Postfix delivers a message with a UTF-8 recipient and an 8-bit body to Hermod with SMTPUTF8, and it arrives intact")]
    public async Task Postfix_delivers_SMTPUTF8_to_Hermod()
    {

        Require("postfix");
        using var postfix = await PostfixInstance.StartAsync($"[{LinuxSideHost}]:{Server.MtaPort}");

        var marker   = Marker();
        var injected = postfix.Inject("postfix-sender@interop.test", [ "jöran@hermod.test" ], Message(marker, "jöran@hermod.test", "Grüße aus Köln"));
        Assume.That(injected.Success, injected.ToString());

        var stored   = await Server.Storage.WaitForMarkerAsync(marker, TimeSpan.FromSeconds(30));

        Assert.Multiple(() => {
            Assert.That(stored?.EnvelopeTo, Is.EqualTo(new[] { "jöran@hermod.test" }), "Postfix's log:\n" + postfix.Log);
            Assert.That(stored?.Raw,        Does.Contain("Grüße aus Köln"));
        });

    }


    [Test(Description = "RFC 3207: Postfix with smtp_tls_security_level = encrypt delivers to Hermod over STARTTLS - or not at all")]
    public async Task Postfix_delivers_to_Hermod_over_enforced_STARTTLS()
    {

        Require("postfix");
        using var postfix = await PostfixInstance.StartAsync($"[{LinuxSideHost}]:{Server.MtaPort}",
                                                            [ "smtp_tls_security_level = encrypt", "smtp_tls_loglevel = 1" ]);

        var marker   = Marker();
        var injected = postfix.Inject("postfix-sender@interop.test", [ "bob@hermod.test" ], Message(marker, "bob@hermod.test"));
        Assume.That(injected.Success, injected.ToString());

        var stored   = await Server.Storage.WaitForMarkerAsync(marker, TimeSpan.FromSeconds(30));

        Assert.Multiple(() => {
            Assert.That(stored,       Is.Not.Null, "Postfix's log:\n" + postfix.Log);
            Assert.That(postfix.Log,  Does.Contain("TLS connection established to"));
        });

    }

    #endregion

    #region Hermod → Postfix

    [Test(Description = "RFC 5321: Hermod's outbound client relays through a strict Postfix, which accepts and passes the message on")]
    public async Task Hermod_relays_through_a_strict_Postfix()
    {

        Require("postfix", "smtp-sink");
        using var sink    = await StartSink();
        using var postfix = await PostfixInstance.StartAsync($"[127.0.0.1]:{sink.Port}");

        var marker = Marker();
        var result = await RelayThrough(postfix, Envelope(marker, "you@sink.example", "hello\n.leading period"));

        var dump   = await sink.WaitForAsync(marker, TimeSpan.FromSeconds(30));

        Assert.Multiple(() => {
            Assert.That(result.Status, Is.EqualTo(SendStatus.Success), $"{result.ResponseCode} {result.ResponseText}\nPostfix's log:\n{postfix.Log}");
            Assert.That(dump,          Does.Contain("\n.leading period"), "Postfix's log:\n" + postfix.Log);
        });

    }


    [Test(Description = "RFC 3461: the DSN parameters Hermod sends survive Postfix - RET and ENVID on MAIL, NOTIFY on RCPT")]
    public async Task DSN_parameters_pass_through_Postfix()
    {

        Require("postfix", "smtp-sink");
        using var sink    = await StartSink();
        using var postfix = await PostfixInstance.StartAsync($"[127.0.0.1]:{sink.Port}");

        var marker = Marker();
        var envId  = $"env-{Guid.NewGuid():N}"[..20];
        var result = await RelayThrough(postfix, Envelope(marker, "you@sink.example", Dsn: new DsnParameters(DsnNotify.Failure | DsnNotify.Delay, DsnRet.Hdrs, envId)));

        var dump   = await sink.WaitForAsync(marker, TimeSpan.FromSeconds(30)) ?? "";

        var mailArgs = dump.Split('\n').FirstOrDefault(line => line.StartsWith("X-Mail-Args:"))  ?? "";
        var rcptArgs = dump.Split('\n').FirstOrDefault(line => line.StartsWith("X-Rcpt-Args:"))  ?? "";

        Assert.Multiple(() => {
            Assert.That(result.Status, Is.EqualTo(SendStatus.Success), "Postfix's log:\n" + postfix.Log);
            Assert.That(mailArgs,      Does.Contain("RET=HDRS").And.Contain($"ENVID={envId}"), dump);
            Assert.That(rcptArgs,      Does.Contain("NOTIFY=FAILURE,DELAY").Or.Contain("NOTIFY=DELAY,FAILURE"), dump);
        });

    }


    [Test(Description = "RFC 6152 §3: Hermod declares its 8-bit content as BODY=8BITMIME, and Postfix passes the declaration on")]
    [Category(TestCategories.KnownIssue), Property("Finding", "O-3")]
    public async Task Eight_bit_content_reaches_Postfix_as_BODY_8BITMIME()
    {

        Require("postfix", "smtp-sink");
        using var sink    = await StartSink();
        using var postfix = await PostfixInstance.StartAsync($"[127.0.0.1]:{sink.Port}");

        var marker = Marker();
        await RelayThrough(postfix, Envelope(marker, "you@sink.example", "Grüße aus Köln"));

        var dump     = await sink.WaitForAsync(marker, TimeSpan.FromSeconds(30)) ?? "";
        var mailArgs = dump.Split('\n').FirstOrDefault(line => line.StartsWith("X-Mail-Args:")) ?? "";

        Assert.That(mailArgs, Does.Contain("BODY=8BITMIME"), dump + "\nPostfix's log:\n" + postfix.Log);

    }


    [Test(Description = "RFC 6531: Hermod relays a message with a UTF-8 recipient through Postfix with SMTPUTF8 - Postfix refuses it without - and it reaches the next hop intact")]
    [Category(TestCategories.KnownIssue), Property("Finding", "O-3")]
    public async Task A_UTF8_recipient_reaches_the_next_hop_through_Postfix()
    {

        Require("postfix");
        using var postfix = await PostfixInstance.StartAsync($"[{LinuxSideHost}]:{Server.MtaPort}");

        var marker = Marker();
        var result = await RelayThrough(postfix, Envelope(marker, "jöran@hermod.test"));

        var stored = await Server.Storage.WaitForMarkerAsync(marker, TimeSpan.FromSeconds(30));

        Assert.Multiple(() => {
            Assert.That(result.Status,       Is.EqualTo(SendStatus.Success), $"{result.ResponseCode} {result.ResponseText}\nPostfix's log:\n{postfix.Log}");
            Assert.That(stored?.EnvelopeTo,  Is.EqualTo(new[] { "jöran@hermod.test" }));
        });

    }


    [Test(Description = "RFC 3207, RFC 7435: Hermod's outbound client uses the STARTTLS Postfix offers")]
    public async Task Hermod_relays_to_Postfix_over_STARTTLS()
    {

        Require("postfix", "smtp-sink");
        using var sink    = await StartSink();
        using var postfix = await PostfixInstance.StartAsync($"[127.0.0.1]:{sink.Port}", WithCertificate: true);

        var marker = Marker();
        var result = await RelayThrough(postfix, Envelope(marker, "you@sink.example"));

        Assert.Multiple(() => {
            Assert.That(result.Status, Is.EqualTo(SendStatus.Success), "Postfix's log:\n" + postfix.Log);
            Assert.That(postfix.Log,   Does.Contain("TLS connection established from"));
        });

    }

    #endregion

}
