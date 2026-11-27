using System.Diagnostics;
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;
using org.GraphDefined.Vanaheimr.Hermod.SMTP.Server;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

public sealed partial class OutboundClientTests
{

    #region The canonicalization Hermod signs with

    private static String[] Letter8bit(params String[] Body)
        => [ .. Letter("news@hermod.test").SkipLast(1),
             "MIME-Version: 1.0", "Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: 8bit", "",
             .. Body ];

    /// <summary>
    /// The message sent directly, as text, signed on the way out; the message as it arrived, and
    /// what the suite's own verifier makes of its signatures.
    /// </summary>
    private static async Task<(IReadOnlyList<DkimVerification> Results, String Message)> SendSignedWith(DkimKey Key, String[] Lines)
    {
        var message = await SendSigned(Lines, new DkimSigner(Key.Config, new CapturingLogger()));
        return (TestDkimVerifier.Verify(message, new Dictionary<String, String> { [Key.RecordName] = Key.Record }), message);
    }

    /// <summary>
    /// The way a relay sends what it received: the message queued as its octets
    /// (<see cref="MailSender.SendAsync(String, IEnumerable{String}, Byte[], DsnParameters?, Boolean, CancellationToken)"/>),
    /// delivered by the QueueProcessor through the scripted smart host, signed on the way out;
    /// the message as it arrived, its octets as Latin-1 text, and what the suite's own verifier
    /// makes of its signatures.
    /// </summary>
    private static async Task<(IReadOnlyList<DkimVerification> Results, String Message)> RelaySignedWith(DkimKey Key, String[] Lines)
    {

        var script = new SmtpServerScript();
        await using var server = ScriptedSmtpServer.Start(script);

        var queue     = new CapturingMailQueue();
        var logger    = new CapturingLogger();
        var client    = new SMTPOutboundClient(ConfigFor(server), new DkimSigner(Key.Config, logger), new StubDnsClient(), logger);
        var bounces   = new BounceHandler(new SMTPServerConfig { Hostname = "relay.hermod.test" }, queue, logger);
        var processor = new QueueProcessor(queue, client, bounces, new QueueProcessorConfig { DomainCooldownSeconds = 0 }, logger);

        await processor.StartAsync();

        var octets   = Encoding.UTF8.GetBytes(String.Concat(Lines.Select(line => line + "\r\n")));
        var id       = (await new MailSender(queue, logger).SendAsync("news@hermod.test", [ "you@outbound.test" ], octets)).Single();

        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < TimeSpan.FromSeconds(10) &&
               (await queue.GetByIdAsync(id))?.Status is null or QueueItemStatus.Pending or QueueItemStatus.Processing)
            await Task.Delay(50);

        await processor.StopAsync();
        await processor.DisposeAsync();
        await server.WhenIdleAsync();

        Assert.That((await queue.GetByIdAsync(id))?.Status, Is.EqualTo(QueueItemStatus.Delivered), Explain(server));

        var message = String.Concat(script.Transactions.Single().DataLines.
                                           Select(line => line.Latin1).
                                           Select(line => (line.StartsWith('.') ? line[1..] : line) + "\r\n"));

        return (TestDkimVerifier.Verify(message, new Dictionary<String, String> { [Key.RecordName] = Key.Record }), message);

    }

    #region P-4: white space is WSP, and nothing else

    private static IEnumerable<TestCaseData> LinesEndingInNoWsp()
    {

        static TestCaseData Case(String Name, String Line, Boolean Relayed)
            => new TestCaseData(Line, Relayed).SetName($"A body whose line ends in {Name} is signed so that it verifies: {(Relayed ? "relayed from the queue, as octets" : "sent directly, as text")}")
                                              .SetProperty("Finding", "P-4");

        // Relayed, the message is signed as its octets, and the last octet of a UTF-8 character,
        // 0xA0 or 0x85, was taken for white space. Sent as text, it is a character - but the
        // NO-BREAK SPACE and the form feed are taken for white space both ways.
        yield return Case("à, C3 A0 (French)",        "Rendez-vous demain, voilà",  Relayed: true);
        yield return Case("ą, C4 85 (Polish)",        "Do zobaczenia z tobą",       Relayed: true);
        yield return Case("х, D1 85 (Russian)",       "До встречи в выходных",      Relayed: true);
        yield return Case("a NO-BREAK SPACE, C2 A0",  "Total: 10 EUR ",        Relayed: true);
        yield return Case("a NO-BREAK SPACE, C2 A0",  "Total: 10 EUR ",        Relayed: false);
        yield return Case("a form feed, 0C",          "Page 1\f",                   Relayed: true);
        yield return Case("a form feed, 0C",          "Page 1\f",                   Relayed: false);

    }

    [TestCaseSource(nameof(LinesEndingInNoWsp))]
    [Description("RFC 6376 §3.4.4, §2.8: relaxed body canonicalization deletes the whitespace at the end of lines, and whitespace is \"WSP = SP / HTAB\" - a signer that deletes more, an octet of a UTF-8 character, a NO-BREAK SPACE, a form feed, hashes another body than every verifier does. Signed relaxed/relaxed (Hermod's default) on the way out, the message verifies with the suite's own verifier")]
    public async Task A_body_whose_line_ends_in_no_WSP_is_signed_so_that_it_verifies(String Line, Boolean Relayed)
    {

        var rsa = RsaKey("hermod.test");

        var (results, message) = Relayed ? await RelaySignedWith(rsa, Letter8bit("Hello,", Line, "Bye."))
                                         : await SendSignedWith (rsa, Letter8bit("Hello,", Line, "Bye."));

        Assert.That(results.Select(r => r.Valid), Is.EqualTo(new[] { true }), String.Join("; ", results.Select(r => r.Detail)) + "\n" + message);

    }


    [Test(Description = "RFC 6376 §3.4.4: a line ending in a character whose last octet is no white space of any kind - ü, C3 BC - is signed so that it verifies, relayed as octets and sent as text; and so is one ending in a character of 0xA0 or 0x85 sent as text (a guard for P-4)")]
    [Property("Finding", "P-4")]
    public async Task A_body_of_UTF_8_text_is_signed_so_that_it_verifies()
    {

        var rsa = RsaKey("hermod.test");

        var (relayed, relayedMessage) = await RelaySignedWith(rsa, Letter8bit("Hello,", "Viele Grüße aus Jena, Jörg Müller, Tschüs", "Bye."));
        var (sent,    sentMessage)    = await SendSignedWith (rsa, Letter8bit("Hello,", "Do zobaczenia z tobą, voilà", "Bye."));

        Assert.Multiple(() => {
            Assert.That(relayed.Select(r => r.Valid), Is.EqualTo(new[] { true }), String.Join("; ", relayed.Select(r => r.Detail)) + "\n" + relayedMessage);
            Assert.That(sent.Select(r => r.Valid),    Is.EqualTo(new[] { true }), String.Join("; ", sent.Select(r => r.Detail))    + "\n" + sentMessage);
        });

    }


    [Test(Description = "RFC 6376 §3.4.4: what is WSP - spaces and tabs at the end of a line, runs of them inside it - is canonicalized away, and the signature verifies, relayed as octets and sent as text (a guard for P-4)")]
    [Property("Finding", "P-4")]
    public async Task A_body_with_WSP_at_the_end_of_its_lines_is_signed_so_that_it_verifies()
    {

        var rsa = RsaKey("hermod.test");

        var (sent,    sentMessage)    = await SendSignedWith (rsa, Letter8bit("Hello, \t world. \t ", "Grüße  ", "Bye."));
        var (relayed, relayedMessage) = await RelaySignedWith(rsa, Letter8bit("Hello, \t world. \t ", "Grüße  ", "Bye."));

        Assert.Multiple(() => {
            Assert.That(sent.Select(r => r.Valid),    Is.EqualTo(new[] { true }), String.Join("; ", sent.Select(r => r.Detail))    + "\n" + sentMessage);
            Assert.That(relayed.Select(r => r.Valid), Is.EqualTo(new[] { true }), String.Join("; ", relayed.Select(r => r.Detail)) + "\n" + relayedMessage);
        });

    }


    [Test(Description = "RFC 8617 §4.1.2, RFC 6376 §3.4.4: the ARC sealer canonicalizes the body of its AMS relaxed - a line that ends in a form feed or a NO-BREAK SPACE keeps it, and the sealed message validates with the suite's validator")]
    [Property("Finding", "P-4")]
    public void A_sealed_body_whose_line_ends_in_no_WSP_validates()
    {

        using var key = new TestDkimKey("forwarder.example", "arc");
        using var rsa = key.PublicKey();

        var message = "From: <news@origin.example>\r\n" +
                      "To: <list@forwarder.example>\r\n" +
                      "Subject: sealed\r\n" +
                      $"Message-ID: <{Guid.NewGuid():N}@origin.example>\r\n" +
                      "Date: Thu, 19 Nov 2026 10:00:00 +0000\r\n" +
                      "\r\n" +
                      "Page 1\f\r\n" +
                      "Total: 10 EUR \r\n";

        var sealer  = new ArcSealer(new ArcConfig { Domain = key.Domain, Selector = key.Selector, PrivateKeyPem = key.ExportPrivateKeyPem() }, new CapturingLogger());
        var sealed_ = sealer.Seal(message, "forwarder.example", "spf=pass smtp.mailfrom=origin.example", ArcResult.None);

        Assert.That(TestArc.Validate(sealed_, rsa), Is.EqualTo(("pass", "1 ARC set(s)")), sealed_);

    }

    #endregion

    #region P-5: c= of one name

    [Test(Description = "RFC 6376 §3.5, c=: \"If only one algorithm is named, that algorithm is used for the header and \"simple\" is used for the body. For example, \"c=relaxed\" is treated the same as \"c=relaxed/simple\"\" - a signer configured with c=relaxed writes c=relaxed and hashes the body simple: over a body with white space that relaxed canonicalization would change, the signature verifies with the suite's own verifier")]
    [Property("Finding", "P-5")]
    public async Task A_signer_configured_with_c_relaxed_hashes_the_body_simple()
    {

        var rsa = RsaKey("hermod.test");
        var key = rsa with { Config = rsa.Config with { Canonicalization = "relaxed" } };

        var (results, message) = await SendSignedWith(key, Letter("news@hermod.test", "Hello,  world.  ", "Bye."));

        Assert.That(results.Select(r => r.Valid), Is.EqualTo(new[] { true }), String.Join("; ", results.Select(r => r.Detail)) + "\n" + message);

    }


    [TestCase("relaxed/simple")]
    [TestCase("relaxed/relaxed")]
    [TestCase("simple/simple")]
    [Description("RFC 6376 §3.5, c=: both canonicalizations named - a signer configured with them signs a message with white space so that it verifies (a guard for P-5)")]
    [Property("Finding", "P-5")]
    public async Task A_signer_configured_with_both_canonicalizations_named_signs_so_that_it_verifies(String Canonicalization)
    {

        var rsa = RsaKey("hermod.test");
        var key = rsa with { Config = rsa.Config with { Canonicalization = Canonicalization } };

        var (results, message) = await SendSignedWith(key, Letter("news@hermod.test", "Hello,  world.  ", "Bye."));

        Assert.That(results.Select(r => r.Valid), Is.EqualTo(new[] { true }), String.Join("; ", results.Select(r => r.Detail)) + "\n" + message);

    }

    #endregion

    #endregion

}
