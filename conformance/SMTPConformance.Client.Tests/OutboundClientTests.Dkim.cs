using System.Security.Cryptography;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;
using org.GraphDefined.Vanaheimr.Hermod.SMTP.Server;

using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

public sealed partial class OutboundClientTests
{

    #region DKIM signatures on the way out

    /// <summary>
    /// A DKIM key made by the test - not by Hermod - as Hermod is configured with it, and its
    /// key record as RFC 6376 §3.6.1 and RFC 8463 §4.2 write it.
    /// </summary>
    private sealed record DkimKey(DkimConfig Config, String RecordName, String Record);

    private static DkimKey RsaKey(String Domain, String Selector = "rsa")
    {
        using var rsa = RSA.Create(2048);
        return new (new DkimConfig { Domain = Domain, Selector = Selector, PrivateKeyPem = rsa.ExportPkcs8PrivateKeyPem() },
                    $"{Selector}._domainkey.{Domain}",
                    $"v=DKIM1; k=rsa; p={Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo())}");
    }

    private static DkimKey Ed25519Key(String Domain, String Selector = "ed")
    {

        var generator = new Ed25519KeyPairGenerator();
        generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var pair      = generator.GenerateKeyPair();

        return new (new DkimConfig { Domain = Domain, Selector = Selector,
                                     PrivateKeyPem = PemEncoding.WriteString("PRIVATE KEY", PrivateKeyInfoFactory.CreatePrivateKeyInfo(pair.Private).GetEncoded()) },
                    $"{Selector}._domainkey.{Domain}",
                    $"v=DKIM1; k=ed25519; p={Convert.ToBase64String(((Ed25519PublicKeyParameters) pair.Public).GetEncoded())}");

    }

    /// <summary>
    /// Send the message through the scripted smart host, signed as configured; the message as
    /// it arrived - its octets as Latin-1 text, dot-stuffing undone.
    /// </summary>
    private static async Task<String> SendSigned(IReadOnlyList<String>       Lines,
                                                 DkimSigner                  Signer,
                                                 Func<String, DkimSigner?>?  SignerFor = null)
    {

        var script = new SmtpServerScript();
        await using var server = ScriptedSmtpServer.Start(script);

        var client = new SMTPOutboundClient(ConfigFor(server), Signer, new StubDnsClient(), new CapturingLogger(), dkimSignerFor: SignerFor);
        var sender = new MailSender(new CapturingMailQueue(), new CapturingLogger(), client);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var result = (await sender.SendDirectAsync(new EMailEnvelop(EMail.Parse([ .. Lines ])), cts.Token)).Single().Result;

        await server.WhenIdleAsync();

        Assert.That(result.Status, Is.EqualTo(SendStatus.Success), result.ResponseText + Explain(server));

        return String.Concat(script.Transactions.Single().DataLines.
                                    Select(line => line.Latin1).
                                    Select(line => (line.StartsWith('.') ? line[1..] : line) + "\r\n"));

    }

    private static String[] Letter(String From, params String[] Body)
        => [ $"From: {From}", "To: you@outbound.test", "Subject: signed on the way out", "Date: Thu, 19 Nov 2026 10:00:00 +0000",
             "Message-ID: <" + Guid.NewGuid().ToString("N") + "@hermod.test>", "", .. Body ];


    [Test(Description = "RFC 6376 §3.7, RFC 8463 §3: a message signed with an RSA and an Ed25519 key (\"signers ... SHOULD ... sign with both\", RFC 8463 §1) leaves with two signatures that verify - checked by the suite's own verifier")]
    public async Task A_message_signed_with_RSA_and_Ed25519_verifies_with_both()
    {

        var rsa     = RsaKey    ("hermod.test");
        var ed25519 = Ed25519Key("hermod.test");

        var message = await SendSigned(Letter("news@hermod.test", "Hello  world ", "", "with whitespace\tto canonicalize   "),
                                       new DkimSigner([ rsa.Config, ed25519.Config ], new CapturingLogger()));

        var results = TestDkimVerifier.Verify(message, new Dictionary<String, String> { [rsa.RecordName] = rsa.Record, [ed25519.RecordName] = ed25519.Record });

        Assert.Multiple(() => {
            Assert.That(results.Select(result => result.Algorithm),   Is.EquivalentTo(new[] { "rsa-sha256", "ed25519-sha256" }), message);
            Assert.That(results.Where(result => !result.Valid),       Is.Empty,                                                  message);
        });

    }


    [Test(Description = "RFC 7489 §3.1.1: a message from a domain with a key of its own is signed with that key (d= its From: domain), so that DMARC aligns")]
    public async Task A_message_is_signed_with_the_key_of_its_From_domain()
    {

        var own   = RsaKey("hermod.test");
        var other = RsaKey("other.test");

        var otherSigner = new DkimSigner(other.Config, new CapturingLogger());

        var message = await SendSigned(Letter("news@other.test", "Hello."),
                                       new DkimSigner(own.Config, new CapturingLogger()),
                                       domain => domain == "other.test" ? otherSigner : null);

        var results = TestDkimVerifier.Verify(message, new Dictionary<String, String> { [own.RecordName] = own.Record, [other.RecordName] = other.Record });

        Assert.Multiple(() => {
            Assert.That(results.Select(result => result.Domain),  Is.EqualTo(new[] { "other.test" }), message);
            Assert.That(results.All(result => result.Valid),      Is.True,                            message);
        });

    }


    [Test(Description = "RFC 6376 §5.3, RFC 6152: an 8-bit body is signed as the octets that go on the wire - the signature verifies over what arrived")]
    public async Task An_8bit_message_is_signed_over_the_octets_that_are_sent()
    {

        var rsa = RsaKey("hermod.test");

        var message = await SendSigned([ .. Letter("news@hermod.test").SkipLast(1),
                                         "MIME-Version: 1.0", "Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: 8bit", "",
                                         "Grüße aus Jena - Ærøskøbing" ],
                                       new DkimSigner(rsa.Config, new CapturingLogger()));

        var results = TestDkimVerifier.Verify(message, new Dictionary<String, String> { [rsa.RecordName] = rsa.Record });

        Assert.Multiple(() => {
            Assert.That(message.Any(c => c > 0x7F),            Is.True,  "the body went out as 8-bit octets: " + message);
            Assert.That(results.Single().Valid,                 Is.True,  results.Single().Detail + "\n" + message);
        });

    }

    #endregion

}
