using System.Text;

using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 6152 (8BITMIME) and RFC 6531 (SMTPUTF8).
/// </summary>
[TestFixture]
public sealed class InternationalizationTests : HermodServerTestBase
{

    [Test(Description = "RFC 6152 §2, RFC 6531 §3.1: 8BITMIME and SMTPUTF8 are advertised")]
    public async Task Eightbitmime_and_smtputf8_are_advertised()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        var (_, extensions) = await client.EhloAsync();

        Assert.That(extensions.Keys, Does.Contain("8BITMIME").And.Contain("SMTPUTF8"), Explain(client));

    }


    [Test(Description = "RFC 6152 §3: BODY=8BITMIME is accepted and 8-bit content arrives unchanged")]
    public async Task Eight_bit_content_is_preserved()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var marker = Marker();
        var text   = "Grüße aus Köln — ½ € ✓";

        var mail = await client.CommandAsync("MAIL FROM:<sender@client.example> BODY=8BITMIME");
        await client.CommandAsync("RCPT TO:<alice@hermod.test>");
        var (_, final) = await client.DataAsync(RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", marker, text));

        var stored = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.Multiple(() => {
            Assert.That(mail.Code,   Is.EqualTo(250), Explain(client));
            Assert.That(final?.Code, Is.EqualTo(250), Explain(client));
            Assert.That(stored?.Raw, Does.Contain(text), Explain(client));
        });

    }


    [Test(Description = "RFC 6152 §2: body-value ::= \"7BIT\" / \"8BITMIME\" — any other BODY= value is a parameter error")]
    [Property("Finding", "S-6")]
    public async Task An_unknown_body_value_is_rejected()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var reply = await client.CommandAsync("MAIL FROM:<sender@client.example> BODY=9BITMIME");

        Assert.That(reply.Code, Is.AnyOf(501, 555), Explain(client));

    }


    [Test(Description = "RFC 6531 §3.4: with the SMTPUTF8 parameter, UTF-8 envelope addresses are accepted and delivered")]
    [Property("Finding", "S-11")]
    public async Task Utf8_addresses_with_the_smtputf8_parameter_are_accepted()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var marker = Marker();

        var mail = await client.CommandAsync("MAIL FROM:<jöran@bücher.example> SMTPUTF8");
        var rcpt = await client.CommandAsync("RCPT TO:<ümlaut@hermod.test>");
        var (_, final) = await client.DataAsync(RawSmtpClientExtensions.Message("jöran@bücher.example", "ümlaut@hermod.test", marker, "x"));

        var stored = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.Multiple(() => {
            Assert.That(mail.Code,              Is.EqualTo(250), Explain(client));
            Assert.That(rcpt.Code,              Is.EqualTo(250), Explain(client));
            Assert.That(final?.Code,            Is.EqualTo(250), Explain(client));
            Assert.That(stored?.EnvelopeFrom,   Is.EqualTo("jöran@bücher.example"), "the envelope sender must be decoded as UTF-8");
            Assert.That(stored?.EnvelopeTo,     Is.EqualTo(new[] { "ümlaut@hermod.test" }), "the envelope recipient must be decoded as UTF-8");
        });

    }


    [Test(Description = "RFC 6531 §3.5: \"When messages are rejected because the MAIL command requires an ASCII address, the reply-code 550 is returned\" — a UTF-8 sender without SMTPUTF8")]
    [Category(TestCategories.KnownIssue), Property("Finding", "S-12")]
    public async Task A_utf8_sender_without_smtputf8_is_rejected_with_550()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var reply = await client.CommandAsync("MAIL FROM:<jöran@bücher.example>");

        Assert.That(reply.Code, Is.EqualTo(550), Explain(client));

    }


    [Test(Description = "RFC 6531 §3.5: \"When messages are rejected because the RCPT command requires an ASCII address, the reply-code 553 is returned\" — a UTF-8 recipient without SMTPUTF8")]
    [Category(TestCategories.KnownIssue), Property("Finding", "S-12")]
    public async Task A_utf8_recipient_without_smtputf8_is_rejected_with_553()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        await client.CommandAsync("MAIL FROM:<sender@client.example>");
        var reply = await client.CommandAsync("RCPT TO:<ümlaut@hermod.test>");

        Assert.That(reply.Code, Is.EqualTo(553), Explain(client));

    }

}
