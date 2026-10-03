using System.Security.Authentication;
using System.Text;

using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Tls.Tests;

/// <summary>
/// RFC 3207: SMTP Service Extension for Secure SMTP over Transport Layer Security.
/// </summary>
[TestFixture]
public sealed class StartTlsTests : HermodServerTestBase
{

    protected override HermodSmtpServerFixtureOptions Options
        => new() { EnableTls = true };


    [Test(Description = "RFC 3207 §4: STARTTLS is advertised when the server can do TLS")]
    public async Task Starttls_is_advertised()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        var (_, extensions) = await client.EhloAsync();

        Assert.That(extensions.Keys, Does.Contain("STARTTLS"), Explain(client));

    }


    [Test(Description = "RFC 3207 §4: STARTTLS is answered with 220 and a TLS handshake (TLS 1.2 or later) follows")]
    public async Task Starttls_leads_to_a_tls_handshake()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        await client.EhloAsync();
        var reply = await client.StartTlsAsync();

        Assert.Multiple(() => {
            Assert.That(reply.Code,              Is.EqualTo(220), Explain(client));
            Assert.That(client.IsTls,            Is.True,         Explain(client));
            Assert.That(client.Tls!.SslProtocol, Is.AnyOf(SslProtocols.Tls12, SslProtocols.Tls13));
        });

    }


    [Test(Description = "RFC 3207 §4: STARTTLS takes no parameters — \"501 Syntax error (no parameters allowed)\"")]
    [Category(TestCategories.KnownIssue), Property("Finding", "S-8")]
    public async Task Starttls_with_a_parameter_is_501()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        await client.EhloAsync();
        var reply = await client.CommandAsync("STARTTLS now");

        Assert.That(reply.Code, Is.EqualTo(501), Explain(client));

    }


    [Test(Description = "RFC 3207 §4.2: \"A server MUST NOT return the STARTTLS extension in response to an EHLO command received after a TLS handshake has completed.\"")]
    public async Task Starttls_is_not_advertised_after_tls()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        await client.EhloAsync();
        await client.StartTlsAsync();
        var (reply, extensions) = await client.EhloAsync();

        Assert.Multiple(() => {
            Assert.That(reply.Code,      Is.EqualTo(250), Explain(client));
            Assert.That(extensions.Keys, Does.Not.Contain("STARTTLS"), Explain(client));
        });

    }


    [Test(Description = "RFC 3207 §4.2: STARTTLS a second time, inside TLS, is refused")]
    public async Task A_second_starttls_is_refused()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        await client.EhloAsync();
        await client.StartTlsAsync();
        await client.EhloAsync();
        var again = await client.CommandAsync("STARTTLS");

        Assert.That(again.Class, Is.EqualTo(5), Explain(client));

    }


    [Test(Description = "RFC 3207 §4.2: \"The server MUST discard any knowledge obtained from the client, such as the argument to the EHLO command\" — MAIL straight after the handshake needs a new EHLO")]
    public async Task Pre_tls_state_is_discarded()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        await client.EhloAsync();
        await client.StartTlsAsync();
        var mail = await client.CommandAsync("MAIL FROM:<sender@client.example>");

        Assert.That(mail.Code, Is.EqualTo(503), Explain(client));

    }


    [Test(Description = "RFC 3207 §4.2, §6 (CVE-2011-0411 class): commands pipelined after STARTTLS in the same packet are plaintext and must not be executed inside TLS")]
    public async Task Plaintext_pipelined_after_starttls_is_not_executed()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        await client.EhloAsync();

        // One write: STARTTLS and an injected command. A vulnerable server answers
        // the injected NOOP inside the TLS session, where the client takes it as
        // the reply to its own next command.
        await client.WriteRawAsync("STARTTLS\r\nNOOP\r\n");
        var starttls = await client.ReadReplyAsync();
        Assume.That(starttls.Code, Is.EqualTo(220), Explain(client));

        await client.UpgradeToTlsAsClientAsync("localhost");

        var ehlo = await client.CommandAsync("EHLO client.example");

        Assert.Multiple(() => {
            Assert.That(ehlo.Code,       Is.EqualTo(250), Explain(client));
            Assert.That(ehlo.IsMultiline, Is.True, "the first reply inside TLS must be the EHLO reply, not one to the injected NOOP" + Explain(client));
        });

    }


    [Test(Description = "RFC 3207 §4: a mail transaction over STARTTLS is delivered, and the Received: clause says ESMTPS (RFC 3848)")]
    public async Task Mail_over_starttls_is_delivered_as_esmtps()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        var marker = Marker();

        await client.EhloAsync();
        await client.StartTlsAsync();
        await client.EhloAsync();
        var final  = await client.SendMailAsync("sender@client.example", "alice@hermod.test",
                                                RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", marker, "secret"));

        var stored = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.Multiple(() => {
            Assert.That(final.Code,  Is.EqualTo(250), Explain(client));
            Assert.That(stored?.Raw, Does.Match(@"\bwith ESMTPS\b"), Explain(client));
        });

    }


    [Test(Description = "RFC 8689 §4: REQUIRETLS is advertised only on a TLS-protected session")]
    public async Task Requiretls_is_advertised_only_after_tls()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        var (_, before) = await client.EhloAsync();
        await client.StartTlsAsync();
        var (_, after)  = await client.EhloAsync();

        Assert.Multiple(() => {
            Assert.That(before.Keys, Does.Not.Contain("REQUIRETLS"), Explain(client));
            Assert.That(after.Keys,  Does.Contain("REQUIRETLS"),     Explain(client));
        });

    }


    [Test(Description = "RFC 8689 §4.1: MAIL FROM with REQUIRETLS outside TLS is refused")]
    public async Task Requiretls_in_cleartext_is_refused()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        await client.EhloAsync();
        var reply = await client.CommandAsync("MAIL FROM:<sender@client.example> REQUIRETLS");

        Assert.That(reply.Class, Is.EqualTo(5), Explain(client));

    }


    [Test(Description = "RFC 8689 §4.1, §5: a REQUIRETLS message relayed onward must carry the requirement into the queue")]
    [Property("Finding", "S-14")]
    public async Task Requiretls_is_carried_onto_the_relay_queue()
    {

        var (client, _) = await Server.ConnectSubmissionAsync();
        await using var __ = client;

        await client.EhloAsync();
        await client.StartTlsAsync();
        await client.EhloAsync();

        var plain = Convert.ToBase64String(Encoding.UTF8.GetBytes("\0alice\0correct horse battery staple"));
        var auth  = await client.CommandAsync("AUTH PLAIN " + plain);
        Assume.That(auth.Code, Is.EqualTo(235), Explain(client));

        var marker = Marker();
        var mail   = await client.CommandAsync("MAIL FROM:<alice@hermod.test> REQUIRETLS");
        var rcpt   = await client.CommandAsync("RCPT TO:<bob@elsewhere.example>");
        var (_, final) = await client.DataAsync(RawSmtpClientExtensions.Message("alice@hermod.test", "bob@elsewhere.example", marker, "x"));

        Assume.That(new[] { mail.Code, rcpt.Code, final?.Code ?? 0 }, Is.All.EqualTo(250), Explain(client));

        var queued = Server.Queue.Queued.SingleOrDefault(q => q.MessageContent.Contains(marker));

        Assert.That(queued,              Is.Not.Null, Explain(client));
        Assert.That(queued!.RequireTls,  Is.True, "the queued message must keep REQUIRETLS for the next hop");

    }

}
