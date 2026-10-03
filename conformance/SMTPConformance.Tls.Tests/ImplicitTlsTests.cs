using NUnit.Framework;

using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Tls.Tests;

/// <summary>
/// RFC 8314 §3.3: Message submission with implicit TLS.
/// </summary>
[TestFixture]
public sealed class ImplicitTlsTests : HermodServerTestBase
{

    protected override HermodSmtpServerFixtureOptions Options
        => new() { EnableTls = true };


    [Test(Description = "RFC 8314 §3.3: on the implicit-TLS port the TLS handshake comes first, then the 220 greeting inside TLS")]
    public async Task Greeting_arrives_inside_tls()
    {

        var (client, greeting) = await Server.ConnectImplicitTlsAsync();
        await using var _ = client;

        Assert.Multiple(() => {
            Assert.That(client.IsTls,         Is.True);
            Assert.That(greeting.Code,        Is.EqualTo(220), Explain(client));
            Assert.That(greeting.Violations,  Is.Empty,        Explain(client));
        });

    }


    [Test(Description = "RFC 3207 §4.2, RFC 8314 §3.3: STARTTLS is not offered on a connection that is already TLS")]
    public async Task Starttls_is_not_offered_on_implicit_tls()
    {

        var (client, _) = await Server.ConnectImplicitTlsAsync();
        await using var __ = client;

        var (_, extensions) = await client.EhloAsync();

        Assert.That(extensions.Keys, Does.Not.Contain("STARTTLS"), Explain(client));

    }


    [Test(Description = "RFC 8314 §3.3, RFC 4954 §4: password mechanisms are offered once the connection is TLS")]
    public async Task Auth_plain_is_offered_on_implicit_tls()
    {

        var (client, _) = await Server.ConnectImplicitTlsAsync();
        await using var __ = client;

        var (_, extensions) = await client.EhloAsync();

        Assert.That((extensions.GetValueOrDefault("AUTH") ?? "").Split(' '), Does.Contain("PLAIN"), Explain(client));

    }


    [Test(Description = "RFC 8314 §3.3: a plaintext client on the implicit-TLS port gets no SMTP greeting in the clear")]
    public async Task A_plaintext_client_gets_no_cleartext_greeting()
    {

        await using var client = await RawSmtpClient.ConnectAsync(Server.Host, Server.ImplicitTlsPort);

        var greeting = await client.TryReadReplyAsync(TimeSpan.FromSeconds(2));

        Assert.That(greeting, Is.Null, Explain(client));

    }

}
