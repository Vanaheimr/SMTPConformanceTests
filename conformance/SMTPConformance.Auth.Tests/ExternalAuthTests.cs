using System.Security.Cryptography.X509Certificates;
using System.Text;

using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Auth.Tests;

/// <summary>
/// SASL EXTERNAL (RFC 4422 Appendix A) on Hermod's submission port: the client authenticates
/// with the certificate it presents in the TLS handshake (RFC 8446 §4.4.2, RFC 5246 §7.4.6),
/// which Hermod maps to an account by its thumbprint. The certificates are self-signed, made
/// by the test.
/// </summary>
[TestFixture]
public sealed class ExternalAuthTests : HermodServerTestBase
{

    protected override HermodSmtpServerFixtureOptions Options
        => new() { EnableTls = true };


    /// <summary>
    /// Submission port, EHLO, STARTTLS with the certificate, EHLO: the client, and the AUTH
    /// mechanisms then offered.
    /// </summary>
    private async Task<(RawSmtpClient Client, String[] Mechanisms)> SubmissionOverTlsWith(X509Certificate2? Certificate)
    {

        var (client, _) = await Server.ConnectSubmissionAsync();
        await client.EhloAsync();
        await client.StartTlsAsync(ClientCertificate: Certificate);
        var (_, extensions) = await client.EhloAsync();

        return (client, (extensions.GetValueOrDefault("AUTH") ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries));

    }


    [Test(Description = "RFC 4422 Appendix A: EXTERNAL authenticates the client \"by some external means\" - here the TLS client certificate, whose thumbprint is listed for carol; RFC 4954 §4: \"AUTH EXTERNAL =\", the empty initial response, asks for the identity the certificate stands for, and is 235. Hermod offers EXTERNAL once a client presented a certificate (SmtpAuthManager.GetAvailableMechanisms); the handshake has to ask for one first: in TLS the server requests the client's certificate (RFC 8446 §4.3.2 CertificateRequest, RFC 5246 §7.4.4), and a client sends one only when asked")]
    [Category(TestCategories.KnownIssue), Property("Finding", "S-27")]
    public async Task A_listed_client_certificate_authenticates_with_EXTERNAL()
    {

        using var certificate = TestCertificate.CreateClientCertificate("carol");
        Server.Users.Add("carol", "unused password", certificate.Thumbprint);

        var (client, mechanisms) = await SubmissionOverTlsWith(certificate);
        await using var _ = client;

        var reply = await client.CommandAsync("AUTH EXTERNAL =");

        Assert.Multiple(() => {
            Assert.That(mechanisms,  Does.Contain("EXTERNAL"),  Explain(client));
            Assert.That(reply.Code,  Is.EqualTo(235),           Explain(client));
        });

    }


    [Test(Description = "RFC 4422 Appendix A, RFC 5280: a certificate anybody can make - self-signed, CN=alice - that is listed for no account authenticates nobody - a guard for S-27")]
    [Property("Finding", "S-27")]
    public async Task An_unlisted_client_certificate_is_refused()
    {

        using var certificate = TestCertificate.CreateClientCertificate("alice");

        var (client, _) = await SubmissionOverTlsWith(certificate);
        await using var __ = client;

        var reply = await client.CommandAsync("AUTH EXTERNAL " + Convert.ToBase64String(Encoding.UTF8.GetBytes("alice")));

        Assert.That(reply.Code, Is.Not.EqualTo(235), Explain(client));

    }


    [Test(Description = "RFC 4422 Appendix A: without a client certificate there is nothing external to authenticate with - a guard for S-27")]
    [Property("Finding", "S-27")]
    public async Task EXTERNAL_without_a_client_certificate_is_refused()
    {

        var (client, mechanisms) = await SubmissionOverTlsWith(null);
        await using var _ = client;

        var reply = await client.CommandAsync("AUTH EXTERNAL =");

        Assert.Multiple(() => {
            Assert.That(mechanisms,  Does.Not.Contain("EXTERNAL"), Explain(client));
            Assert.That(reply.Code,  Is.Not.EqualTo(235),          Explain(client));
        });

    }

}
