using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;

using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Tls.Tests;

/// <summary>
/// RFC 8446 §4.4.2 and RFC 5246 §7.4.2: the certificate the server presents comes with the
/// intermediates a client needs to reach a root it trusts - from a PEM file as certbot writes
/// it - and a certificate renewed while the server runs is presented from the next handshake.
/// </summary>
[TestFixture]
public sealed class CertificateChainTests
{

    /// <summary>
    /// Write a certificate issued by an intermediate as certbot does: fullchain.pem (the
    /// certificate, then the intermediate) and privkey.pem.
    /// </summary>
    private static (X509Certificate2 Authority, X509Certificate2 Server) WritePem(String Directory, String ServerName = "mx.hermod.test")
    {

        var (authority, server) = TestCertificate.CreateIssuedCertificate(ServerName);

        File.WriteAllText(Path.Combine(Directory, "fullchain.pem"), server.ExportCertificatePem() + "\n" + authority.ExportCertificatePem() + "\n");
        File.WriteAllText(Path.Combine(Directory, "privkey.pem"),   server.GetRSAPrivateKey()!.ExportPkcs8PrivateKeyPem() + "\n");

        return (authority, server);

    }

    private static async Task<IReadOnlyList<X509Certificate2>> PresentedOverStartTls(HermodSmtpServerFixture Server)
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var _ = client;

        await client.EhloAsync();
        await client.StartTlsAsync("mx.hermod.test");

        return client.PeerCertificates;

    }


    [Test(Description = "RFC 8446 §4.4.2: \"The sender's certificate MUST come in the first CertificateEntry in the list\", the intermediates after it - read from a fullchain.pem, all of them are sent")]
    public async Task The_intermediates_of_a_PEM_certificate_are_sent_with_it()
    {

        var directory = Directory.CreateTempSubdirectory("smtp-conformance-pem-").FullName;

        try
        {

            var (authority, certificate) = WritePem(directory);

            await using var server = await HermodSmtpServerFixture.StartAsync(new() {
                                               PemCertificate = (Path.Combine(directory, "fullchain.pem"), Path.Combine(directory, "privkey.pem"))
                                           });

            var presented = await PresentedOverStartTls(server);

            Assert.Multiple(() => {
                Assert.That(presented.FirstOrDefault()?.Thumbprint,           Is.EqualTo(certificate.Thumbprint),  "the server's own certificate first");
                Assert.That(presented.Select(presented => presented.Thumbprint), Does.Contain(authority.Thumbprint), "and the intermediate that issued it");
            });

        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch { }
        }

    }


    [Test(Description = "A certificate renewed on disk while the server runs - as certbot renews every 60 days - is presented from the next handshake on, without a restart")]
    public async Task A_renewed_certificate_is_presented_without_a_restart()
    {

        var directory = Directory.CreateTempSubdirectory("smtp-conformance-pem-").FullName;

        try
        {

            var (_, first) = WritePem(directory);
            var file       = new ServerCertificateFile(Path.Combine(directory, "fullchain.pem"), Path.Combine(directory, "privkey.pem"), CheckInterval: TimeSpan.Zero);

            await using var server = await HermodSmtpServerFixture.StartAsync(new() { CertificateSelector = file.Selector });

            var before      = await PresentedOverStartTls(server);
            var (_, second) = WritePem(directory);
            var after       = await PresentedOverStartTls(server);

            Assert.Multiple(() => {
                Assert.That(before.FirstOrDefault()?.Thumbprint, Is.EqualTo(first. Thumbprint), "before the renewal");
                Assert.That(after. FirstOrDefault()?.Thumbprint, Is.EqualTo(second.Thumbprint), "after it" + (file.LastError is null ? "" : ": " + file.LastError));
            });

        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch { }
        }

    }

}
