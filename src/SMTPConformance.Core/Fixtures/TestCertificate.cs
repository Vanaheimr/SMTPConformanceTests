using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SMTPConformance.Core.Fixtures;

/// <summary>
/// Self-signed certificates for STARTTLS and implicit-TLS test listeners.
/// </summary>
public static class TestCertificate
{

    /// <summary>
    /// The password every PFX this class writes is protected with. It protects
    /// nothing — the key is thrown away with the test run — but Hermod's
    /// <c>SMTPServer</c> only loads a PKCS#12 file through the password overload.
    /// </summary>
    public const String PfxPassword = "smtp-conformance";


    /// <summary>
    /// RSA-2048 server certificate with SANs for the given name, localhost and
    /// 127.0.0.1, valid for 7 days, exportable private key.
    /// </summary>
    public static X509Certificate2 CreateServerCertificate(String CommonName = "localhost")
    {

        using var rsa = RSA.Create(2048);

        var request = new CertificateRequest(
                          $"CN={CommonName}",
                          rsa,
                          HashAlgorithmName.SHA256,
                          RSASignaturePadding.Pkcs1
                      );

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false)
        );

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                false
            )
        );

        // id-kp-serverAuth
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([ new Oid("1.3.6.1.5.5.7.3.1") ], false)
        );

        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName(CommonName);
        if (CommonName != "localhost")
            sanBuilder.AddDnsName("localhost");
        sanBuilder.AddIpAddress(System.Net.IPAddress.Loopback);
        request.CertificateExtensions.Add(sanBuilder.Build());

        var certificate = request.CreateSelfSigned(
                              DateTimeOffset.UtcNow.AddMinutes(-5),
                              DateTimeOffset.UtcNow.AddDays(7)
                          );

        return X509CertificateLoader.LoadPkcs12(
                   certificate.Export(X509ContentType.Pfx),
                   null,
                   X509KeyStorageFlags.Exportable
               );

    }


    /// <summary>
    /// A certification authority, and a server certificate it issued for the given name only -
    /// for DANE-TA(2), where the authority is the trust anchor (RFC 7672 §3.1.2).
    /// </summary>
    public static (X509Certificate2 Authority, X509Certificate2 Server) CreateIssuedCertificate(String ServerName)
    {

        using var authorityKey = RSA.Create(2048);
        var authorityRequest   = new CertificateRequest("CN=Conformance test authority", authorityKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        authorityRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        authorityRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var authority    = authorityRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(8));

        using var serverKey    = RSA.Create(2048);
        var serverRequest      = new CertificateRequest($"CN={ServerName}", serverKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        serverRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([ new Oid("1.3.6.1.5.5.7.3.1") ], false));
        var names              = new SubjectAlternativeNameBuilder();
        names.AddDnsName(ServerName);
        serverRequest.CertificateExtensions.Add(names.Build());
        using var issued       = serverRequest.Create(authority, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(7), RandomNumberGenerator.GetBytes(8));
        using var server       = issued.CopyWithPrivateKey(serverKey);

        return (X509CertificateLoader.LoadCertificate(authority.RawData),
                X509CertificateLoader.LoadPkcs12(server.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.Exportable));

    }


    /// <summary>
    /// Write a fresh server certificate to a PFX file in <paramref name="Directory"/>,
    /// protected with <see cref="PfxPassword"/>.
    /// </summary>
    /// <returns>The path, and the certificate itself for assertions on what a client was shown.</returns>
    public static (String Path, X509Certificate2 Certificate) WritePfx(String Directory, String CommonName = "localhost")
    {

        var certificate = CreateServerCertificate(CommonName);
        var path        = System.IO.Path.Combine(Directory, "server.pfx");

        File.WriteAllBytes(path, certificate.Export(X509ContentType.Pfx, PfxPassword));

        return (path, certificate);

    }

}
