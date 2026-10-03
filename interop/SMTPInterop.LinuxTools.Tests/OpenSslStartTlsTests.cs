using NUnit.Framework;

using SMTPConformance.Core;

namespace SMTPInterop.LinuxTools.Tests;

/// <summary>
/// OpenSSL's <c>s_client -starttls smtp</c> — the reference STARTTLS client
/// most TLS scanners (testssl.sh, sslyze, the MTA-STS checkers) build on.
/// </summary>
[TestFixture]
[Category(TestCategories.Wsl)]
public sealed class OpenSslStartTlsTests : LinuxToolTestBase
{

    // stdin is held open for a second before QUIT: s_client hangs up the moment
    // stdin ends, which on the implicit-TLS port is before the greeting arrives.
    private Wsl.Result SClient(UInt16 Port, String Arguments)
        => Wsl.Run($"(sleep 1; printf 'QUIT\\r\\n') | timeout 15 openssl s_client -connect {LinuxSideHost}:{Port} {Arguments} -brief 2>&1",
                   TimeSpan.FromSeconds(30));


    [Test(Description = "RFC 3207: openssl s_client completes STARTTLS on the MTA port with TLS 1.3")]
    public void Starttls_with_tls13()
    {

        Require("openssl");

        var result = SClient(Server.MtaPort, "-starttls smtp -tls1_3");

        Assert.That(result.StdOut, Does.Contain("Protocol version: TLSv1.3"), result.ToString());

    }


    [Test(Description = "RFC 3207, RFC 8996: openssl s_client completes STARTTLS with TLS 1.2")]
    public void Starttls_with_tls12()
    {

        Require("openssl");

        var result = SClient(Server.MtaPort, "-starttls smtp -tls1_2");

        Assert.That(result.StdOut, Does.Contain("Protocol version: TLSv1.2"), result.ToString());

    }


    [Test(Description = "RFC 8996: TLS 1.1 is refused")]
    public void Tls11_is_refused()
    {

        Require("openssl");

        var result = SClient(Server.MtaPort, "-starttls smtp -tls1_1");

        Assert.That(result.StdOut, Does.Not.Contain("Protocol version: TLSv1.1"), result.ToString());

    }


    [Test(Description = "RFC 8314 §3.3: openssl s_client completes an implicit-TLS handshake on the SMTPS port and sees the 220 greeting")]
    public void Implicit_tls_handshake()
    {

        Require("openssl");

        var result = SClient(Server.ImplicitTlsPort, "");

        Assert.That(result.StdOut, Does.Contain("Protocol version: TLSv1.").And.Contain("220 "), result.ToString());

    }

}
