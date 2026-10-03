using NUnit.Framework;

using SMTPConformance.Core;

namespace SMTPInterop.LinuxTools.Tests;

/// <summary>
/// swaks, the Swiss Army Knife for SMTP — the tool postmasters reach for first,
/// with pipelining, STARTTLS, every common AUTH mechanism and deliberately
/// broken input built in.
/// </summary>
[TestFixture]
[Category(TestCategories.Wsl)]
public sealed class SwaksTests : LinuxToolTestBase
{

    private Wsl.Result Swaks(String Arguments)
        => Wsl.Run($"swaks --server {LinuxSideHost} --from sender@client.example --to alice@hermod.test --timeout 15 {Arguments} 2>&1",
                   TimeSpan.FromSeconds(45));


    [Test(Description = "RFC 5321: swaks delivers a message to the MTA port")]
    public async Task Swaks_plain_delivery()
    {

        Require("swaks");

        var marker = Marker();
        var result = Swaks($"--port {Server.MtaPort} --header 'Subject: {marker}'");

        Assert.That(result.Success, Is.True, result.ToString());
        Assert.That(await Server.Storage.WaitForMarkerAsync(marker), Is.Not.Null, result.ToString());

    }


    [Test(Description = "RFC 2920: swaks --pipeline sends the envelope as one group and Hermod answers it in order")]
    public async Task Swaks_pipelined_delivery()
    {

        Require("swaks");

        var marker = Marker();
        var result = Swaks($"--port {Server.MtaPort} --pipeline --header 'Subject: {marker}'");

        Assert.That(result.Success, Is.True, result.ToString());
        Assert.That(await Server.Storage.WaitForMarkerAsync(marker), Is.Not.Null, result.ToString());

    }


    [Test(Description = "RFC 3207, RFC 4954: swaks STARTTLS + AUTH PLAIN on the submission port")]
    public async Task Swaks_starttls_auth_plain()
    {

        Require("swaks");

        var marker = Marker();
        var result = Swaks($"--port {Server.SubmissionPort} --tls --auth PLAIN --auth-user alice --auth-password 'correct horse battery staple' " +
                           $"--from alice@hermod.test --header 'Subject: {marker}'");

        Assert.That(result.Success, Is.True, result.ToString());
        Assert.That(await Server.Storage.WaitForMarkerAsync(marker), Is.Not.Null, result.ToString());

    }


    [Test(Description = "RFC 3207: swaks --tls-on-connect (implicit TLS) with AUTH LOGIN on the SMTPS port")]
    public async Task Swaks_implicit_tls_auth_login()
    {

        Require("swaks");

        var marker = Marker();
        var result = Swaks($"--port {Server.ImplicitTlsPort} --tls-on-connect --auth LOGIN --auth-user alice --auth-password 'correct horse battery staple' " +
                           $"--from alice@hermod.test --header 'Subject: {marker}'");

        Assert.That(result.Success, Is.True, result.ToString());
        Assert.That(await Server.Storage.WaitForMarkerAsync(marker), Is.Not.Null, result.ToString());

    }

}
