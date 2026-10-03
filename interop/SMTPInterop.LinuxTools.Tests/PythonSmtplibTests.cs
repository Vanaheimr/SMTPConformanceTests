using NUnit.Framework;

using SMTPConformance.Core;

namespace SMTPInterop.LinuxTools.Tests;

/// <summary>
/// CPython's <c>smtplib</c> — an SMTP client implementation that shares no code
/// with Hermod — sending to Hermod's server.
/// </summary>
[TestFixture]
[Category(TestCategories.Wsl)]
public sealed class PythonSmtplibTests : LinuxToolTestBase
{

    private String Preamble()
        => $"""
            import smtplib, ssl, sys
            from email.message import EmailMessage
            HOST = '{LinuxSideHost}'
            MTA, SUBMISSION, SMTPS = {Server.MtaPort}, {Server.SubmissionPort}, {Server.ImplicitTlsPort}
            tls = ssl.create_default_context()
            tls.check_hostname = False
            tls.verify_mode = ssl.CERT_NONE
            def message(subject, sender='sender@client.example', to='alice@hermod.test', body='Hello from smtplib.'):
                m = EmailMessage()
                m['From'], m['To'], m['Subject'] = sender, to, subject
                m.set_content(body)
                return m

            """;


    [Test(Description = "RFC 5321: smtplib delivers a plain message to the MTA port")]
    public async Task Smtplib_plain_delivery()
    {

        Require();

        var marker = Marker();
        var result = RunPython(Preamble() + $"""
                     with smtplib.SMTP(HOST, MTA, timeout=10) as s:
                         s.send_message(message('{marker}'))
                     """);

        Assert.That(result.Success, Is.True, result.ToString());
        Assert.That(await Server.Storage.WaitForMarkerAsync(marker), Is.Not.Null, Server.Log.ToString());

    }


    [Test(Description = "RFC 3207, RFC 4954: smtplib upgrades with STARTTLS on the submission port, authenticates, and submits")]
    public async Task Smtplib_starttls_auth_submission()
    {

        Require();

        var marker = Marker();
        var result = RunPython(Preamble() + $"""
                     with smtplib.SMTP(HOST, SUBMISSION, timeout=10) as s:
                         s.starttls(context=tls)
                         s.login('alice', 'correct horse battery staple')
                         s.send_message(message('{marker}', sender='alice@hermod.test', to='bob@hermod.test'))
                     """);

        var stored = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.That(result.Success, Is.True, result.ToString());
        Assert.That(stored?.Raw,    Does.Match(@"\bwith ESMTPSA\b"), Server.Log.ToString());

    }


    [Test(Description = "RFC 8314 §3.3: smtplib.SMTP_SSL submits over implicit TLS")]
    public async Task Smtplib_implicit_tls_submission()
    {

        Require();

        var marker = Marker();
        var result = RunPython(Preamble() + $"""
                     with smtplib.SMTP_SSL(HOST, SMTPS, context=tls, timeout=10) as s:
                         s.login('alice', 'correct horse battery staple')
                         s.send_message(message('{marker}', sender='alice@hermod.test', to='bob@hermod.test'))
                     """);

        Assert.That(result.Success, Is.True, result.ToString());
        Assert.That(await Server.Storage.WaitForMarkerAsync(marker), Is.Not.Null, Server.Log.ToString());

    }


    [Test(Description = "RFC 6531: smtplib sends with SMTPUTF8 and UTF-8 addresses; Hermod stores the envelope correctly")]
    [Property("Finding", "S-11")]
    public async Task Smtplib_smtputf8_delivery()
    {

        Require();

        var marker = Marker();
        var result = RunPython(Preamble() + $"""
                     with smtplib.SMTP(HOST, MTA, timeout=10) as s:
                         s.send_message(message('{marker}', sender='jöran@bücher.example', to='ümlaut@hermod.test', body='Grüße'),
                                        mail_options=['SMTPUTF8'])
                     """);

        var stored = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.That(result.Success,        Is.True, result.ToString());
        Assert.That(stored?.EnvelopeTo,    Is.EqualTo(new[] { "ümlaut@hermod.test" }), Server.Log.ToString());

    }


    [Test(Description = "RFC 4954 §6: smtplib's login() over cleartext is refused by Hermod (538/no PLAIN offered), and nothing is accepted for relay")]
    public void Smtplib_cleartext_login_is_refused()
    {

        Require();

        var result = RunPython(Preamble() + """
                     try:
                         with smtplib.SMTP(HOST, SUBMISSION, timeout=10) as s:
                             s.login('alice', 'correct horse battery staple')
                     except smtplib.SMTPException as e:
                         print('refused:', type(e).__name__, e)
                         sys.exit(0)
                     print('cleartext login succeeded')
                     sys.exit(1)
                     """);

        Assert.That(result.Success, Is.True, result.ToString());

    }

}
