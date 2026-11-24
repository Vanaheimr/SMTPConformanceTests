using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;
using org.GraphDefined.Vanaheimr.Hermod.TLS;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// REQUIRETLS (RFC 8689 §4.3) as the submission client gives it: a message that is to travel
/// on TLS only goes to a server that keeps it so - inside TLS, with REQUIRETLS on MAIL.
/// </summary>
public sealed partial class SubmissionClientTests
{

    #region C-19: a message that requires TLS, and a server without REQUIRETLS

    private static EMailEnvelop RequiringTls()

        => new (EMail.Parse([
                    "From: app@client.example",
                    "To: you@scripted.test",
                    "Subject: for TLS only",
                    "Content-Type: text/plain; charset=utf-8",
                    "",
                    "This message requires TLS on every hop."
                ])) { RequireTls = true };


    [Test(Description = "RFC 8689 §4.3: \"If TLS is to be required, it MUST do so by negotiating STARTTLS and REQUIRETLS and including the REQUIRETLS option on the MAIL FROM command\"; §2: \"Following the negotiation of STARTTLS, the SMTP server MUST advertise in the subsequent EHLO response that it supports REQUIRETLS\" - a server that does not is no path for the message, not one to give it to without the option")]
    [Property("Finding", "C-19")]
    public async Task A_REQUIRETLS_message_goes_to_no_server_that_does_not_offer_REQUIRETLS()
    {

        var script = new SmtpServerScript { Certificate = TestCertificate.CreateServerCertificate() };
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server, TLSUsage.STARTTLS);

        var result = await client.Send(RequiringTls(), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        Assert.Multiple(() => {
            Assert.That(script.Transactions, Is.Empty,                         "no MAIL for a message the server would not keep on TLS" + Explain(server));
            Assert.That(result,              Is.Not.EqualTo(MailSentStatus.ok), Explain(server));
        });

    }


    [Test(Description = "RFC 8689 §4.3: inside TLS, to a server that offers REQUIRETLS, the message goes with REQUIRETLS on MAIL - a guard")]
    [Property("Finding", "C-19")]
    public async Task A_REQUIRETLS_message_goes_with_REQUIRETLS_on_MAIL()
    {

        var script = new SmtpServerScript {
                         Certificate  = TestCertificate.CreateServerCertificate(),
                         Extensions   = [ "PIPELINING", "SIZE 10485760", "8BITMIME", "ENHANCEDSTATUSCODES", "SMTPUTF8", "DSN", "REQUIRETLS" ]
                     };
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server, TLSUsage.STARTTLS);

        var result      = await client.Send(RequiringTls(), NumberOfRetries: 0);
        await server.WhenIdleAsync();
        var transaction = script.Transactions.SingleOrDefault();

        Assert.Multiple(() => {
            Assert.That(result,                     Is.EqualTo(MailSentStatus.ok), Explain(server));
            Assert.That(transaction?.Tls,           Is.True,                       Explain(server));
            Assert.That(transaction?.MailFromLine,  Does.EndWith(" REQUIRETLS"),   Explain(server));
        });

    }

    #endregion

}
