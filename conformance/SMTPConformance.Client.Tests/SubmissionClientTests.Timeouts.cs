using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;
using org.GraphDefined.Vanaheimr.Hermod.TLS;

using SMTPConformance.Core;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// RFC 5321 §4.5.3.2: how long the submission client waits for the server, with the timeouts
/// it has when nobody configured any.
/// </summary>
public sealed partial class SubmissionClientTests
{

    #region C-14: the timeouts of the submission client

    [Test(Description = "RFC 5321 §4.5.3.2: \"the minimum per-command timeout values SHOULD be as follows\" - §4.5.3.2.6, DATA Termination: 10 minutes, \"A spurious timeout at this point would ... typically result in delivery of multiple copies of the message\" - with the default command timeout, a server that takes 31 seconds to deliver gets the message once, and the client counts it sent")]
    [Category(TestCategories.KnownIssue), Property("Finding", "C-14")]
    public async Task A_server_that_takes_half_a_minute_for_the_end_of_data_is_waited_for()
    {

        var script = new SmtpServerScript { EndOfDataDelay = TimeSpan.FromSeconds(31) };
        await using var server = ScriptedSmtpServer.Start(script);

        // The defaults but for the server to reach: no command timeout set.
        using var client = new SMTPSubmissionClient(DomainName.Parse("127.0.0.1"),
                                                    IPPort.Parse(server.Port),
                                                    LocalDomain:                 "client.example",
                                                    UseTLS:                      TLSUsage.NoTLS,
                                                    RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Success(),
                                                    ConnectionTimeout:           TimeSpan.FromSeconds(3));

        var result = await client.Send(Message("hello"), NumberOfRetries: 1);
        await server.WhenIdleAsync();

        Assert.Multiple(() => {
            Assert.That(result,                     Is.EqualTo(MailSentStatus.ok), Explain(server));
            Assert.That(script.Transactions.Count,  Is.EqualTo(1),                 "one message, one transaction" + Explain(server));
        });

    }

    #endregion

}
