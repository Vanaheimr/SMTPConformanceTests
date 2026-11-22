using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// RFC 5321 §4.5.3.2: how long the relay waits for the next hop, with the timeouts it has when
/// nobody configured any.
/// </summary>
public sealed partial class OutboundClientTests
{

    #region O-13: the timeouts of the relay

    [Test(Description = "RFC 5321 §4.5.3.2: \"the minimum per-command timeout values SHOULD be as follows\" - §4.5.3.2.6, DATA Termination: 10 minutes, \"A spurious timeout at this point would be very wasteful and would typically result in delivery of multiple copies of the message, since it has been successfully sent and the server has accepted responsibility for delivery\" - with the default configuration, a next hop that takes 61 seconds to deliver gets the message once, and the relay counts it delivered")]
    [Property("Finding", "O-13")]
    public async Task A_next_hop_that_takes_a_minute_for_the_end_of_data_is_waited_for()
    {

        var script = new SmtpServerScript { EndOfDataDelay = TimeSpan.FromSeconds(61) };
        await using var server = ScriptedSmtpServer.Start(script);

        // The defaults but for the way to the scripted next hop: no read or write timeout set.
        var config = new SmtpOutboundConfig {
                         LocalHostname               = "relay.hermod.test",
                         SmartHost                   = "127.0.0.1",
                         SmartHostPort               = org.GraphDefined.Vanaheimr.Hermod.IPPort.Parse(server.Port),
                         RemoteCertificateValidator  = (_, _, _, _) => true
                     };

        var sender = new MailSender(new CapturingMailQueue(), new CapturingLogger(),
                                    new SMTPOutboundClient(config, null, new StubDnsClient(), new CapturingLogger()));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(120));
        var result = (await sender.SendDirectAsync(Envelope([ "you@outbound.test" ]), cts.Token)).Single().Result;

        await server.WhenIdleAsync();

        Assert.Multiple(() => {
            Assert.That(result.Status,              Is.EqualTo(SendStatus.Success), $"{result.ResponseCode} {result.ResponseText}" + Explain(server));
            Assert.That(script.Transactions.Count,  Is.EqualTo(1),                  Explain(server));
        });

    }

    #endregion

}
