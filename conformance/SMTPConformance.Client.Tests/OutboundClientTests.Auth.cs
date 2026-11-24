using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

public sealed partial class OutboundClientTests
{

    #region O-19: AUTH=<> to a smart host the relay signed in to

    /// <summary>
    /// The relay's client for the scripted next hop as its smart host, on the loopback, signing in
    /// with PLAIN in cleartext - nothing crosses a network.
    /// </summary>
    private static SMTPOutboundClient SignedInClientFor(ScriptedSmtpServer NextHop)

        => new (ConfigFor(NextHop) with {
                    SmartHostUsername        = "relay-user",
                    SmartHostPassword        = "relay-secret",
                    SmartHostAuthWithoutTls  = true
                },
                null, new StubDnsClient(), new CapturingLogger());

    private static String MailFromOf(SmtpServerScript Script)
    {
        lock (Script.Transactions)
            return Script.Transactions.Single().MailFromLine ?? "";
    }


    public static IEnumerable<TestCaseData> RelayedForOthers()
    {

        TestCaseData Case(String Name, String MailFrom)
            => new TestCaseData(MailFrom).SetName($"Relayed through a smart host signed in to: {Name}")
                                         .SetProperty("Finding", "O-19");

        yield return Case("from a client that did not authenticate",    "MAIL FROM:<app@client.example>");
        yield return Case("with AUTH=<> from the client",               "MAIL FROM:<app@client.example> AUTH=<>");

    }


    [TestCaseSource(nameof(RelayedForOthers))]
    [Description("RFC 4954 §5: \"if the client is not authenticated, then the server MUST behave as if the AUTH=<> parameter was supplied\", and \"If an AUTH=<> parameter was supplied, either explicitly or due to the requirement in the previous paragraph, then the server MUST supply the AUTH=<> parameter when relaying the message to any server which it has authenticated to using the AUTH extension\" - else the smart host takes the message for one its account submitted")]
    public async Task A_message_relayed_through_a_smart_host_signed_in_to_carries_AUTH_empty(String MailFrom)
    {

        var script = new SmtpServerScript { AuthMechanisms = [ "PLAIN" ], AuthBeforeTls = true };
        await using var nextHop = ScriptedSmtpServer.Start(script);

        var run = await RelayThroughHermod(nextHop, MailFrom, [ "RCPT TO:<you@outbound.test>" ], Client: SignedInClientFor(nextHop));

        Assume.That(AuthCommands(script), Is.Not.Empty, "the relay signed in" + Explain(nextHop));

        Assert.That(MailFromOf(script).Split(' ').Skip(2), Does.Contain("AUTH=<>"),
                    $"{run.Received}{Explain(nextHop)}");

    }


    [Test(Description = "RFC 4954 §5, RFC 5321 §4.1.1.2: a next hop that offers no AUTH gets no AUTH parameter - a guard for O-19")]
    [Property("Finding", "O-19")]
    public async Task A_next_hop_without_AUTH_gets_no_AUTH_parameter()
    {

        var script = new SmtpServerScript();
        await using var nextHop = ScriptedSmtpServer.Start(script);

        var run = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example> AUTH=<>", [ "RCPT TO:<you@outbound.test>" ]);

        Assert.That(MailFromOf(script), Does.Not.Contain("AUTH="), $"{run.Received}{Explain(nextHop)}");

    }

    #endregion


    #region O-20: no initial response beyond the line length

    [Test(Description = "RFC 4954 §4: \"Note that the AUTH command is still subject to the line length limitations defined in [SMTP]. If use of the initial response argument would cause the AUTH command to exceed this length, the client MUST NOT use the initial response parameter (and instead proceed as defined in Section 5.1 of [SASL])\" - RFC 5321 §4.5.3.1.4: 512 octets with CR LF; a password of 400 octets goes after the 334")]
    [Property("Finding", "O-20")]
    public async Task A_long_password_goes_to_the_smart_host_without_an_initial_response()
    {

        var password = new String('p', 400);

        var script = new SmtpServerScript { Certificate = TestCertificate.CreateServerCertificate("relay.test"), AuthMechanisms = [ "PLAIN" ] };
        await using var server = ScriptedSmtpServer.Start(script);

        var result = await SendWithCredentials(server, Validator: OwnCaNameChecked, Password: password);

        var lines  = Commands(script);
        var auth   = lines.FindIndex(line => line.StartsWith("AUTH", StringComparison.OrdinalIgnoreCase));

        Assume.That(auth, Is.Not.Negative, "the relay signed in" + Explain(server));

        Assert.Multiple(() => {
            Assert.That(Encoding.UTF8.GetByteCount(lines[auth]) + 2, Is.LessThanOrEqualTo(512), "the AUTH command fits a command line - the response after the 334 need not (RFC 4954 §4)" + Explain(server));
            Assert.That(lines[auth],     Is.EqualTo("AUTH PLAIN").IgnoreCase,                                          Explain(server));
            Assert.That(Unb64(lines.ElementAtOrDefault(auth + 1)), Is.EqualTo("\0relay-user\0" + password),            Explain(server));
            Assert.That(result.Status,   Is.EqualTo(SendStatus.Success),                                               result.ResponseText);
        });

    }

    private static List<String> Commands(SmtpServerScript Script)
    {
        lock (Script.Commands)
            return [ .. Script.Commands.Select(command => command.Line) ];
    }

    private static String? Unb64(String? Line)
    {
        try
        {
            return Line is null ? null : Encoding.UTF8.GetString(Convert.FromBase64String(Line));
        }
        catch (FormatException)
        {
            return null;
        }
    }

    #endregion

}
