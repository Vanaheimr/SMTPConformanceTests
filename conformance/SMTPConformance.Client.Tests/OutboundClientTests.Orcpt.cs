using System.Text.RegularExpressions;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// The ORCPT the relay writes itself (RFC 3461 §4.2, §5.2.1 (d)): orcpt-parameter = "ORCPT="
/// original-recipient-address, original-recipient-address = addr-type ";" xtext - the address
/// xtext-encoded, as any value of the parameter.
/// </summary>
public sealed partial class OutboundClientTests
{

    #region O-14: the ORCPT of the relay is xtext

    // RFC 3461 §4: xtext = *( xchar / hexchar ), xchar = "!" to "~" except "+" and "=",
    // hexchar = "+" 2(%x30-39 / %x41-46); §4.2: addr-type = atom.
    [GeneratedRegex(@"\bORCPT=(?<value>\S*)", RegexOptions.IgnoreCase)]
    private static partial Regex OrcptParameter();

    [GeneratedRegex(@"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+;(?:[!-*,-<>-~]|\+[0-9A-F]{2})+$")]
    private static partial Regex OrcptValue();

    private static IEnumerable<String> OrcptValues(SmtpServerScript Script)
        => Script.Transactions.SelectMany(transaction => transaction.RcptToLines).
                               Select    (line        => OrcptParameter().Match(line)).
                               Where     (match       => match.Success).
                               Select    (match       => match.Groups["value"].Value);


    public static IEnumerable<TestCaseData> AddressesThatNeedXtext()
    {

        TestCaseData Case(String Address, String Why)
            => new TestCaseData(Address).SetName($"The ORCPT the relay writes for {Address} is xtext - {Why}")
                                        .SetProperty("Finding", "O-14");

        yield return Case("user+tag@outbound.test", "a \"+\" is \"+2B\"");
        yield return Case("a=b@outbound.test",      "an \"=\" is \"+3D\"");

    }

    [TestCaseSource(nameof(AddressesThatNeedXtext))]
    [Description("RFC 3461 §5.2.1 (d): a relay to a DSN server \"MAY\" supply an ORCPT when none was given, and §4.2: original-recipient-address = addr-type \";\" xtext; §4: \"+\" and \"=\" are not xchars - written as they are, the parameter is not one, and a next hop that checks it refuses the recipient (501)")]
    public async Task The_ORCPT_the_relay_writes_is_xtext(String Address)
    {

        var script = new SmtpServerScript();
        await using var nextHop = ScriptedSmtpServer.Start(script);

        var run = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example>", [ $"RCPT TO:<{Address}> NOTIFY=FAILURE" ]);

        var values = OrcptValues(script).ToArray();

        Assert.Multiple(() => {
            Assert.That(values, Is.Not.Empty,               "an ORCPT was supplied" + run.Explain(nextHop));
            Assert.That(values, Has.All.Matches(OrcptValue()), run.Explain(nextHop));
        });

    }


    [Test(Description = "RFC 3461 §4.2: the ORCPT of a message of Hermod's own, sent with a DSN request to a recipient whose address has a \"+\" - xtext as well")]
    [Property("Finding", "O-14")]
    public async Task The_ORCPT_of_an_own_message_is_xtext()
    {

        var script = new SmtpServerScript();
        await using var server = ScriptedSmtpServer.Start(script);

        var result = await SendDirect(server, Envelope([ "user+tag@outbound.test" ], Dsn: new DsnParameters(DsnNotify.Failure, null, null)));

        var values = OrcptValues(script).ToArray();

        Assert.Multiple(() => {
            Assert.That(result.Status, Is.EqualTo(SendStatus.Success),  Explain(server));
            Assert.That(values,        Is.Not.Empty,                    "an ORCPT was supplied" + Explain(server));
            Assert.That(values,        Has.All.Matches(OrcptValue()),   Explain(server));
        });

    }


    [Test(Description = "RFC 3461 §5.2.1 (d): \"If an ORCPT parameter was present in the RCPT command when the message was received, an ORCPT parameter with the same value MUST be specified when the message is relayed\" - the client's xtext goes on as it came")]
    public async Task A_received_ORCPT_is_relayed_as_it_came()
    {

        var script = new SmtpServerScript();
        await using var nextHop = ScriptedSmtpServer.Start(script);

        var run = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example>", [ "RCPT TO:<user+tag@outbound.test> ORCPT=rfc822;team+2Bsales@client.example" ]);

        Assert.That(OrcptValues(script), Is.EqualTo(new[] { "rfc822;team+2Bsales@client.example" }), run.Explain(nextHop));

    }

    #endregion

}
