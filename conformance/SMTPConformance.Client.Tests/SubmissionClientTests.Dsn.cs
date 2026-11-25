using System.Text.RegularExpressions;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// DSN (RFC 3461) as the submission client asks for it: ENVID on the wire as xtext (§4, §4.4),
/// RET and NOTIFY as the caller gave them (§4.1, §4.3), and none of them to a server that does
/// not offer DSN (§5.2.2).
/// </summary>
public sealed partial class SubmissionClientTests
{

    #region Setup

    private static EMailEnvelop WithDsn(DsnParameters Dsn)
        => new (EMail.Parse([
                    "From: app@client.example",
                    "To: you@scripted.test",
                    "Subject: delivery status notifications",
                    "Content-Type: text/plain; charset=utf-8",
                    "",
                    "A message that asks for delivery status notifications."
                ])) { Dsn = Dsn };

    private static async Task<(MailSentStatus Result, SmtpServerScript Script, ScriptedSmtpServer Server)> SendWithDsn(DsnParameters  Dsn,
                                                                                                                       Boolean        ServerOffersDsn = true)
    {

        var script = ServerOffersDsn
                         ? new SmtpServerScript()
                         : new SmtpServerScript { Extensions = [ "PIPELINING", "SIZE 10485760", "8BITMIME", "ENHANCEDSTATUSCODES", "SMTPUTF8" ] };

        var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        var result = await client.Send(WithDsn(Dsn), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        return (result, script, server);

    }

    private static String[] CommandLines(SmtpServerScript Script)
    {
        lock (Script.Commands)
            return [ .. Script.Commands.Select(command => command.Line) ];
    }

    private static String[] MailLines(SmtpServerScript Script)
        => [ .. CommandLines(Script).Where(line => line.StartsWith("MAIL ", StringComparison.OrdinalIgnoreCase)) ];

    private static String[] RcptLines(SmtpServerScript Script)
        => [ .. CommandLines(Script).Where(line => line.StartsWith("RCPT ", StringComparison.OrdinalIgnoreCase)) ];

    /// <summary>
    /// The value of a parameter on a MAIL or RCPT line, or null.
    /// </summary>
    private static String? Parameter(String Line, String Keyword)
        => Line[(Line.IndexOf('>') + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries)
               .Where (parameter => parameter.StartsWith(Keyword + "=", StringComparison.OrdinalIgnoreCase))
               .Select(parameter => parameter[(Keyword.Length + 1)..])
               .FirstOrDefault();

    // RFC 3461 §4: xtext = *( xchar / hexchar ); xchar is "!" to "~" but "+" and "="; hexchar
    // is "+" and two upper-case hex digits.
    [GeneratedRegex(@"^(?:[!-*,-<>-~]|\+[0-9A-F]{2})*$")]
    private static partial Regex XText();

    #endregion


    #region C-22: ENVID as xtext

    public static IEnumerable<TestCaseData> EnvelopeIds()
    {

        TestCaseData Case(String Name, String EnvId, String XText)
            => new TestCaseData(EnvId, XText).SetName($"ENVID goes as xtext: {Name}")
                                             .SetCategory(TestCategories.KnownIssue)
                                             .SetProperty("Finding", "C-22");

        yield return Case("a space",             "order 42",      "order+2042");
        yield return Case("an equals sign",      "batch=7",       "batch+3D7");
        yield return Case("a plus sign",         "QQ+314159",     "QQ+2B314159");

    }

    [TestCaseSource(nameof(EnvelopeIds))]
    [Description("RFC 3461 §4: \"the esmtp-values for these parameters are encoded as 'xtext'\"; §4.4: \"envid-parameter = 'ENVID=' xtext\", and \"the value of the ENVID parameter prior to encoding as 'xtext' MUST consist entirely of printable (graphic and white space) characters from the US-ASCII repertoire\" - a space, \"=\" and \"+\" are of them, and go as hexchars")]
    public async Task ENVID_goes_as_xtext(String EnvId, String XText)
    {

        var (_, script, server) = await SendWithDsn(new DsnParameters(DsnNotify.Failure, EnvId: EnvId));
        await using var _server = server;

        var mail = MailLines(script).SingleOrDefault();

        Assert.Multiple(() => {
            Assert.That(mail,                                 Does.Match(MailFromSyntax()), Explain(server));
            Assert.That(mail is null ? null : Parameter(mail, "ENVID"), Is.EqualTo(XText), Explain(server));
        });

    }


    [Test(Description = "RFC 3461 §4.4: the ENVID is of printable US-ASCII characters - CR and LF are none - and RFC 5321 §2.3.8: a command line ends with the first CR LF; an envelope identifier with a line break in it ends the MAIL command there, and what follows is a command of its own")]
    [Property("Finding", "C-22")]
    [Category(TestCategories.KnownIssue)]
    public async Task An_ENVID_with_a_line_break_is_no_command_of_its_own()
    {

        var (_, script, server) = await SendWithDsn(new DsnParameters(DsnNotify.Failure, EnvId: "x\r\nRCPT TO:<intruder@evil.test>"));
        await using var _server = server;

        Assert.Multiple(() => {
            Assert.That(RcptLines(script),  Has.None.Contains("intruder@evil.test"),   "no recipient of the ENVID's making" + Explain(server));
            Assert.That(MailLines(script),  Has.All.Match(MailFromSyntax()),            Explain(server));
        });

    }


    [Test(Description = "RFC 3461 §4.4: \"The ENVID parameter MAY be up to 100 characters in length\" - a longer one is refused by a server that checks (§5.1 (a)), so it does not go")]
    [Property("Finding", "C-22")]
    [Category(TestCategories.KnownIssue)]
    public async Task No_ENVID_goes_longer_than_100_characters()
    {

        var (_, script, server) = await SendWithDsn(new DsnParameters(DsnNotify.Failure, EnvId: new String('e', 101)));
        await using var _server = server;

        Assert.That(MailLines(script).Select(line => Parameter(line, "ENVID")).Where(envId => envId is not null),
                    Has.All.Length.LessThanOrEqualTo(100),
                    Explain(server));

    }


    [Test(Description = "RFC 3461 §4.4: an ENVID of xchars goes as it is - a guard")]
    [Property("Finding", "C-22")]
    public async Task An_ENVID_of_xchars_goes_as_it_is()
    {

        var (result, script, server) = await SendWithDsn(new DsnParameters(DsnNotify.Failure, EnvId: "QQ314159"));
        await using var _server = server;

        var mail = MailLines(script).SingleOrDefault();

        Assert.Multiple(() => {
            Assert.That(result,                                         Is.EqualTo(MailSentStatus.ok), Explain(server));
            Assert.That(mail is null ? null : Parameter(mail, "ENVID"), Is.EqualTo("QQ314159"),        Explain(server));
        });

    }

    #endregion

    #region C-23: RET without NOTIFY and ENVID

    [Test(Description = "RFC 3461 §4.3: \"The RET esmtp-keyword on the extended MAIL command specifies whether or not the message should be included in any failed DSN\"; §4.1: \"the absence of a NOTIFY parameter in a RCPT command may be interpreted as either NOTIFY=FAILURE or NOTIFY=FAILURE,DELAY\" - a failed DSN comes without NOTIFY too, and RET=HDRS keeps the body out of it")]
    [Property("Finding", "C-23")]
    [Category(TestCategories.KnownIssue)]
    public async Task RET_goes_without_NOTIFY_and_ENVID()
    {

        var (result, script, server) = await SendWithDsn(new DsnParameters(Ret: DsnRet.Hdrs));
        await using var _server = server;

        var mail = MailLines(script).SingleOrDefault();

        Assert.Multiple(() => {
            Assert.That(result,                                       Is.EqualTo(MailSentStatus.ok), Explain(server));
            Assert.That(mail is null ? null : Parameter(mail, "RET"), Is.EqualTo("HDRS"),            Explain(server));
        });

    }


    [Test(Description = "RFC 3461 §4.3: RET=HDRS with NOTIFY=FAILURE goes on MAIL - a guard")]
    [Property("Finding", "C-23")]
    public async Task RET_goes_with_NOTIFY()
    {

        var (_, script, server) = await SendWithDsn(new DsnParameters(DsnNotify.Failure, DsnRet.Hdrs));
        await using var _server = server;

        var mail = MailLines(script).SingleOrDefault();
        var rcpt = RcptLines(script).SingleOrDefault();

        Assert.Multiple(() => {
            Assert.That(mail is null ? null : Parameter(mail, "RET"),    Is.EqualTo("HDRS"),    Explain(server));
            Assert.That(rcpt is null ? null : Parameter(rcpt, "NOTIFY"), Is.EqualTo("FAILURE"), Explain(server));
            Assert.That(rcpt is null ? null : Parameter(rcpt, "ORCPT"),  Is.EqualTo("rfc822;you@scripted.test"), Explain(server));
        });

    }

    #endregion

    #region C-24: NOTIFY=NEVER

    [Test(Description = "RFC 3461 §4.1: \"A NOTIFY parameter value of 'NEVER' requests that a DSN not be returned to the sender under any conditions\" - and the absence of NOTIFY is NOTIFY=FAILURE: a caller who asks for no DSN at all and whose RCPT goes without NOTIFY gets the failed ones all the same")]
    [Property("Finding", "C-24")]
    [Category(TestCategories.KnownIssue)]
    public async Task NOTIFY_NEVER_goes_on_RCPT()
    {

        var (result, script, server) = await SendWithDsn(new DsnParameters(Notify: DsnNotify.Never));
        await using var _server = server;

        var rcpt = RcptLines(script).SingleOrDefault();

        Assert.Multiple(() => {
            Assert.That(result,                                          Is.EqualTo(MailSentStatus.ok), Explain(server));
            Assert.That(rcpt is null ? null : Parameter(rcpt, "NOTIFY"), Is.EqualTo("NEVER"),           Explain(server));
        });

    }


    [Test(Description = "RFC 3461 §4.1: a message that asks for nothing goes without NOTIFY, RET and ENVID - the server's default applies; a guard")]
    [Property("Finding", "C-24")]
    public async Task A_message_that_asks_for_no_DSN_goes_without_DSN_parameters()
    {

        var (result, script, server) = await SendWithDsn(DsnParameters.None);
        await using var _server = server;

        Assert.Multiple(() => {
            Assert.That(result,             Is.EqualTo(MailSentStatus.ok),                                  Explain(server));
            Assert.That(MailLines(script),  Has.None.Contains("RET=").And.None.Contains("ENVID="),          Explain(server));
            Assert.That(RcptLines(script),  Has.None.Contains("NOTIFY=").And.None.Contains("ORCPT="),       Explain(server));
        });

    }

    #endregion

    #region Guard: no DSN parameters to a server without DSN

    [Test(Description = "RFC 3461 §5.2.2 (a): \"ENVID, NOTIFY, RET, or ORCPT parameters MUST NOT be issued when relaying a message to an SMTP server that does not support this extension\"; RFC 5321 §4.1.1.11 - a guard")]
    public async Task No_DSN_parameters_go_to_a_server_without_DSN()
    {

        var (result, script, server) = await SendWithDsn(new DsnParameters(DsnNotify.Success | DsnNotify.Failure, DsnRet.Hdrs, "QQ314159"), ServerOffersDsn: false);
        await using var _server = server;

        Assert.Multiple(() => {
            Assert.That(result,             Is.EqualTo(MailSentStatus.ok),                                  Explain(server));
            Assert.That(MailLines(script),  Has.None.Contains("RET=").And.None.Contains("ENVID="),          Explain(server));
            Assert.That(RcptLines(script),  Has.None.Contains("NOTIFY=").And.None.Contains("ORCPT="),       Explain(server));
        });

    }

    #endregion

}
