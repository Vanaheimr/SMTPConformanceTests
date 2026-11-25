using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// DSN (RFC 3461) as the relay asks for it when an application hands it a message
/// (MailSender.SendDirectAsync): the same DsnParameters as the submission client's, so the
/// same rules - ENVID as xtext (§4, §4.4), RET and NOTIFY as the caller gave them (§4.1, §4.3).
/// </summary>
public sealed partial class OutboundClientTests
{

    #region Setup

    private static async Task<(SmtpServerScript Script, ScriptedSmtpServer Server)> SendDirectWithDsn(DsnParameters Dsn)
    {

        var script = new SmtpServerScript();
        var server = ScriptedSmtpServer.Start(script);

        await SendDirect(server, Envelope([ "you@outbound.test" ], Dsn: Dsn));

        return (script, server);

    }

    private static String[] CommandLines(SmtpServerScript Script)
    {
        lock (Script.Commands)
            return [ .. Script.Commands.Select(command => command.Line) ];
    }

    private static String? DsnParameter(SmtpServerScript Script, String Command, String Keyword)
        => CommandLines(Script).Where (line => line.StartsWith(Command + " ", StringComparison.OrdinalIgnoreCase))
                               .Select(line => line[(line.IndexOf('>') + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries)
                                                   .Where (parameter => parameter.StartsWith(Keyword + "=", StringComparison.OrdinalIgnoreCase))
                                                   .Select(parameter => parameter[(Keyword.Length + 1)..])
                                                   .FirstOrDefault())
                               .FirstOrDefault();

    #endregion


    #region C-22: ENVID as xtext

    [Test(Description = "RFC 3461 §4.4: \"envid-parameter = 'ENVID=' xtext\"; \"the value of the ENVID parameter prior to encoding as 'xtext' MUST consist entirely of printable (graphic and white space) characters from the US-ASCII repertoire\" - a space goes as \"+20\"")]
    [Property("Finding", "C-22")]
    public async Task The_relay_gives_ENVID_as_xtext()
    {

        var (script, server) = await SendDirectWithDsn(new DsnParameters(DsnNotify.Failure, EnvId: "order 42"));
        await using var _server = server;

        Assert.That(DsnParameter(script, "MAIL", "ENVID"), Is.EqualTo("order+2042"), Explain(server));

    }


    [Test(Description = "RFC 3461 §4.4: the ENVID is of printable US-ASCII characters - CR and LF are none - and RFC 5321 §2.3.8: a command line ends with the first CR LF; an envelope identifier with a line break in it is no command of its own")]
    [Property("Finding", "C-22")]
    public async Task An_ENVID_with_a_line_break_is_no_command_of_the_relay()
    {

        var (script, server) = await SendDirectWithDsn(new DsnParameters(DsnNotify.Failure, EnvId: "x\r\nRCPT TO:<intruder@evil.test>"));
        await using var _server = server;

        Assert.That(CommandLines(script), Has.None.Contains("intruder@evil.test"), "no recipient of the ENVID's making" + Explain(server));

    }

    #endregion

    #region C-23: RET without NOTIFY and ENVID

    [Test(Description = "RFC 3461 §4.3: \"The RET esmtp-keyword on the extended MAIL command specifies whether or not the message should be included in any failed DSN\" - and a failed DSN comes without NOTIFY too (§4.1)")]
    [Property("Finding", "C-23")]
    public async Task The_relay_gives_RET_without_NOTIFY_and_ENVID()
    {

        var (script, server) = await SendDirectWithDsn(new DsnParameters(Ret: DsnRet.Hdrs));
        await using var _server = server;

        Assert.That(DsnParameter(script, "MAIL", "RET"), Is.EqualTo("HDRS"), Explain(server));

    }

    #endregion

    #region C-24: NOTIFY=NEVER

    [Test(Description = "RFC 3461 §4.1: \"A NOTIFY parameter value of 'NEVER' requests that a DSN not be returned to the sender under any conditions\" - without it the next hop sends the failed ones")]
    [Property("Finding", "C-24")]
    public async Task The_relay_gives_NOTIFY_NEVER()
    {

        var (script, server) = await SendDirectWithDsn(new DsnParameters(Notify: DsnNotify.Never));
        await using var _server = server;

        Assert.That(DsnParameter(script, "RCPT", "NOTIFY"), Is.EqualTo("NEVER"), Explain(server));

    }

    #endregion

}
