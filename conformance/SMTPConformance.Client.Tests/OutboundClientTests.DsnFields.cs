using System.Text.RegularExpressions;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// What the relay's reports say of the next hop: the Diagnostic-Code it answered with, and the
/// Remote-MTA that answered. RFC 3461 §6.3 (h), (i): "For DSNs resulting from attempts to relay
/// a message to one or more recipients via SMTP, the Remote-MTA field MUST be supplied", "the
/// Diagnostic-Code MUST be supplied" - and §9.2, §9.3 say how each is written.
/// </summary>
public sealed partial class OutboundClientTests
{

    #region Reading the delivery-status part

    /// <summary>
    /// The message/delivery-status (or message/global-delivery-status) part of a report, as
    /// written: folded lines and all.
    /// </summary>
    private static String DeliveryStatus(String Report)

        => Regex.Match(Report, "Content-Type: message/(?:global-)?delivery-status.*?\r\n\r\n(.*?)\r\n--", RegexOptions.Singleline).Groups[1].Value;

    /// <summary>
    /// The value of the first field of that name in the delivery-status part, unfolded: RFC
    /// 5322 §2.2.3, "Unfolding is accomplished by simply removing any CRLF that is immediately
    /// followed by WSP".
    /// </summary>
    private static String? StatusField(String Report, String Name)
    {

        var field = Regex.Match(DeliveryStatus(Report), $@"(?m)^{Regex.Escape(Name)}:[ \t]*([^\r\n]*(?:\r\n[ \t][^\r\n]*)*)");

        return field.Success
                   ? Regex.Replace(field.Groups[1].Value, "\r\n(?=[ \t])", "")
                   : null;

    }

    /// <summary>
    /// The text of an "smtp" Diagnostic-Code - what follows "smtp;" (RFC 3464 §2.3.6:
    /// diagnostic-type ";" *text).
    /// </summary>
    private static String? SmtpDiagnostic(String Report)

        => StatusField(Report, "Diagnostic-Code") is { } code && Regex.Match(code, @"^smtp\s*;\s*(.*)$", RegexOptions.IgnoreCase | RegexOptions.Singleline) is { Success: true } smtp
               ? smtp.Groups[1].Value
               : null;

    #endregion


    #region D-16: a multi-line reply in Diagnostic-Code

    private const String MultiLineRcpt  = "550-5.1.1 mailbox unavailable\r\n550 5.1.1 user has moved with no forwarding address";
    private const String MultiLineMail  = "550-5.7.1 Sender refused\r\n550 5.7.1 see https://mx.outbound.test/why";
    private const String MultiLineData  = "554-5.7.1 Message refused\r\n554-5.7.1 it looks like spam to us\r\n554 5.7.1 see https://mx.outbound.test/why";
    private const String MultiLineLater = "450-4.2.1 Mailbox busy\r\n450 4.2.1 try again later";
    private const String MultiLineTaken = "250-2.0.0 Ok\r\n250 2.0.0 queued as 4711";

    public static IEnumerable<TestCaseData> MultiLineRepliesOfTheNextHop()
    {

        TestCaseData Case(String Name, SmtpServerScript Script, String Notify, Boolean Delay, String Reply)
            => new TestCaseData(Script, Notify, Delay, Reply).SetName($"A multi-line reply in Diagnostic-Code: {Name}")
                                                             .SetCategory(TestCategories.KnownIssue)
                                                             .SetProperty("Finding", "D-16");

        yield return Case("the bounce, a reply to RCPT",
                          new SmtpServerScript { RcptReply = _ => MultiLineRcpt },                                                  "FAILURE", false, MultiLineRcpt);

        yield return Case("the bounce, a reply to MAIL",
                          new SmtpServerScript { MailReply = MultiLineMail },                                                       "FAILURE", false, MultiLineMail);

        yield return Case("the bounce, a reply to the end of the data, of three lines",
                          new SmtpServerScript { EndOfDataReply = MultiLineData },                                                  "FAILURE", false, MultiLineData);

        yield return Case("the delayed DSN",
                          new SmtpServerScript { RcptReply = _ => MultiLineLater },                                                 "DELAY",   true,  MultiLineLater);

        yield return Case("the relayed DSN, a next hop without DSN",
                          new SmtpServerScript { Extensions = [ "PIPELINING", "8BITMIME", "ENHANCEDSTATUSCODES" ], EndOfDataReply = MultiLineTaken },
                                                                                                                                    "SUCCESS", false, MultiLineTaken);

    }


    [TestCaseSource(nameof(MultiLineRepliesOfTheNextHop))]
    [Description("RFC 3461 §9.2, the \"smtp\" diagnostic-type: diagnostic-code = *( 3*DIGIT \"-\" *text ) 3*DIGIT SPACE *text - \"For a single-line SMTP reply to an SMTP command, the diagnostic-code SHOULD be an exact transcription of the reply. For multi-line SMTP replies, it is necessary to insert a SPACE before each line after the first\", e.g. \"Diagnostic-Code: smtp ; 550-mailbox unavailable\" folded onto \" 550 user has moved with no forwarding address\": every line of the reply, its reply code and all")]
    public async Task A_multi_line_reply_is_transcribed_line_by_line(SmtpServerScript Script, String Notify, Boolean Delay, String Reply)
    {

        await using var nextHop = ScriptedSmtpServer.Start(Script);

        var run    = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example>", [ $"RCPT TO:<gone@outbound.test> NOTIFY={Notify}" ],
                                              Config: Delay ? DelayAtOnce : null);
        var report = run.Reports.FirstOrDefault()?.MessageContent;

        Assert.That(report, Is.Not.Null, run.Explain(nextHop));
        Assert.That(SmtpDiagnostic(report!), Is.EqualTo(String.Join(" ", Reply.Split("\r\n"))), run.Explain(nextHop));

    }


    [Test(Description = "RFC 5321 §4.5.3.1.5: \"The maximum total length of a reply line including the reply code and the <CRLF> is 512 octets\" - a reply of three such lines; RFC 5322 §2.1.1: \"Each line of characters MUST be no more than 998 characters, and SHOULD be no more than 78 characters, excluding the CRLF\" - the bounce that transcribes it (RFC 3461 §9.2) has no line longer")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "D-16")]
    public async Task A_reply_of_three_long_lines_makes_no_line_longer_than_998_characters()
    {

        var line  = new String('x', 488);
        var reply = $"550-5.7.1 {line}\r\n550-5.7.1 {line}\r\n550 5.7.1 {line}";

        await using var nextHop = ScriptedSmtpServer.Start(new SmtpServerScript { RcptReply = _ => reply });

        var run    = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example>", [ "RCPT TO:<gone@outbound.test>" ]);
        var bounce = run.Reports.FirstOrDefault()?.MessageContent;

        Assert.That(bounce, Is.Not.Null, run.Explain(nextHop));
        Assert.Multiple(() => {
            Assert.That(bounce!.Split("\r\n").Max(text => text.Length), Is.LessThanOrEqualTo(998),                          run.Explain(nextHop));
            Assert.That(SmtpDiagnostic(bounce),                         Is.EqualTo(String.Join(" ", reply.Split("\r\n"))),  "every line, transcribed");
        });

    }


    [Test(Description = "RFC 3461 §9.2: \"For a single-line SMTP reply to an SMTP command, the diagnostic-code SHOULD be an exact transcription of the reply\" (a guard for D-16)")]
    [Property("Finding", "D-16")]
    public async Task A_single_line_reply_is_transcribed_exactly()
    {

        await using var nextHop = NextHopRefusing("550 5.1.1 <gone@outbound.test>: Recipient address rejected");

        var run    = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example>", [ "RCPT TO:<gone@outbound.test>" ]);
        var bounce = run.Reports.FirstOrDefault()?.MessageContent;

        Assert.That(bounce, Is.Not.Null, run.Explain(nextHop));
        Assert.That(SmtpDiagnostic(bounce!), Is.EqualTo("550 5.1.1 <gone@outbound.test>: Recipient address rejected"), run.Explain(nextHop));

    }

    #endregion

    #region D-17: the Remote-MTA of a next hop known by its address

    public static IEnumerable<TestCaseData> RemoteMtaByAddress()
    {

        TestCaseData Case(String Name, SmtpServerScript Script, String Notify)
            => new TestCaseData(Script, Notify).SetName($"The Remote-MTA of a smart host given as an address is a domain-literal: {Name}")
                                               .SetCategory(TestCategories.KnownIssue)
                                               .SetProperty("Finding", "D-17");

        yield return Case("the bounce",
                          new SmtpServerScript { RcptReply = _ => "550 5.1.1 No such user" },                                       "FAILURE");

        yield return Case("the relayed DSN, a next hop without DSN",
                          new SmtpServerScript { Extensions = [ "PIPELINING", "8BITMIME", "ENHANCEDSTATUSCODES" ] },                "SUCCESS");

    }


    [TestCaseSource(nameof(RemoteMtaByAddress))]
    [Description("RFC 3461 §9.3, the \"dns\" MTA-name-type: \"MTA names of type \"dns\" SHOULD be valid Internet domain names. If such domain names are not available, a domain-literal containing the internet protocol address is acceptable\" - domain-literal = \"[\" 1*3DIGIT 3(\".\" 1*3DIGIT) \"]\"; the relay knows its smart host as 127.0.0.1, and by no name: \"Remote-MTA: dns; [127.0.0.1]\", not a bare address")]
    public async Task The_Remote_MTA_of_a_next_hop_given_as_an_address_is_a_domain_literal(SmtpServerScript Script, String Notify)
    {

        await using var nextHop = ScriptedSmtpServer.Start(Script);

        var run    = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example>", [ $"RCPT TO:<gone@outbound.test> NOTIFY={Notify}" ]);
        var report = run.Reports.FirstOrDefault()?.MessageContent;

        Assert.That(report, Is.Not.Null, run.Explain(nextHop));
        Assert.That(StatusField(report!, "Remote-MTA") is { } remote ? Regex.Replace(remote, @"^dns\s*;\s*", "dns; ", RegexOptions.IgnoreCase) : null,
                    Is.EqualTo("dns; [127.0.0.1]"), run.Explain(nextHop));

    }

    #endregion

}
