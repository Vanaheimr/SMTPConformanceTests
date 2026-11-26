using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// The sizes of RFC 5321 §4.5.3.1 - a local-part of 64 octets, a domain of 255, a path of 256, a
/// reply line of 512 - and what the server makes of a name or a path longer than they allow,
/// which still fits in its command line (1024 octets, as Hermod has it by default): "Objects
/// larger than these sizes SHOULD be avoided when possible", and clients "MUST be prepared for a
/// server to reject them". Whatever the server takes, it writes into the header of the message
/// it delivers - Received (§4.4), Return-Path - and into the report it sends on it (RFC 3461),
/// where RFC 5322 §2.1.1 holds: "Each line of characters MUST be no more than 998 characters".
/// </summary>
[TestFixture]
public sealed class SizeLimitTests : HermodServerTestBase
{

    #region Setup

    /// <summary>
    /// Hermod's own command line limit, not one of the suite's.
    /// </summary>
    protected override HermodSmtpServerFixtureOptions Options
        => new() { MaxCommandLineLength = new SMTPServerConfig { Hostname = "mx.hermod.test" }.MaxCommandLineLength };

    /// <summary>
    /// A domain name of that many octets: labels of 63 octets (RFC 1035 §2.3.4), ".example" at
    /// the end. Every label is a valid one; only the whole is longer than RFC 5321 §4.5.3.1.2
    /// allows when <paramref name="Length"/> is more than 255.
    /// </summary>
    private static String DomainOf(Int32 Length)
    {

        var labels = Length - ".example".Length;
        var domain = String.Concat(Enumerable.Repeat(new String('d', 63) + ".", labels / 64)) + new String('d', labels % 64) + ".example";

        Assert.That(domain.Length, Is.EqualTo(Length),        "the domain the test meant to write");
        Assert.That(domain,        Does.Not.Contain(".."),    "the domain the test meant to write");

        return domain;

    }

    /// <summary>
    /// The longest line of a message, without its CR LF.
    /// </summary>
    private static Int32 LongestLine(String Message)
        => Message.Split("\r\n").Max(line => line.Length);

    /// <summary>
    /// The reply lines that are longer than RFC 5321 §4.5.3.1.5 allows, with their length - the
    /// reply code and the CR LF included.
    /// </summary>
    private static IEnumerable<String> TooLong(SmtpReply Reply)
        => Reply.RawLines.Where(line => line.Length + 2 > 512).Select(line => $"{line.Length + 2} octets: {line[..Math.Min(line.Length, 60)]}...");

    /// <summary>
    /// One transaction with this EHLO name, reverse-path and forward-path: the message, and the
    /// reports the server queued on it - or nothing, when the server refused the name or a path,
    /// which RFC 5321 §4.5.3.1 lets it do.
    /// </summary>
    private async Task<(String? Message, IReadOnlyList<String> Reports, String Explanation)> Deliver(String Ehlo, String MailFrom, String RcptTo)
    {

        var marker      = Marker();

        var (client, _) = await Server.ConnectMtaAsync();
        await using var _client = client;

        var (ehlo, _)   = await client.EhloAsync(Ehlo);
        if (!ehlo.IsPositiveCompletion)
            return (null, [], Explain(client));

        if (!(await client.CommandAsync($"MAIL FROM:{MailFrom}")).IsPositiveCompletion)
            return (null, [], Explain(client));

        if (!(await client.CommandAsync($"RCPT TO:{RcptTo}")).IsPositiveCompletion)
            return (null, [], Explain(client));

        var (_, final)  = await client.DataAsync($"From: <sender@client.example>\r\nSubject: {marker}\r\n\r\nWhat is written on top of this?\r\n");

        Assert.That(final?.Code, Is.EqualTo(250), Explain(client));

        var stored      = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.That(stored, Is.Not.Null, Explain(client));

        return (stored!.Raw,
                [ .. Server.Queue.Queued.Where(mail => mail.MessageContent.Contains(marker, StringComparison.Ordinal)).Select(mail => mail.MessageContent) ],
                Explain(client));

    }

    #endregion


    #region S-51: a header line of more than 998 characters

    public static IEnumerable<TestCaseData> NamesAndPathsTooLong()
    {

        TestCaseData Case(String Name, String Ehlo, String MailFrom, String RcptTo)
            => new TestCaseData(Ehlo, MailFrom, RcptTo).SetName($"No header line of more than 998 characters: {Name}")
                                                       .SetProperty("Finding", "S-51");

        yield return Case("an EHLO name of 1000 octets, in Received",
                          DomainOf(1000),         "<sender@client.example>",                              "<alice@hermod.test>");

        yield return Case("a reverse-path of 997 octets, in Return-Path",
                          "mx.client.example",    $"<{new String('l', 64)}@{DomainOf(930)}>",             "<alice@hermod.test>");

        yield return Case("a forward-path of 1004 octets, in Received",
                          "mx.client.example",    "<sender@client.example>",                              $"<{new String('r', 990)}@hermod.test>");

        yield return Case("a forward-path of 989 octets, in the delivered DSN",
                          "mx.client.example",    "<sender@client.example>",                              $"<{new String('r', 975)}@hermod.test> NOTIFY=SUCCESS");

    }


    [TestCaseSource(nameof(NamesAndPathsTooLong))]
    [Description("RFC 5321 §4.5.3.1.2: \"The maximum total length of a domain name or number is 255 octets\"; §4.5.3.1.1, §4.5.3.1.3: a local-part of 64 octets, a path of 256 - and §4.5.3.1: \"Objects larger than these sizes SHOULD be avoided when possible\", clients \"MUST be prepared for a server to reject them\", §4.5.3.1.9: \"501 Path too long\". A server that takes a longer one anyway writes it into the Received field (§4.4), the Return-Path and the DSN (RFC 3461 §6.3 (e)) - and RFC 5322 §2.1.1: \"Each line of characters MUST be no more than 998 characters, and SHOULD be no more than 78 characters, excluding the CRLF\". Refused, or written within the limit")]
    public async Task No_header_line_of_more_than_998_characters(String Ehlo, String MailFrom, String RcptTo)
    {

        var (message, reports, explanation) = await Deliver(Ehlo, MailFrom, RcptTo);

        if (message is null)
            Assert.Pass("refused: RFC 5321 §4.5.3.1 lets the server do that");

        Assert.Multiple(() => {
            Assert.That(LongestLine(message!),             Is.LessThanOrEqualTo(998), "the message as delivered" + explanation);
            Assert.That(reports.Select(LongestLine),       Has.All.LessThanOrEqualTo(998), "the reports on it");
        });

    }

    #endregion


    #region S-52: a reply line of more than 512 octets

    public static IEnumerable<TestCaseData> GreetingsWithANameTooLong()
    {

        TestCaseData Case(String Command)
            => new TestCaseData(Command).SetName($"No reply line of more than 512 octets: {Command} with a name of 1000 octets")
                                        .SetProperty("Finding", "S-52");

        yield return Case("EHLO");
        yield return Case("HELO");

    }


    [TestCaseSource(nameof(GreetingsWithANameTooLong))]
    [Description("RFC 5321 §4.5.3.1.5: \"The maximum total length of a reply line including the reply code and the <CRLF> is 512 octets. More information may be conveyed through multiple-line replies\" - a client need not read more; §4.5.3.1.2: a domain name is 255 octets at most, so an EHLO or HELO argument of 1000 octets is none, and is not answered with a reply line that repeats it whole")]
    public async Task No_reply_line_of_more_than_512_octets(String Command)
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var _client = client;

        var reply = await client.CommandAsync($"{Command} {DomainOf(1000)}");

        Assert.That(TooLong(reply), Is.Empty, Explain(client));

    }

    #endregion


    #region Guard: the sizes RFC 5321 asks for are taken

    [Test(Description = "RFC 5321 §4.5.3.1: \"Every implementation MUST be able to receive objects of at least these sizes\" - an EHLO name of 255 octets (§4.5.3.1.2), a reverse-path of 256 (§4.5.3.1.3), a local-part of 64 (§4.5.3.1.1): taken, answered with reply lines of 512 octets at most, and delivered with no header line of more than 998 characters (a guard for S-51 and S-52)")]
    [Property("Finding", "S-51")]
    public async Task Names_and_paths_of_the_sizes_RFC_5321_asks_for_are_taken()
    {

        var ehlo     = DomainOf(255);
        var mailFrom = $"<{new String('l', 64)}@{DomainOf(189)}>";
        var rcptTo   = $"<{new String('r', 64)}@hermod.test> NOTIFY=SUCCESS";

        Assert.That(mailFrom.Length, Is.EqualTo(256), "the reverse-path the test meant to write");

        var (client, _) = await Server.ConnectMtaAsync();
        await using (client)
        {
            var (reply, _) = await client.EhloAsync(ehlo);
            Assert.Multiple(() => {
                Assert.That(reply.Code,     Is.EqualTo(250), Explain(client));
                Assert.That(TooLong(reply), Is.Empty,        Explain(client));
            });
        }

        var (message, reports, explanation) = await Deliver(ehlo, mailFrom, rcptTo);

        Assert.That(message, Is.Not.Null, "taken" + explanation);
        Assert.Multiple(() => {
            Assert.That(message,                       Does.Contain($"Return-Path: {mailFrom}\r\n").And.Contain($"from {ehlo} "), explanation);
            Assert.That(LongestLine(message!),         Is.LessThanOrEqualTo(998),       explanation);
            Assert.That(reports,                       Has.Count.EqualTo(1),            "the delivered DSN");
            Assert.That(reports.Select(LongestLine),   Has.All.LessThanOrEqualTo(998),  "the delivered DSN");
        });

    }

    #endregion

}
