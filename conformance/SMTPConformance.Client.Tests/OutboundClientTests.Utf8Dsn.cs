using System.Text.RegularExpressions;

using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// The bounce of an SMTPUTF8 message (RFC 6533 §4): RFC 3464's message/delivery-status is 7-bit
/// only, and message/rfc822 has no room for UTF-8 header values (RFC 6532 §3.7) - a report that
/// needs UTF-8 uses message/global-delivery-status and message/global.
/// </summary>
public sealed partial class OutboundClientTests
{

    #region D-13: the bounce of an SMTPUTF8 message

    /// <summary>
    /// The parts of a multipart report: the Content-Type of each and the whole part.
    /// </summary>
    private static IReadOnlyList<(String ContentType, String Part)> ReportParts(String Report)
    {

        var boundary = Regex.Match(Report, "boundary=\"([^\"]*)\"").Groups[1].Value;

        return [.. Report.Split("\r\n--" + boundary).
                          Skip(1).
                          Where (part => !part.StartsWith("--")).
                          Select(part => (Regex.Match(part, @"^Content-Type:\s*([^;\r\n]+)", RegexOptions.Multiline | RegexOptions.IgnoreCase).Groups[1].Value.Trim().ToLowerInvariant(),
                                          part))];

    }

    private static Boolean IsAscii(String Text)
        => Text.All(c => c < 0x80);


    private static async Task<(RelayRun Run, ScriptedSmtpServer NextHop)> BounceOfUtf8Recipient()
    {

        var nextHop = NextHopRefusing("550 5.1.1 No such user");
        var run     = await RelayThroughHermod(nextHop, "MAIL FROM:<app@client.example> SMTPUTF8", [ "RCPT TO:<jörg@outbound.test>" ]);

        return (run, nextHop);

    }


    [Test(Description = "RFC 3464 §2.1, message/delivery-status: \"\"7bit\" encoding is sufficient and MUST be used\"; RFC 6533 §4: \"the second part is a 7-bit-only message/delivery-status\" and \"the present standard DSN format does not permit the return of undeliverable SMTPUTF8 messages\" - fields with UTF-8 in them go in a message/global-delivery-status (§4.1)")]
    [Category(TestCategories.KnownIssue), Property("Finding", "D-13")]
    public async Task The_status_of_a_UTF_8_recipient_is_a_message_global_delivery_status()
    {

        var (run, nextHop) = await BounceOfUtf8Recipient();
        await using var _ = nextHop;

        var bounce = run.Reports.SingleOrDefault()?.MessageContent;

        Assert.That(bounce, Is.Not.Null, run.Explain(nextHop));

        var status = ReportParts(bounce!).Single(part => part.Part.Contains("Final-Recipient:", StringComparison.OrdinalIgnoreCase));

        Assert.That(IsAscii(status.Part) || status.ContentType == "message/global-delivery-status", Is.True,
                    $"a {status.ContentType} with UTF-8 in it:" + run.Explain(nextHop));

    }


    [Test(Description = "RFC 6532 §3.7: a message with \"8-bit UTF-8 header values\" is a \"message/global message\", and \"The content of a message/global part is otherwise identical to that of a message/rfc822 part\"; RFC 6533 §4 - the returned SMTPUTF8 message is message/global (or message/global-headers), not message/rfc822 (or text/rfc822-headers)")]
    [Category(TestCategories.KnownIssue), Property("Finding", "D-13")]
    public async Task A_returned_message_with_UTF_8_header_values_is_message_global()
    {

        var (run, nextHop) = await BounceOfUtf8Recipient();
        await using var _ = nextHop;

        var bounce = run.Reports.SingleOrDefault()?.MessageContent;

        Assert.That(bounce, Is.Not.Null, run.Explain(nextHop));

        // The part's own header, then the returned message: its header section is what matters.
        var returned = ReportParts(bounce!).Last();
        var start    = returned.Part.IndexOf("\r\n\r\n", StringComparison.Ordinal) + 4;
        var end      = returned.Part.IndexOf("\r\n\r\n", start, StringComparison.Ordinal);
        var header   = end < 0 ? returned.Part[start..] : returned.Part[start..end];

        Assume.That(returned.ContentType, Is.AnyOf("message/rfc822", "text/rfc822-headers", "message/global", "message/global-headers"), run.Explain(nextHop));

        Assert.That(IsAscii(header) || returned.ContentType is "message/global" or "message/global-headers", Is.True,
                    $"a {returned.ContentType} with UTF-8 header values:" + run.Explain(nextHop));

    }

    #endregion

}
