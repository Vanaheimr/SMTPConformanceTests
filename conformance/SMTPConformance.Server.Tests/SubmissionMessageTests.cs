using System.Text.RegularExpressions;

using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 6409: what the server owes a message it takes as the Message Submission Agent - from a
/// client signed in on the submission port, with no application of its own to hand it to -
/// before it relays or delivers it. §8: "Any message forwarded or delivered by the MSA MUST
/// conform to the requirements of [SMTP-MTA] and [MESSAGE-FORMAT]"; §4.2: "The MSA MUST ensure
/// that all domains in the SMTP envelope are fully qualified"; §8.3: "The MSA SHOULD add or
/// replace the 'Message-ID' field, if it lacks it". RFC 5321 §6.4 lets "one used as the target
/// of SMTP as an initial posting (message submission) protocol" add a message-id and a date and
/// correct addresses to FQDN format - and says "These changes MUST NOT be applied by an SMTP
/// server that provides an intermediate relay function".
/// </summary>
[TestFixture]
public sealed class SubmissionMessageTests : HermodServerTestBase
{

    #region Setup

    protected override HermodSmtpServerFixtureOptions Options
        => new() { EnableTls = true };

    private const String Date       = "Date: Thu, 26 Nov 2026 10:00:00 +0000\r\n";
    private const String From       = "From: <alice@hermod.test>\r\n";

    /// <summary>
    /// What became of one submission: the replies, and the message as the server relays it (the
    /// queue) or delivers it (the store) - null when it refused it.
    /// </summary>
    private sealed record Outcome(Int32 Mail, Int32 Rcpt, Int32 EndOfData, String? Message, String? EnvelopeFrom, IReadOnlyList<String> EnvelopeTo, String Explanation)
    {

        /// <summary>
        /// The server said no, for good, at one of the steps - which RFC 6409 lets it do.
        /// </summary>
        public Boolean Refused
            => Mail / 100 == 5 || Rcpt / 100 == 5 || EndOfData / 100 == 5;

    }

    private async Task<Outcome> SubmitAsync(String Header, String MailFrom = "alice@hermod.test", String RcptTo = "bob@remote.example", Boolean SignedIn = true)
    {

        var marker = Marker();

        RawSmtpClient client;
        if (SignedIn)
            client = await Server.ConnectSignedInAsync();
        else
            client = await Server.ConnectAndEhloAsync();

        await using var _client = client;

        var mail = await client.CommandAsync($"MAIL FROM:<{MailFrom}>");
        if (mail.Code != 250)
            return new Outcome(mail.Code, 0, 0, null, null, [], Explain(client));

        var rcpt = await client.CommandAsync($"RCPT TO:<{RcptTo}>");
        if (rcpt.Code != 250)
            return new Outcome(mail.Code, rcpt.Code, 0, null, null, [], Explain(client));

        var (data, end) = await client.DataAsync(Header + $"Subject: {marker}\r\n\r\nbody\r\n");
        Assume.That(data.Code, Is.EqualTo(354), Explain(client));

        if (end?.Code != 250)
            return new Outcome(mail.Code, rcpt.Code, end?.Code ?? 0, null, null, [], Explain(client));

        var stored = await Server.Storage.WaitForMarkerAsync(marker, TimeSpan.FromSeconds(1));
        if (stored is not null)
            return new Outcome(mail.Code, rcpt.Code, end.Code, stored.Raw, stored.EnvelopeFrom, stored.EnvelopeTo, Explain(client));

        var queued = Server.Queue.Queued.FirstOrDefault(mail => mail.MessageContent.Contains(marker, StringComparison.Ordinal));

        return new Outcome(mail.Code, rcpt.Code, end.Code, queued?.MessageContent, queued?.EnvelopeFrom, queued?.EnvelopeTo ?? [], Explain(client));

    }

    /// <summary>
    /// The header section of a message, its folded lines unfolded (RFC 5322 §2.2.3).
    /// </summary>
    private static String[] HeaderLines(String Message)
    {
        var end = Message.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        return Regex.Replace(end < 0 ? Message : Message[..end], @"\r\n[ \t]", " ").Split("\r\n");
    }

    private static String[] Fields(String Message, String Name)
        => [ .. HeaderLines(Message).Where(line => line.StartsWith(Name + ":", StringComparison.OrdinalIgnoreCase)).Select(line => line[(Name.Length + 1)..].Trim()) ];

    /// <summary>
    /// A domain that is fully qualified (RFC 6409 §4.2): more than one label.
    /// </summary>
    private static Boolean FullyQualified(String Address)
        => Address.LastIndexOf('@') is var at and > 0 && Address[(at + 1)..].Trim('.').Contains('.');

    #endregion


    #region S-56: the message the MSA relays or delivers is RFC 5322's

    private static IEnumerable<TestCaseData> IncompleteMessages()
    {

        static TestCaseData Case(String Name, String Header, String RcptTo)
            => new TestCaseData(Header, RcptTo).SetName($"A submitted message goes on as RFC 5322 has it: {Name}")
                                               .SetCategory(TestCategories.KnownIssue)
                                               .SetProperty("Finding", "S-56");

        yield return Case("no Date, relayed",           From,                   "bob@remote.example");
        yield return Case("no Date, delivered",         From,                   "alice@hermod.test");
        yield return Case("no From",                    Date,                   "bob@remote.example");
        yield return Case("a From without a domain",    "From: alice\r\n" + Date, "bob@remote.example");

    }

    [TestCaseSource(nameof(IncompleteMessages))]
    [Description("RFC 6409 §8: \"Any message forwarded or delivered by the MSA MUST conform to the requirements of [SMTP-MTA] and [MESSAGE-FORMAT]\"; RFC 5322 §3.6: \"The only required header fields are the origination date field and the originator address field(s)\", §3.4.1: addr-spec = local-part \"@\" domain; RFC 6409 §4.2: \"If the MSA examines or alters the message text in any way, except to add trace header fields, it MUST ensure that all domains in address header fields are fully qualified\" - a message without Date or From, or with a From that names no domain, is refused (RFC 6409 §4.1: 554), or it goes on with them, as RFC 5321 §6.4 lets the server that takes submissions add \"a date, time, or time zone when none appears\"")]
    public async Task A_submitted_message_goes_on_as_RFC_5322_has_it(String Header, String RcptTo)
    {

        var outcome = await SubmitAsync(Header, RcptTo: RcptTo);

        if (outcome.Refused)
            return;

        Assert.That(outcome.Message, Is.Not.Null, "the message, relayed or delivered" + outcome.Explanation);

        var from = Fields(outcome.Message!, "From");

        Assert.That(Fields(outcome.Message!, "Date"), Has.Length.EqualTo(1),                  "the Date field of the message that goes on" + outcome.Explanation);
        Assert.That(from,                             Has.Length.EqualTo(1),                  "the From field of the message that goes on" + outcome.Explanation);
        Assert.That(Regex.Matches(from[0], @"[^\s<>,;:""]+@[^\s<>,;:""]+").Select(match => match.Value),
                    Is.Not.Empty.And.All.Matches<String>(FullyQualified),                    $"the addresses of From: {from[0]}" + outcome.Explanation);

    }

    #endregion

    #region S-57: a Message-ID for the message that lacks one

    [Test(Description = "RFC 6409 §8.3: \"The MSA SHOULD add or replace the 'Message-ID' field, if it lacks it, or it is not valid syntax\"; RFC 5322 §3.6.4: \"every message SHOULD have a \\\"Message-ID:\\\" field\", msg-id = [CFWS] \"<\" id-left \"@\" id-right \">\" [CFWS] - a submitted message without one goes on with one")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-57")]
    public async Task A_submitted_message_without_a_Message_ID_gets_one()
    {

        var outcome = await SubmitAsync(From + Date);

        Assert.That(outcome.EndOfData,                       Is.EqualTo(250),                                  outcome.Explanation);
        Assert.That(Fields(outcome.Message ?? "", "Message-ID"), Has.Length.EqualTo(1).And.All.Match(@"^<[^<>@\s]+@[^<>@\s]+>$"),
                    "the Message-ID of the message that goes on" + outcome.Explanation);

    }


    [Test(Description = "RFC 6409 §8.3: the Message-ID is added \"if it lacks it, or it is not valid syntax\" - one of valid syntax goes on as the client gave it, and alone (a guard for S-57)")]
    [Property("Finding", "S-57")]
    public async Task The_Message_ID_of_a_submitted_message_is_kept()
    {

        var messageId = $"<{Guid.NewGuid():N}@client.example>";

        var outcome   = await SubmitAsync(From + Date + $"Message-ID: {messageId}\r\n");

        Assert.That(outcome.EndOfData,                           Is.EqualTo(250),                  outcome.Explanation);
        Assert.That(Fields(outcome.Message ?? "", "Message-ID"), Is.EqualTo(new[] { messageId }),  outcome.Explanation);
        Assert.That(Fields(outcome.Message ?? "", "Date"),       Is.EqualTo(new[] { Date[6..^2] }), "the Date the client gave" + outcome.Explanation);

    }


    [Test(Description = "RFC 5321 §6.4: adding a message-id or a date \"MAY be applied when necessary by an originating SMTP server, or one used as the target of SMTP as an initial posting (message submission) protocol\" - and \"there is at best great concern about fixes applied by a relay or delivery SMTP server that has little or no knowledge of the user or client machine\": a message from another server, not signed in, is delivered as it came, no Date and no Message-ID added (a guard for S-56 and S-57)")]
    [Property("Finding", "S-57")]
    public async Task A_message_from_another_server_is_delivered_as_it_came()
    {

        var outcome = await SubmitAsync(From, MailFrom: "sender@client.example", RcptTo: "alice@hermod.test", SignedIn: false);

        Assert.That(outcome.EndOfData,                           Is.EqualTo(250),   outcome.Explanation);
        Assert.That(outcome.Message,                             Is.Not.Null,       outcome.Explanation);
        Assert.That(Fields(outcome.Message!, "Date"),            Is.Empty,          "a Date the server added" + outcome.Explanation);
        Assert.That(Fields(outcome.Message!, "Message-ID"),      Is.Empty,          "a Message-ID the server added" + outcome.Explanation);

    }

    #endregion

    #region S-58: the envelope of a submission is fully qualified

    private static IEnumerable<TestCaseData> SingleLabelEnvelopes()
    {

        static TestCaseData Case(String Name, String MailFrom, String RcptTo)
            => new TestCaseData(MailFrom, RcptTo).SetName($"The envelope of a submission is fully qualified: {Name}")
                                                 .SetCategory(TestCategories.KnownIssue)
                                                 .SetProperty("Finding", "S-58");

        yield return Case("a recipient at a single-label domain",  "alice@hermod.test",  "bob@intranet");
        yield return Case("a sender at a single-label domain",     "alice@intranet",     "bob@remote.example");

    }

    [TestCaseSource(nameof(SingleLabelEnvelopes))]
    [Description("RFC 6409 §4.2: \"The MSA MUST ensure that all domains in the SMTP envelope are fully qualified\", \"Reply code 554 is to be used to reject a MAIL, RCPT, or DATA command that contains improper domain references\"; RFC 5321 §6.4: the server that takes submissions MAY apply the \"Correction of addresses to proper FQDN format\" - a single-label domain in MAIL or RCPT is refused, or the message goes on with a fully qualified one")]
    public async Task The_envelope_of_a_submission_is_fully_qualified(String MailFrom, String RcptTo)
    {

        var outcome = await SubmitAsync(From.Replace("alice@hermod.test", MailFrom) + Date, MailFrom, RcptTo);

        if (outcome.Refused)
            return;

        Assert.That(outcome.Message,                                 Is.Not.Null,                                         "the message, relayed" + outcome.Explanation);
        Assert.That(new[] { outcome.EnvelopeFrom ?? "" }.Concat(outcome.EnvelopeTo),
                    Is.All.Matches<String>(FullyQualified),                                                                $"the envelope it went on with: <{outcome.EnvelopeFrom}> to {String.Join(", ", outcome.EnvelopeTo)}" + outcome.Explanation);

    }

    #endregion

}
