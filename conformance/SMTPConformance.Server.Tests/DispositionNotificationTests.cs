using System.Text;
using System.Text.RegularExpressions;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 8098 message disposition notifications as Hermod's server sends them on its own
/// (<c>EnableAutoMdn</c>, <see cref="org.GraphDefined.Vanaheimr.Hermod.SMTP.Server.MdnGeneratingMailStorage"/>):
/// when an MDN may be sent automatically at all (§2.1, §6.4), never in answer to an MDN (§2.1),
/// its format - multipart/report (RFC 6522) with report-type=disposition-notification (§3), the
/// fields of message/disposition-notification (§3.1, §3.2) - and its envelope (§3). Driven over
/// the wire: a message asking for a read receipt is delivered to a local mailbox, and what the
/// server queues for relay is read with the suite's own MIME reader.
/// </summary>
[TestFixture]
public sealed class DispositionNotificationTests : HermodServerTestBase
{

    protected override HermodSmtpServerFixtureOptions Options
        => new() { EnableAutoMdn = true };


    #region Setup

    private const String Sender = "sender@client.example";

    /// <summary>
    /// A message to alice@hermod.test, its subject the marker, asking for a read receipt.
    /// </summary>
    private static String Message(String   Marker,
                                  String?  DispositionNotificationTo  = Sender,
                                  String   From                       = "Sender <" + Sender + ">",
                                  Boolean  WithMessageId              = true,
                                  String   MoreHeaders                = "",
                                  String   Body                       = "Did you get this?\r\n")

        => $"From: {From}\r\n" +
           "To: Alice <alice@hermod.test>\r\n" +
           $"Subject: {Marker}\r\n" +
           "Date: Fri, 20 Nov 2026 10:00:00 +0100\r\n" +
           (WithMessageId ? $"Message-ID: <{Marker}@client.example>\r\n" : "") +
           (DispositionNotificationTo is not null ? $"Disposition-Notification-To: {DispositionNotificationTo}\r\n" : "") +
           MoreHeaders +
           "\r\n" +
           Body;

    /// <summary>
    /// One transaction from mx.client.example: MAIL FROM:&lt;<paramref name="MailFrom"/>&gt;, one
    /// RCPT TO: per entry of <paramref name="RcptTo"/> (path and parameters), the message.
    /// Asserts that it was taken.
    /// </summary>
    private async Task Deliver(String MailFrom, String Message, params String[] RcptTo)
    {

        await using var client = await Server.ConnectAndEhloAsync("mx.client.example");

        var mail = await client.CommandAsync($"MAIL FROM:<{MailFrom}>");
        Assert.That(mail.Code, Is.EqualTo(250), Explain(client));

        foreach (var rcpt in RcptTo.Length > 0 ? RcptTo : [ "<alice@hermod.test>" ])
            Assert.That((await client.CommandAsync($"RCPT TO:{rcpt}")).Code, Is.EqualTo(250), Explain(client));

        var (_, final) = await client.DataAsync(Message);

        Assert.That(final?.Code, Is.EqualTo(250), Explain(client));

    }

    /// <summary>
    /// The MDNs queued about the message with this marker. They are queued before the
    /// end of data is answered.
    /// </summary>
    private IReadOnlyList<QueuedMail> Mdns(String Marker)

        => [ .. Server.Queue.Queued.Where(mail => mail.MessageContent.Contains(Marker, StringComparison.Ordinal) &&
                                                  mail.MessageContent.Contains("disposition-notification", StringComparison.OrdinalIgnoreCase)) ];

    /// <summary>
    /// The one MDN about the message with this marker.
    /// </summary>
    private QueuedMail Mdn(String Marker)
    {

        var mdns = Mdns(Marker);

        Assert.That(mdns, Has.Count.EqualTo(1), $"one MDN about {Marker}\n--- server log ---\n{Server.Log}");

        return mdns[0];

    }

    /// <summary>
    /// The fields of the message/disposition-notification part, raw - each "name: value" line
    /// unfolded.
    /// </summary>
    internal static String Report(String Mdn)
        => Regex.Replace(ReportMail.Part(Mdn, "message/disposition-notification").Text, @"\r\n[ \t]+", " ");

    /// <summary>
    /// The value of a field of the message/disposition-notification part, or null.
    /// </summary>
    internal static String? Field(String Mdn, String Name)
    {
        var match = Regex.Match(Report(Mdn), $@"^{Regex.Escape(Name)}[ \t]*:(?<v>[^\r\n]*)", RegexOptions.Multiline | RegexOptions.IgnoreCase);
        return match.Success ? match.Groups["v"].Value.Trim() : null;
    }

    /// <summary>
    /// RFC 8098 §3.2.6, disposition-field, with OWS as *WSP.
    /// </summary>
    internal static readonly Regex DispositionField = new(@"^(?<action>manual-action|automatic-action)[ \t]*/[ \t]*(?<sending>MDN-sent-manually|MDN-sent-automatically)[ \t]*;[ \t]*(?<type>displayed|deleted|dispatched|processed)([ \t]*/[ \t]*[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+([ \t]*,[ \t]*[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+)*)?[ \t]*$",
                                                          RegexOptions.IgnoreCase);

    #endregion


    #region When an MDN is sent

    [Test(Description = "RFC 8098 §2.1: an MDN is requested with Disposition-Notification-To; the server, set to answer such requests, queues one when the address is the reverse-path's")]
    public async Task A_message_asking_for_a_receipt_to_its_own_reverse_path_is_answered()
    {

        var marker = Marker();

        await Deliver(Sender, Message(marker));

        var mdn = Mdn(marker);

        Assert.That(mdn.EnvelopeTo, Is.EqualTo(new[] { Sender }));

    }


    [Test(Description = "RFC 8098 §2.1: \"The presence of a Disposition-Notification-To header field in a message is merely a request for an MDN\" - without one, none is sent")]
    public async Task A_message_asking_for_no_receipt_is_not_answered()
    {

        var marker = Marker();

        await Deliver(Sender, Message(marker, DispositionNotificationTo: null));

        Assert.That(Mdns(marker), Is.Empty);

    }


    [TestCase("Sender <sender@client.example>",  Description = "a display name")]
    [TestCase("sender@CLIENT.EXAMPLE",           Description = "the domain in capitals")]
    [Test(Description = "RFC 8098 §2.1: \"The comparison of the addresses is done using only the addr-spec ... excluding any angle brackets, phrase\" and \"case insensitive for the domain part\" - these are the reverse-path's address")]
    public async Task The_same_address_in_another_spelling_is_the_reverse_path(String DispositionNotificationTo)
    {

        var marker = Marker();

        await Deliver(Sender, Message(marker, DispositionNotificationTo));

        Assert.That(Mdns(marker), Has.Count.EqualTo(1));

    }


    private static IEnumerable<TestCaseData> AddressesTheReversePathDoesNotVouchFor()
    {

        yield return new TestCaseData(Sender, "victim@elsewhere.example").
                         SetName("{m}(a third party)").
                         SetProperty("Finding", "K-1");

        yield return new TestCaseData("", Sender).
                         SetName("{m}(a null reverse-path)").
                         SetProperty("Finding", "K-1");

        yield return new TestCaseData(Sender, "Sender@client.example").
                         SetName("{m}(a local-part in another case)").
                         SetProperty("Finding", "K-1");

        yield return new TestCaseData(Sender, "sender@client.example, victim@elsewhere.example").
                         SetName("{m}(two distinct addresses)").
                         SetProperty("Finding", "K-1");

    }

    [TestCaseSource(nameof(AddressesTheReversePathDoesNotVouchFor))]
    [Test(Description = "RFC 8098 §2.1: \"MDNs MUST NOT be sent automatically if the address in the Disposition-Notification-To header field differs from the address in the Return-Path header field\" - the local-part compared \"case sensitive\" - and \"Confirmation from the user MUST be obtained (or no MDN sent) if ... there is more than one distinct address\"; §6.4: or MDNs flood a third party")]
    public async Task No_MDN_is_sent_automatically_to_an_address_the_reverse_path_does_not_vouch_for(String MailFrom, String DispositionNotificationTo)
    {

        var marker = Marker();

        await Deliver(MailFrom, Message(marker, DispositionNotificationTo));

        Assert.That(Mdns(marker).Select(mdn => $"MAIL FROM:<{mdn.EnvelopeFrom}> to {String.Join(", ", mdn.EnvelopeTo)}"), Is.Empty);

    }


    [Test(Description = "RFC 8098 §2.1: \"An MDN MUST NOT be generated in response to an MDN\" - not even to one that, against §3, asks for a receipt itself")]
    [Property("Finding", "K-4")]
    public async Task No_MDN_is_sent_in_answer_to_an_MDN()
    {

        var marker   = Marker();
        var boundary = "mdn-" + marker;

        var incoming = Message(marker,
                               MoreHeaders:  "MIME-Version: 1.0\r\n" +
                                             $"Content-Type: multipart/report; report-type=disposition-notification; boundary=\"{boundary}\"\r\n",
                               Body:         $"--{boundary}\r\n" +
                                             "Content-Type: text/plain\r\n\r\n" +
                                             "Your message was displayed.\r\n" +
                                             $"--{boundary}\r\n" +
                                             "Content-Type: message/disposition-notification\r\n\r\n" +
                                             "Reporting-UA: client.example; Foomail 97.1\r\n" +
                                             "Final-Recipient: rfc822; sender@client.example\r\n" +
                                             "Original-Message-ID: <first@hermod.test>\r\n" +
                                             "Disposition: manual-action/MDN-sent-manually; displayed\r\n" +
                                             $"\r\n--{boundary}--\r\n");

        await Deliver(Sender, incoming);

        Assert.That(Mdns(marker), Is.Empty);

    }


    [Test(Description = "RFC 8098 §3: \"Multiple MDNs may be generated as a result of one message submission, one per recipient\" - \"A particular MDN describes the disposition of exactly one message for exactly one recipient\"")]
    public async Task Two_local_recipients_give_two_MDNs_one_for_each()
    {

        var marker = Marker();

        await Deliver(Sender, Message(marker), "<alice@hermod.test>", "<bob@hermod.test>");

        var finalRecipients = Mdns(marker).Select(mdn => Field(mdn.MessageContent, "Final-Recipient")).ToList();

        Assert.That(finalRecipients, Is.EquivalentTo(new[] { "rfc822; alice@hermod.test", "rfc822; bob@hermod.test" }).Using<String>((a, b) => Regex.Replace(a, @"\s", "").Equals(Regex.Replace(b, @"\s", ""), StringComparison.OrdinalIgnoreCase)));

    }


    [Test(Description = "RFC 8098 §2.1: \"A user agent MUST NOT issue more than one MDN on behalf of each particular recipient. That is, once an MDN has been issued on behalf of a recipient, no further MDNs may be issued on behalf of that recipient\" - a recipient the client names twice (RCPT TO twice, the same path: RFC 5321 forbids it nowhere) is one recipient, with one MDN")]
    [Property("Finding", "K-11")]
    public async Task A_recipient_named_twice_gives_one_MDN()
    {

        var marker = Marker();

        await Deliver(Sender, Message(marker), "<alice@hermod.test>", "<alice@hermod.test>");

        Assert.That(Mdns(marker), Has.Count.EqualTo(1), $"\n--- server log ---\n{Server.Log}");

    }

    #endregion


    #region The format

    [Test(Description = "RFC 8098 §3: a multipart/report (RFC 6522) whose \"report-type parameter ... is \"disposition-notification\"\", the first component human-readable, the second message/disposition-notification")]
    public async Task The_MDN_is_a_multipart_report_of_report_type_disposition_notification()
    {

        var marker  = Marker();

        await Deliver(Sender, Message(marker));

        var content     = Mdn(marker).MessageContent;
        var contentType = ReportMail.Headers(content).GetValueOrDefault("Content-Type") ?? "";
        var parts       = ReportMail.Parts(content);

        Assert.Multiple(() => {
            Assert.That(contentType.Split(';')[0].Trim(),                   Is.EqualTo("multipart/report").IgnoreCase);
            Assert.That(ReportMail.Parameter(contentType, "report-type"),   Is.EqualTo("disposition-notification").IgnoreCase);
            Assert.That(parts.Count,                                        Is.InRange(2, 3), "two or three parts (RFC 6522 §3)");
            Assert.That(parts[0].ContentType.Split(';')[0].Trim(),          Does.StartWith("text/").IgnoreCase, "a human-readable first part");
            Assert.That(parts[1].ContentType.Split(';')[0].Trim(),          Is.EqualTo("message/disposition-notification").IgnoreCase);
        });

    }


    [Test(Description = "RFC 8098 §3: \"The MDN MUST be addressed (in both the message header field and the transport envelope) to the address(es) from the Disposition-Notification-To header field\"; \"The From header field of the MDN MUST contain the address of the person for whom the message disposition notification is being issued\"")]
    public async Task The_MDN_goes_to_the_requester_from_the_recipient()
    {

        var marker  = Marker();

        await Deliver(Sender, Message(marker, "Sender <sender@client.example>"));

        var mdn     = Mdn(marker);
        var headers = ReportMail.Headers(mdn.MessageContent);

        Assert.Multiple(() => {
            Assert.That(mdn.EnvelopeTo,                                                       Is.EqualTo(new[] { Sender }));
            Assert.That(MailboxAddress.ParseList(headers.GetValueOrDefault("To")).Select(m => m.Address),   Is.EqualTo(new[] { Sender }));
            Assert.That(MailboxAddress.ParseList(headers.GetValueOrDefault("From")).Select(m => m.Address), Is.EqualTo(new[] { "alice@hermod.test" }));
        });

    }


    [Test(Description = "RFC 8098 §3: \"The envelope sender address (i.e., SMTP \"MAIL FROM\") of the MDN MUST be null (<>)\"")]
    [Property("Finding", "K-3")]
    public async Task The_MDN_is_sent_from_the_null_reverse_path()
    {

        var marker = Marker();

        await Deliver(Sender, Message(marker));

        Assert.That(Mdn(marker).EnvelopeFrom, Is.Empty.Or.EqualTo("<>"));

    }


    [Test(Description = "RFC 8098 §3: \"A message disposition notification MUST NOT itself request an MDN\"; \"The Message-ID header field (if present) for an MDN MUST be different from the Message-ID of the message\"")]
    public async Task The_MDN_asks_for_no_MDN_and_has_a_Message_ID_of_its_own()
    {

        var marker  = Marker();

        await Deliver(Sender, Message(marker));

        var headers = ReportMail.Headers(Mdn(marker).MessageContent);

        Assert.Multiple(() => {
            Assert.That(headers.ContainsKey("Disposition-Notification-To"),  Is.False);
            Assert.That(headers.GetValueOrDefault("Message-ID"),             Is.Not.EqualTo($"<{marker}@client.example>"));
        });

    }


    [Test(Description = "RFC 8098 §3.2.4: \"This field MUST be present\" - Final-Recipient: address-type \";\" generic-address, the recipient \"as it was\", the case of its letters \"MUST be preserved\"")]
    public async Task Final_Recipient_names_the_recipient_as_it_was_written()
    {

        var marker = Marker();

        await Deliver(Sender, Message(marker), "<Alice.Liddell@hermod.test>");

        Assert.That(Field(Mdn(marker).MessageContent, "Final-Recipient"), Does.Match(@"^rfc822[ \t]*;[ \t]*Alice\.Liddell@hermod\.test$"));

    }


    [Test(Description = "RFC 8098 §3.2.5: Original-Message-ID \"MUST be present if and only if the original message contained a Message-ID header field\" - with it")]
    public async Task Original_Message_ID_names_the_message()
    {

        var marker = Marker();

        await Deliver(Sender, Message(marker));

        Assert.That(Field(Mdn(marker).MessageContent, "Original-Message-ID"), Is.EqualTo($"<{marker}@client.example>"));

    }


    [Test(Description = "RFC 8098 §3.2.5: Original-Message-ID \"MUST be present if and only if the original message contained a Message-ID header field\" - without it")]
    public async Task Without_a_Message_ID_there_is_no_Original_Message_ID()
    {

        var marker = Marker();

        await Deliver(Sender, Message(marker, WithMessageId: false));

        Assert.That(Field(Mdn(marker).MessageContent, "Original-Message-ID"), Is.Null);

    }


    [Test(Description = "RFC 8098 §3.2.6: \"This field MUST be present\" - disposition-mode \";\" disposition-type; a delivery agent's own MDN is automatic-action/MDN-sent-automatically (§3.2.6.1), not displayed (§3.2.6.2: \"displayed by the MUA to someone reading\")")]
    public async Task The_Disposition_field_follows_the_grammar_and_says_what_happened()
    {

        var marker      = Marker();

        await Deliver(Sender, Message(marker));

        var disposition = DispositionField.Match(Field(Mdn(marker).MessageContent, "Disposition") ?? "");

        Assert.Multiple(() => {
            Assert.That(disposition.Success,                     Is.True, Report(Mdn(marker).MessageContent));
            Assert.That(disposition.Groups["action"].Value,      Is.EqualTo("automatic-action").IgnoreCase);
            Assert.That(disposition.Groups["sending"].Value,     Is.EqualTo("MDN-sent-automatically").IgnoreCase);
            Assert.That(disposition.Groups["type"].Value,        Is.Not.EqualTo("displayed").IgnoreCase);
        });

    }


    [Test(Description = "RFC 8098 §3.2.1: reporting-ua-field = \"Reporting-UA\" \":\" OWS ua-name OWS [ \";\" OWS ua-product OWS ], ua-name without a semicolon; §3.1: the fields are 7bit")]
    public async Task Reporting_UA_follows_the_grammar_and_the_report_is_7bit()
    {

        var marker = Marker();

        await Deliver(Sender, Message(marker));

        var content = Mdn(marker).MessageContent;

        Assert.Multiple(() => {
            Assert.That(Field(content, "Reporting-UA"),       Does.Match(@"^[^;\r\n]*(;[^\r\n]*)?$"));
            Assert.That(Report(content).All(c => c < 0x80),    Is.True, "US-ASCII");
        });

    }


    [Test(Description = "RFC 8098 §3.2.3: \"If there is an Original-Recipient header field in the message ... then the Original-Recipient field MUST be included\"")]
    [Property("Finding", "K-5")]
    public async Task Original_Recipient_is_taken_from_the_message()
    {

        var marker = Marker();

        await Deliver(Sender, Message(marker, MoreHeaders: "Original-Recipient: rfc822;alias@hermod.test\r\n"));

        Assert.That(Field(Mdn(marker).MessageContent, "Original-Recipient") ?? "(no Original-Recipient field)", Does.Match(@"^rfc822[ \t]*;[ \t]*alias@hermod\.test$"));

    }


    [Test(Description = "RFC 8098 §3.2.3: \"if information about the original recipient is reliably available some other way, then the Original-Recipient field MUST be included\" - §5: as the ORCPT of RFC 3461 carries it")]
    [Property("Finding", "K-5")]
    public async Task Original_Recipient_is_taken_from_ORCPT()
    {

        var marker = Marker();

        await Deliver(Sender, Message(marker), "<alice@hermod.test> ORCPT=rfc822;alias@hermod.test");

        Assert.That(Field(Mdn(marker).MessageContent, "Original-Recipient") ?? "(no Original-Recipient field)", Does.Match(@"^rfc822[ \t]*;[ \t]*alias@hermod\.test$"));

    }


    [Test(Description = "RFC 8098 §2.3: \"if the ORCPT information is available, the delivering MTA SHOULD insert an Original-Recipient header field at the beginning of the message\" - so that the MUA can return it in its MDN")]
    [Property("Finding", "K-9")]
    public async Task The_delivering_server_writes_Original_Recipient_from_ORCPT()
    {

        var marker = Marker();

        await Deliver(Sender, Message(marker, DispositionNotificationTo: null), "<alice@hermod.test> ORCPT=rfc822;alias@hermod.test");

        var stored = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.That(ReportMail.Headers(stored!.Raw).GetValueOrDefault("Original-Recipient") ?? "(no Original-Recipient header field)", Does.Match(@"^rfc822[ \t]*;[ \t]*alias@hermod\.test$"), stored.Raw);

    }


    [Test(Description = "RFC 6522 §4: \"The text/rfc822-headers body part SHOULD contain all the mail header fields from the message\" - its Received fields too, what the returned header is for: \"diagnostics based on the Received header fields\"")]
    [Property("Finding", "K-10")]
    public async Task The_returned_header_has_every_Received_field()
    {

        var marker   = Marker();

        await Deliver(Sender, Message(marker, MoreHeaders: "Received: from relay.client.example by mx.client.example; Fri, 20 Nov 2026 10:00:01 +0100\r\n"));

        var returned = ReportMail.Part(Mdn(marker).MessageContent, "text/rfc822-headers").Text;

        Assert.That(Regex.Matches(returned, @"^Received:", RegexOptions.Multiline | RegexOptions.IgnoreCase), Has.Count.EqualTo(2), "Hermod's own and the one that came with the message\n" + returned);

    }


    [Test(Description = "RFC 5322 §2.2.3: \"Unfolding is accomplished by simply removing any CRLF that is immediately followed by WSP\" - the white space stays; a folded field comes back with its words apart, not run together")]
    [Property("Finding", "K-10")]
    public async Task A_folded_field_is_returned_with_its_white_space()
    {

        var marker   = Marker();

        await Deliver(Sender, Message(marker, MoreHeaders: $"Comments: {marker} first\r\n second\r\n"));

        var returned = ReportMail.Headers(ReportMail.Part(Mdn(marker).MessageContent, "text/rfc822-headers").Text);

        Assert.That(Regex.Replace(returned.GetValueOrDefault("Comments") ?? "(no Comments field)", @"\s+", " "), Is.EqualTo($"{marker} first second"));

    }

    #endregion


    #region Hostile requests

    [Test(Description = "RFC 8098 §2.1: mdn-request-header = \"Disposition-Notification-To\" \":\" mailbox-list - a value that is none asks for nothing; the message is delivered all the same")]
    public async Task A_request_without_a_mailbox_is_delivered_and_not_answered()
    {

        var marker = Marker();

        await Deliver(Sender, Message(marker, "<<<@@@>>> ,,, \"unterminated"));

        Assert.That(Mdns(marker), Is.Empty);

    }


    [Test(Description = "RFC 8098 §6.4: a request naming thousands of addresses is a mail bomb; the message is still taken at once (§2.1: the request \"can\" be ignored), within 15 seconds")]
    public async Task A_request_naming_5000_addresses_does_not_hold_up_delivery()
    {

        var marker    = Marker();
        var addresses = String.Join(",\r\n ", Enumerable.Range(0, 5000).Select(i => $"victim{i}@elsewhere.example"));

        await Deliver(Sender, Message(marker, addresses)).WaitAsync(TimeSpan.FromSeconds(15));

    }


    [Test(Description = "RFC 5322 §3.2.2: comments nest - 20000 open parentheses in Disposition-Notification-To are parsed in time, within 15 seconds, and the message is delivered")]
    public async Task Deeply_nested_comments_in_the_request_do_not_hold_up_delivery()
    {

        var marker  = Marker();
        var nesting = String.Join("\r\n ", Enumerable.Repeat(new String('(', 1000), 20));

        await Deliver(Sender, Message(marker, Sender + " " + nesting)).WaitAsync(TimeSpan.FromSeconds(15));

    }


    [Test(Description = "RFC 5322 §2.2.3: a field may be folded onto any number of lines - one folded onto 240000 lines (under 1 MB) is read in time and the message answered within 10 seconds; without EnableAutoMdn it takes well under one")]
    [Property("Finding", "K-2")]
    public async Task A_field_folded_onto_240000_lines_does_not_hold_up_delivery()
    {

        var marker = Marker();
        var folded = "X-Filler: a" + String.Concat(Enumerable.Repeat("\r\n x", 240_000)) + "\r\n";

        await Deliver(Sender, Message(marker, MoreHeaders: folded)).WaitAsync(TimeSpan.FromSeconds(15));

    }

    #endregion

}


/// <summary>
/// RFC 8098 as an application meets it in Hermod's API for mail user agents: who asks for a
/// receipt and whether sending one needs the reader's consent
/// (<see cref="DispositionNotification.RequestedBy"/>, <see cref="DispositionNotification.GoesElsewhere"/>,
/// §2.1), the receipt a reader confirms (<see cref="DispositionNotification.Build"/>) and the
/// one <see cref="EMail.CreateReadReceipt"/> writes (§3, §3.2) - each read with the suite's
/// own MIME reader.
/// </summary>
[TestFixture]
public sealed class DispositionNotificationApiTests
{

    #region Setup

    private static readonly DateTimeOffset displayed = new (2026, 11, 20, 9, 30, 0, TimeSpan.FromHours(1));

    private static String Raw(String  DispositionNotificationTo,
                              String  From         = "Bernd <bernd@example.net>",
                              String  MoreHeaders  = "")

        => $"From: {From}\r\n" +
           "To: anna@example.test\r\n" +
           "Subject: Termin\r\n" +
           "Date: Fri, 20 Nov 2026 09:00:00 +0100\r\n" +
           "Message-ID: <original@example.net>\r\n" +
           $"Disposition-Notification-To: {DispositionNotificationTo}\r\n" +
           MoreHeaders +
           "\r\nHallo\r\n";

    private static MimeMessage Message(String DispositionNotificationTo, String From = "Bernd <bernd@example.net>", String MoreHeaders = "")
        => MimeMessage.Parse(Encoding.UTF8.GetBytes(Raw(DispositionNotificationTo, From, MoreHeaders)));

    private static String Built(MimeMessage Message)
        => Encoding.UTF8.GetString(DispositionNotification.Build(Message, new MailboxAddress(null, "anna@example.test"), "Conformance", displayed).ToBytes());

    #endregion


    #region RequestedBy, GoesElsewhere

    [Test(Description = "RFC 8098 §2.1: Disposition-Notification-To names where the MDN goes; RequestedBy says who asked")]
    public void RequestedBy_names_the_address_that_asked()
    {

        Assert.That(DispositionNotification.RequestedBy(Message("Bernd <bernd@example.net>"))?.Address, Is.EqualTo("bernd@example.net"));

    }


    [TestCase("bernd@example.net",        "bernd@example.net",      Description = "the same address")]
    [TestCase("bernd@EXAMPLE.NET",        "bernd@example.net",      Description = "the domain in capitals")]
    [Test(Description = "RFC 8098 §2.1: the addr-spec of Disposition-Notification-To compared with the Return-Path, \"case insensitive for the domain part\" - the same: no consent needed")]
    public void The_reverse_paths_own_address_does_not_go_elsewhere(String DispositionNotificationTo, String EnvelopeFrom)
    {

        var message = Message(DispositionNotificationTo, From: "Bernd <bernd@example.net>");

        Assert.That(DispositionNotification.GoesElsewhere(message, DispositionNotification.RequestedBy(message)!, EnvelopeFrom), Is.False);

    }


    [Test(Description = "RFC 8098 §2.1: \"MDNs MUST NOT be sent automatically if the address in the Disposition-Notification-To header field differs from the address in the Return-Path header field\" - another address goes elsewhere")]
    public void A_third_party_goes_elsewhere()
    {

        var message = Message("tracker@collect.example");

        Assert.That(DispositionNotification.GoesElsewhere(message, DispositionNotification.RequestedBy(message)!, "bernd@example.net"), Is.True);

    }


    private static IEnumerable<TestCaseData> RequestsThatNeedConsent()
    {

        yield return new TestCaseData("Bernd@example.net", "bernd@example.net").
                         SetName("{m}(a local-part in another case)").
                         SetProperty("Finding", "K-7");

        yield return new TestCaseData("bernd@example.net", null).
                         SetName("{m}(no Return-Path)").
                         SetProperty("Finding", "K-7");

        yield return new TestCaseData("bernd@example.net", "").
                         SetName("{m}(a null Return-Path)").
                         SetProperty("Finding", "K-7");

        yield return new TestCaseData("bernd@example.net, tracker@collect.example", "bernd@example.net").
                         SetName("{m}(two distinct addresses)").
                         SetProperty("Finding", "K-7");

    }

    [TestCaseSource(nameof(RequestsThatNeedConsent))]
    [Test(Description = "RFC 8098 §2.1: the local-part compared \"case sensitive\"; \"Confirmation from the user MUST be obtained (or no MDN sent) if there is no Return-Path header field in the message or if there is more than one distinct address in the Disposition-Notification-To header field\"")]
    public void A_request_the_RFC_wants_confirmed_goes_elsewhere(String DispositionNotificationTo, String? EnvelopeFrom)
    {

        var message = Message(DispositionNotificationTo, From: "Bernd <bernd@example.net>");

        Assert.That(DispositionNotification.GoesElsewhere(message, DispositionNotification.RequestedBy(message)!, EnvelopeFrom), Is.True);

    }

    #endregion


    #region Build

    [Test(Description = "RFC 8098 §3: multipart/report, report-type=disposition-notification; §3.2.4, §3.2.5, §3.2.6: Final-Recipient, Original-Message-ID, and the reader's manual-action/MDN-sent-manually")]
    public void A_confirmed_receipt_is_a_disposition_notification_about_the_message()
    {

        var receipt     = Built(Message("Bernd <bernd@example.net>"));
        var contentType = ReportMail.Headers(receipt).GetValueOrDefault("Content-Type") ?? "";
        var disposition = DispositionNotificationTests.DispositionField.Match(DispositionNotificationTests.Field(receipt, "Disposition") ?? "");

        Assert.Multiple(() => {
            Assert.That(contentType.Split(';')[0].Trim(),                                   Is.EqualTo("multipart/report").IgnoreCase);
            Assert.That(ReportMail.Parameter(contentType, "report-type"),                   Is.EqualTo("disposition-notification").IgnoreCase);
            Assert.That(ReportMail.Headers(receipt).ContainsKey("Disposition-Notification-To"), Is.False, "§3: an MDN MUST NOT request one");
            Assert.That(DispositionNotificationTests.Field(receipt, "Final-Recipient"),     Does.Match(@"^rfc822[ \t]*;[ \t]*anna@example\.test$"));
            Assert.That(DispositionNotificationTests.Field(receipt, "Original-Message-ID"), Is.EqualTo("<original@example.net>"));
            Assert.That(disposition.Success,                                                Is.True, DispositionNotificationTests.Report(receipt));
            Assert.That(disposition.Groups["action"].Value,                                 Is.EqualTo("manual-action").IgnoreCase);
            Assert.That(disposition.Groups["sending"].Value,                                Is.EqualTo("MDN-sent-manually").IgnoreCase);
        });

    }


    [Test(Description = "RFC 8098 §3: \"The MDN MUST be addressed ... to the address(es) from the Disposition-Notification-To header field\" - every one of them, once the reader confirmed")]
    [Property("Finding", "K-6")]
    public void A_confirmed_receipt_goes_to_every_address_that_asked()
    {

        var receipt = Built(Message("bernd@example.net, Carla <carla@example.org>"));

        Assert.That(MailboxAddress.ParseList(ReportMail.Headers(receipt).GetValueOrDefault("To")).Select(m => m.Address),
                    Is.EquivalentTo(new[] { "bernd@example.net", "carla@example.org" }));

    }


    [Test(Description = "RFC 8098 §3.2.3: \"If there is an Original-Recipient header field in the message ... then the Original-Recipient field MUST be included\"")]
    [Property("Finding", "K-5")]
    public void A_confirmed_receipt_returns_the_Original_Recipient()
    {

        var receipt = Built(Message("bernd@example.net", MoreHeaders: "Original-Recipient: rfc822;team@example.test\r\n"));

        Assert.That(DispositionNotificationTests.Field(receipt, "Original-Recipient") ?? "(no Original-Recipient field)", Does.Match(@"^rfc822[ \t]*;[ \t]*team@example\.test$"));

    }

    #endregion


    #region CreateReadReceipt

    private static String CreateReadReceipt(String Raw, MessageDisposition? Disposition = null)
    {

        var mail = EMail.Parse(Raw.Split("\r\n"));
        var mdn  = mail.CreateReadReceipt((EMailAddress) SimpleEMailAddress.Parse("anna@example.test"), Disposition);

        Assert.That(mdn, Is.Not.Null, "a receipt was asked for");

        return String.Join("\r\n", mdn!.ToText());

    }


    [Test(Description = "RFC 8098 §3, §3.2: the read receipt a client writes - multipart/report of report-type disposition-notification, to the requester, from the reader, Final-Recipient, Original-Message-ID, a Disposition after the grammar")]
    public void CreateReadReceipt_writes_a_disposition_notification()
    {

        var receipt     = CreateReadReceipt(Raw("Bernd <bernd@example.net>"), MessageDisposition.DisplayedManually);
        var headers     = ReportMail.Headers(receipt);
        var contentType = headers.GetValueOrDefault("Content-Type") ?? "";

        Assert.Multiple(() => {
            Assert.That(contentType.Split(';')[0].Trim(),                                    Is.EqualTo("multipart/report").IgnoreCase);
            Assert.That(ReportMail.Parameter(contentType, "report-type"),                    Is.EqualTo("disposition-notification").IgnoreCase);
            Assert.That(MailboxAddress.ParseList(headers.GetValueOrDefault("To")).Select(m => m.Address),   Is.EqualTo(new[] { "bernd@example.net" }));
            Assert.That(MailboxAddress.ParseList(headers.GetValueOrDefault("From")).Select(m => m.Address), Is.EqualTo(new[] { "anna@example.test" }));
            Assert.That(headers.ContainsKey("Disposition-Notification-To"),                  Is.False);
            Assert.That(headers.GetValueOrDefault("Message-ID"),                             Is.Not.EqualTo("<original@example.net>"));
            Assert.That(DispositionNotificationTests.Field(receipt, "Final-Recipient"),      Does.Match(@"^rfc822[ \t]*;[ \t]*anna@example\.test$"));
            Assert.That(DispositionNotificationTests.Field(receipt, "Original-Message-ID"),  Is.EqualTo("<original@example.net>"));
            Assert.That(DispositionNotificationTests.Field(receipt, "Disposition"),          Does.Match(DispositionNotificationTests.DispositionField.ToString()).IgnoreCase);
        });

    }


    [Test(Description = "RFC 8098 §3.2.6.1: manual-action - \"in order to preserve the user's privacy, this MUST be the default for MUAs\"; MDN-sent-manually - \"this MUST be the default for MUAs\"")]
    [Property("Finding", "K-8")]
    public void CreateReadReceipt_defaults_to_manual_action_and_MDN_sent_manually()
    {

        var receipt     = CreateReadReceipt(Raw("bernd@example.net"));
        var disposition = DispositionNotificationTests.DispositionField.Match(DispositionNotificationTests.Field(receipt, "Disposition") ?? "");

        Assert.Multiple(() => {
            Assert.That(disposition.Groups["action"].Value,   Is.EqualTo("manual-action").IgnoreCase);
            Assert.That(disposition.Groups["sending"].Value,  Is.EqualTo("MDN-sent-manually").IgnoreCase);
        });

    }

    #endregion

}
