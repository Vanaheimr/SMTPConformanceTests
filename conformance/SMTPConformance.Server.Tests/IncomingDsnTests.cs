using System.Text;
using System.Text.RegularExpressions;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// Delivery status notifications (RFC 3464, RFC 6522, RFC 3463) from the other end: the
/// reports other MTAs send to this server. Hermod has no reader for them - BounceInfo and
/// BounceType are used nowhere - so what is tested is what the server does with one that
/// arrives (RFC 3461 §6, RFC 5321 §4.5.5): taken from the null reverse-path, delivered as
/// it is, never answered, relayed with its null reverse-path. And what Hermod reads of a
/// foreign status code to put into a report of its own (<see cref="DsnGenerator.StatusOf"/>).
/// The DSN Hermod writes is read back by the suite's own strict RFC 3464 reader.
/// </summary>
[TestFixture]
public sealed class IncomingDsnTests : HermodServerTestBase
{

    // Relaying without AUTH: the DSN of a foreign MTA for an address elsewhere is relayed.
    protected override HermodSmtpServerFixtureOptions Options
        => new() { RequireAuthForRelay = false };


    #region Setup

    /// <summary>
    /// A DSN as a foreign MTA sends it (RFC 3464 §2, RFC 6522 §3): multipart/report with
    /// report-type=delivery-status, a text part, the message/delivery-status part with the
    /// given per-recipient groups, the returned header.
    /// </summary>
    private static String ForeignDsn(String Marker, Int32 Groups = 1)
    {

        var dsn = new StringBuilder();

        dsn.Append("From: Mail Delivery Subsystem <MAILER-DAEMON@mx.remote.example>\r\n").
            Append("To: <sender@hermod.test>\r\n").
            Append($"Subject: Delivery Status Notification (Failure) {Marker}\r\n").
            Append("Date: Thu, 19 Nov 2026 10:00:00 +0000\r\n").
            Append($"Message-ID: <{Guid.NewGuid():N}@mx.remote.example>\r\n").
            Append("Auto-Submitted: auto-replied\r\n").
            Append("MIME-Version: 1.0\r\n").
            Append("Content-Type: multipart/report; report-type=delivery-status;\r\n\tboundary=\"dsn-boundary-1\"\r\n").
            Append("\r\n").
            Append("--dsn-boundary-1\r\n").
            Append("Content-Type: text/plain; charset=us-ascii\r\n").
            Append("\r\n").
            Append("Your message could not be delivered.\r\n").
            Append("\r\n").
            Append("--dsn-boundary-1\r\n").
            Append("Content-Type: message/delivery-status\r\n").
            Append("\r\n").
            Append("Reporting-MTA: dns; mx.remote.example\r\n").
            Append("Arrival-Date: Thu, 19 Nov 2026 09:59:58 +0000\r\n");

        for (var i = 0; i < Groups; i++)
            dsn.Append("\r\n").
                Append($"Final-Recipient: rfc822; user{i}@remote.example\r\n").
                Append("Action: failed\r\n").
                Append("Status: 5.1.1\r\n").
                Append("Diagnostic-Code: smtp; 550 5.1.1 No such user\r\n");

        dsn.Append("\r\n").
            Append("--dsn-boundary-1\r\n").
            Append("Content-Type: text/rfc822-headers\r\n").
            Append("\r\n").
            Append("From: <sender@hermod.test>\r\n").
            Append("To: <user0@remote.example>\r\n").
            Append("Subject: the message that bounced\r\n").
            Append("\r\n").
            Append("--dsn-boundary-1--\r\n");

        return dsn.ToString();

    }

    private async Task<(RawSmtpClient Client, SmtpReply Mail, SmtpReply Rcpt, SmtpReply? Final)> SendDsnAsync(String Recipient, String Message, String RcptParameters = "")
    {

        var client      = await Server.ConnectAndEhloAsync("mx.remote.example");
        var mail        = await client.CommandAsync("MAIL FROM:<>");
        var rcpt        = await client.CommandAsync($"RCPT TO:<{Recipient}>{RcptParameters}");
        var (_, final)  = rcpt.Code == 250 ? await client.DataAsync(Message) : (rcpt, null);

        return (client, mail, rcpt, final);

    }

    #endregion


    #region A DSN that arrives

    [Test(Description = "RFC 5321 §4.5.5: DSNs (RFC 3461) are \"required by existing and proposed Standards to be sent with a null reverse-path\" - one from MAIL FROM:<> to a local mailbox is taken and delivered as it arrived, its delivery-status part octet for octet")]
    public async Task A_DSN_is_taken_from_the_null_reverse_path_and_delivered_as_it_arrived()
    {

        var marker                       = Marker();
        var message                      = ForeignDsn(marker);
        var (client, mail, rcpt, final)  = await SendDsnAsync("sender@hermod.test", message);
        await using var _client          = client;
        var stored                       = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.Multiple(() => {
            Assert.That((mail.Code, rcpt.Code, final?.Code), Is.EqualTo((250, 250, (Int32?) 250)), Explain(client));
            Assert.That(stored,                               Is.Not.Null, Explain(client));
            Assert.That(stored?.EnvelopeFrom,                 Is.EqualTo("").Or.EqualTo("<>"), "the null reverse-path");
            Assert.That(stored?.Raw,                          Does.EndWith(message), "the message as it arrived, after the trace fields");
        });

    }


    [Test(Description = "RFC 3461 §6: \"A DSN MUST NOT be returned to the sender for any message for which the return address from the SMTP MAIL command was NULL (\"<>\")\" - a DSN delivered here with NOTIFY=SUCCESS,FAILURE gets no report back")]
    public async Task A_DSN_is_never_answered_with_a_DSN()
    {

        var marker                       = Marker();
        var queued                       = Server.Queue.Queued.Count;
        var (client, mail, rcpt, final)  = await SendDsnAsync("sender@hermod.test", ForeignDsn(marker), " NOTIFY=SUCCESS,FAILURE");
        await using var _client          = client;

        await Server.Storage.WaitForMarkerAsync(marker);
        await Task.Delay(200);

        Assert.Multiple(() => {
            Assert.That(final?.Code,               Is.EqualTo(250),     Explain(client));
            Assert.That(Server.Queue.Queued.Count, Is.EqualTo(queued),  "nothing queued: no delivered-DSN to the null reverse-path");
        });

    }


    [Test(Description = "RFC 5321 §4.5.5: systems \"SHOULD NOT add a non-null reverse-path, or change a null reverse-path to a non-null one, to such messages when forwarding\" - a DSN relayed onwards keeps MAIL FROM:<>")]
    public async Task A_relayed_DSN_keeps_its_null_reverse_path()
    {

        var marker                       = Marker();
        var (client, mail, rcpt, final)  = await SendDsnAsync("sender@elsewhere.example", ForeignDsn(marker));
        await using var _client          = client;
        var relayed                      = Server.Queue.Queued.FirstOrDefault(queued => queued.MessageContent.Contains(marker, StringComparison.Ordinal));

        Assert.Multiple(() => {
            Assert.That(final?.Code,             Is.EqualTo(250),                 Explain(client));
            Assert.That(relayed?.EnvelopeFrom,   Is.EqualTo("").Or.EqualTo("<>"), "queued with the null reverse-path");
        });

    }


    [Test(Description = "RFC 3464 §2.1: \"delivery-status-content = per-message-fields 1*( CRLF per-recipient-fields )\" - no upper bound: a DSN with 3000 recipient groups (330 KiB) is taken in time")]
    [CancelAfter(30_000)]
    public async Task A_DSN_with_3000_recipient_groups_is_taken_in_time()
    {

        var marker                       = Marker();
        var (client, mail, rcpt, final)  = await SendDsnAsync("sender@hermod.test", ForeignDsn(marker, Groups: 3000));
        await using var _client          = client;
        var stored                       = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.Multiple(() => {
            Assert.That(final?.Code,  Is.EqualTo(250),  Explain(client));
            Assert.That(stored,       Is.Not.Null,      Explain(client));
        });

    }

    #endregion

    #region The status code of a foreign reply

    [TestCase(550, "550 5.1.1 No such user",           "5.1.1",  TestName = "The status code of 550 5.1.1 is 5.1.1")]
    [TestCase(550, "5.7.1 Relaying denied",            "5.7.1",  TestName = "The status code of a text without its reply code is read")]
    [TestCase(452, "452 4.2.2 Mailbox full",           "4.2.2",  TestName = "The status code of 452 4.2.2 is 4.2.2")]
    [TestCase(450, "450 5.1.1 class of another reply", "4.0.0",  TestName = "A status code of another class than the reply is not taken")]
    [TestCase(550, "550 6.1.1 no such class",          "5.0.0",  TestName = "A class other than 2, 4, 5 is not taken")]
    [TestCase(550, "550 5.1.1000 four digits",         "5.0.0",  TestName = "A detail of four digits is not taken")]
    [TestCase(550, "550 No enhanced code at all",      "5.0.0",  TestName = "Without a status code the class of the reply is X.0.0")]
    [Description("RFC 3463 §2: status-code = class \".\" subject \".\" detail, class = \"2\"/\"4\"/\"5\", subject = 1*3digit, detail = 1*3digit; RFC 3461 §6.3 (g): the Status of a DSN is the status code of the reply, else its class")]
    public void The_status_code_of_a_reply_is_read_as_RFC_3463_writes_it(Int32 Code, String Text, String Status)
    {

        Assert.That(DsnGenerator.StatusOf(Code, Text, Permanent: Code >= 500), Is.EqualTo(Status));

    }


    [TestCase(550, "550 5.01.1 leading zero in the subject",  TestName = "A subject with a leading zero is not taken as it is")]
    [TestCase(550, "550 5.1.01 leading zero in the detail",   TestName = "A detail with a leading zero is not taken as it is")]
    [TestCase(450, "450 4.007.000 leading zeros throughout",  TestName = "Leading zeros throughout are not taken as they are")]
    [Description("RFC 3463 §2 and RFC 3464 §2.3.4: \"Each numeric sub-field within the status-code MUST be expressed without leading zero digits\" - what a next hop sent with leading zeros is no status code, and does not go into the Status field of Hermod's DSN as it is")]
    [Category(TestCategories.KnownIssue), Property("Finding", "I-6")]
    public void A_status_code_with_leading_zeros_does_not_go_into_a_DSN(Int32 Code, String Text)
    {

        Assert.That(DsnGenerator.StatusOf(Code, Text, Permanent: Code >= 500), Does.Match(StatusCode));

    }

    private const String StatusCode = @"^[245]\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$";

    #endregion

    #region Reading the DSN Hermod writes

    /// <summary>
    /// The fields of a message/delivery-status body (RFC 3464 §2.1): the per-message group,
    /// then the per-recipient groups - each a list of (name, value), continuation lines
    /// unfolded (§2.1.1), names as written. Throws on what the grammar does not allow: a line
    /// end other than CR LF, a line that is neither a field nor a continuation, no
    /// per-recipient group.
    /// </summary>
    private static (List<(String Name, String Value)> PerMessage, List<List<(String Name, String Value)>> PerRecipient) DeliveryStatus(String Content)
    {

        if (Regex.IsMatch(Content, "\r(?!\n)|(?<!\r)\n"))
            throw new FormatException("a line end other than CR LF");

        var groups = new List<List<(String Name, String Value)>>();
        var group  = new List<(String Name, String Value)>();

        foreach (var line in Content.TrimEnd('\r', '\n').Split("\r\n"))
        {

            if (line.Length == 0)
            {
                if (group.Count > 0)
                    groups.Add(group);
                group = [];
                continue;
            }

            if (line[0] is ' ' or '\t')
            {
                if (group.Count == 0)
                    throw new FormatException($"a continuation line without a field: {line}");
                group[^1] = (group[^1].Name, group[^1].Value + " " + line.Trim());
                continue;
            }

            var field = Regex.Match(line, @"^(?<name>[!-9;-~]+):[ \t]*(?<value>.*?)[ \t]*$");

            if (!field.Success)
                throw new FormatException($"not a field: {line}");

            group.Add((field.Groups["name"].Value, field.Groups["value"].Value));

        }

        if (group.Count > 0)
            groups.Add(group);

        if (groups.Count < 2)
            throw new FormatException("delivery-status-content = per-message-fields 1*( CRLF per-recipient-fields )");

        return (groups[0], groups.Skip(1).ToList());

    }

    private static IReadOnlyList<String> All(IEnumerable<(String Name, String Value)> Group, String Name)
        => [ .. Group.Where(field => field.Name.Equals(Name, StringComparison.OrdinalIgnoreCase)).Select(field => field.Value) ];

    private static String? One(IEnumerable<(String Name, String Value)> Group, String Name)
        => All(Group, Name) is [ var value ] ? value : null;

    // atom (RFC 5322 §3.2.3) ";" text: address-type, diagnostic-type, MTA-name-type (RFC 3464 §2.1.2).
    private const String TypedValue = @"^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+[ \t]*;[ \t]*\S.*$";

    // RFC 5322 §3.3 date-time, numeric zone.
    private const String DateTimeValue = @"^(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), )?\d{1,2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}(?::\d{2})? [+-]\d{4}$";


    [Test(Description = "RFC 3464 §2.1.1: \"Notification fields may be continued onto multiple lines\", \"Field names are case-insensitive\"; §2.1.2: address-type values are case-insensitive - the suite's reader reads a DSN written that way")]
    public void The_suites_reader_reads_folded_fields_in_any_case()
    {

        var (perMessage, perRecipient) = DeliveryStatus("reporting-mta: DNS;\r\n mx.remote.example\r\n\r\nFINAL-RECIPIENT: RFC822;\r\n\tuser@remote.example\r\naction: Failed\r\nstatus: 5.1.1 (no such user)\r\n");

        Assert.Multiple(() => {
            Assert.That(One(perMessage, "Reporting-MTA"),          Is.EqualTo("DNS; mx.remote.example"));
            Assert.That(One(perRecipient[0], "Final-Recipient"),   Does.Match(TypedValue));
            Assert.That(One(perRecipient[0], "Action"),            Is.EqualTo("Failed"));
            Assert.That(One(perRecipient[0], "Status"),            Does.StartWith("5.1.1"));
        });

    }


    [Test(Description = "RFC 6522 §3: multipart/report, \"Required parameters: boundary, report-type\", two or three parts in order - human-readable, then the machine-parsable one (report-type delivery-status: message/delivery-status), then the returned message; RFC 3464 §2.2, §2.3: Reporting-MTA required, and per recipient Final-Recipient, Action, Status (RFC 3463, no leading zeros), each as its grammar says")]
    public void The_DSN_Hermod_writes_reads_as_RFC_3464_and_RFC_6522_define_it()
    {

        var generator = new DsnGenerator(new SMTPServerConfig { Hostname = "mx.hermod.test" });
        var arrival   = new DateTimeOffset(2026, 11, 19, 9, 0, 0, TimeSpan.Zero);
        var octets    = generator.GenerateOctets("sender@client.example", "ENV+2B1", null, arrival,
                                                 Encoding.UTF8.GetBytes("From: <sender@client.example>\r\nTo: <a@remote.example>\r\nSubject: x\r\n\r\nHello.\r\n"),
                                                 [ new DsnRecipient("a@remote.example", DsnAction.Failed,  "5.1.1", "rfc822;A@remote.example", "mx.remote.example",
                                                                    "smtp; 550 5.1.1 No such user", arrival.AddMinutes(1)),
                                                   new DsnRecipient("b@remote.example", DsnAction.Delayed, "4.4.1", null, null,
                                                                    "smtp; 451 4.4.1 Try later", arrival.AddMinutes(1), arrival.AddDays(5)) ]);
        var dsn       = Encoding.UTF8.GetString(octets);

        var headers   = ReportMail.Headers(dsn);
        var parts     = ReportMail.Parts(dsn);
        var (perMessage, perRecipient) = DeliveryStatus(parts[1].Text);

        Assert.Multiple(() => {

            Assert.That(headers["Content-Type"],                                Does.StartWith("multipart/report"));
            Assert.That(ReportMail.Parameter(headers["Content-Type"], "report-type"), Is.EqualTo("delivery-status").IgnoreCase);
            Assert.That(parts,                                                  Has.Count.InRange(2, 3));
            Assert.That(parts[0].ContentType,                                   Does.StartWith("text/"));
            Assert.That(parts[1].ContentType,                                   Is.EqualTo("message/delivery-status"));
            Assert.That(parts[2].ContentType,                                   Is.EqualTo("message/rfc822").Or.EqualTo("text/rfc822-headers"));

            Assert.That(All(perMessage, "Reporting-MTA"),                       Has.Count.EqualTo(1));
            Assert.That(One(perMessage, "Reporting-MTA"),                       Does.Match(TypedValue));
            Assert.That(One(perMessage, "Original-Envelope-Id"),                Is.EqualTo("ENV+1"), "the ENVID, xtext decoded");
            Assert.That(One(perMessage, "Arrival-Date"),                        Does.Match(DateTimeValue));

            Assert.That(perRecipient,                                           Has.Count.EqualTo(2));

            foreach (var group in perRecipient)
            {
                Assert.That(All(group, "Final-Recipient"),                      Has.Count.EqualTo(1));
                Assert.That(One(group, "Final-Recipient"),                      Does.Match(TypedValue));
                Assert.That(One(group, "Action")?.ToLowerInvariant(),           Is.AnyOf("failed", "delayed", "delivered", "relayed", "expanded"));
                Assert.That(One(group, "Status"),                               Does.Match(StatusCode));
                foreach (var value in All(group, "Remote-MTA").Concat(All(group, "Diagnostic-Code")).Concat(All(group, "Original-Recipient")))
                    Assert.That(value,                                          Does.Match(TypedValue));
                foreach (var value in All(group, "Last-Attempt-Date").Concat(All(group, "Will-Retry-Until")))
                    Assert.That(value,                                          Does.Match(DateTimeValue));
            }

            Assert.That(One(perRecipient[0], "Final-Recipient"),                Is.EqualTo("rfc822; a@remote.example"));
            Assert.That(One(perRecipient[0], "Original-Recipient"),             Is.EqualTo("rfc822; A@remote.example"), "case preserved");
            Assert.That((One(perRecipient[0], "Action"), One(perRecipient[0], "Status")), Is.EqualTo(("failed", "5.1.1")));
            Assert.That((One(perRecipient[1], "Action"), One(perRecipient[1], "Status")), Is.EqualTo(("delayed", "4.4.1")));
            Assert.That(All(perRecipient[1], "Will-Retry-Until"),               Has.Count.EqualTo(1));
            Assert.That(All(perRecipient[1], "Original-Recipient"),             Is.Empty, "no ORCPT, no Original-Recipient");

        });

    }

    #endregion

}
