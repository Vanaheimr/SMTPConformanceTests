using System.Text;
using System.Text.RegularExpressions;

using NUnit.Framework;

using SMTPConformance.Core;

using org.GraphDefined.Vanaheimr.Hermod.Mail;

namespace SMTPConformance.MessageFormat.Tests;

/// <summary>
/// What a part is when the reader does not know its subtype, and the message a message
/// carries: RFC 2046 §4.1.4 a text of a subtype the reader does not know, §5.2.4 a message
/// of one, §5.2.1 message/rfc822 and RFC 6532 §3.7 message/global, and RFC 2045 §2.7, §2.8,
/// §6.2 what 7bit and 8bit promise of the octets. Read by <see cref="MimeMessage"/>, written
/// by <see cref="MimeAttachedMessage"/>.
/// </summary>
[TestFixture]
public sealed class MessagePartsTests
{

    private static MimeMessage Parse(String Message)
        => MimeMessage.Parse(Encoding.UTF8.GetBytes(Message.ReplaceLineEndings("\r\n")));

    /// <summary>
    /// The header of an entity as it is written, unfolded, one field a line.
    /// </summary>
    private static String[] HeaderOf(MimeEntity Entity)
    {
        var octets = Encoding.UTF8.GetString(Entity.ToBytes());
        return Regex.Replace(octets[..octets.IndexOf("\r\n\r\n", StringComparison.Ordinal)], "\r\n(?=[ \t])", "").Split("\r\n");
    }

    private static String? Field(String[] Header, String Name)
        => Header.FirstOrDefault(line => line.StartsWith(Name + ":", StringComparison.OrdinalIgnoreCase)) is { } line
               ? line[(Name.Length + 1)..].Trim()
               : null;


    #region E-26: a text of a subtype the reader does not know

    private static IEnumerable<TestCaseData> TextsOfAnUnknownSubtype()
    {

        TestCaseData Case(String Name, String Message, Int32[] Path)
            => new TestCaseData(Message, Path).SetName($"A text of a subtype the reader does not know is text: {Name}")
                                              .SetProperty("Finding", "E-26");

        yield return Case("text/markdown, the message", """
            From: author@example.org
            To: recipient@example.net
            Subject: Notes
            MIME-Version: 1.0
            Content-Type: text/markdown; charset=utf-8

            # The notes

            *Read them.*

            """, []);

        yield return Case("text/x-log, the message", """
            From: author@example.org
            To: recipient@example.net
            Subject: The log
            MIME-Version: 1.0
            Content-Type: text/x-log; charset=us-ascii

            12:00 started
            12:01 stopped

            """, []);

        yield return Case("text/markdown, the first part of a multipart/mixed", """
            From: author@example.org
            To: recipient@example.net
            Subject: Notes and a picture
            MIME-Version: 1.0
            Content-Type: multipart/mixed; boundary="b1"

            --b1
            Content-Type: text/markdown; charset=utf-8

            # The notes
            --b1
            Content-Type: image/png
            Content-Transfer-Encoding: base64
            Content-Disposition: attachment; filename="picture.png"

            iVBORw0KGgo=
            --b1--

            """, [ 0 ]);

    }

    [TestCaseSource(nameof(TextsOfAnUnknownSubtype))]
    [Description("RFC 2046 §4.1.4: \"Unrecognized subtypes of \"text\" should be treated as subtype \"plain\" as long as the MIME implementation knows how to handle the charset\"")]
    public void A_text_of_an_unknown_subtype_is_text(String Message, Int32[] Path)
    {

        var message = Parse(Message);
        var part    = Path.Aggregate(message.Root, (entity, index) => entity.Children[index]);

        Assert.Multiple(() => {
            Assert.That(message.TextBody,     Is.SameAs(part));
            Assert.That(message.Attachments,  Does.Not.Contain(part));
        });

    }

    [Test(Description = "RFC 2046 §4.1.3: text/plain is the body; RFC 2183 §2.2: a text of another subtype marked attachment, with a file name, is listed as one - a guard for E-26")]
    public void A_text_marked_attachment_is_listed_whatever_its_subtype()
    {

        var message = Parse("""
            From: author@example.org
            To: recipient@example.net
            Subject: An invitation
            MIME-Version: 1.0
            Content-Type: multipart/mixed; boundary="b1"

            --b1
            Content-Type: text/plain; charset=us-ascii

            You are invited.
            --b1
            Content-Type: text/calendar; charset=utf-8; method=REQUEST
            Content-Disposition: attachment; filename="invite.ics"

            BEGIN:VCALENDAR
            END:VCALENDAR
            --b1--

            """);

        Assert.Multiple(() => {
            Assert.That(message.TextBody,     Is.SameAs(message.Root.Children[0]));
            Assert.That(message.Attachments,  Is.EqualTo(new[] { message.Root.Children[1] }));
        });

    }

    #endregion

    #region E-27: a message of a subtype the reader does not know

    private static IEnumerable<TestCaseData> MessagesOfAnUnknownSubtype()
    {

        TestCaseData Case(String Subtype, String Content)
            => new TestCaseData(Subtype, Content).SetName($"A message part of a subtype the reader does not know is an attachment: message/{Subtype}")
                                                 .SetProperty("Finding", "E-27");

        yield return Case("http",      "GET /index.html HTTP/1.1\r\nHost: example.org\r\n");
        yield return Case("sipfrag",   "SIP/2.0 200 OK\r\n");
        yield return Case("x-example", "Anything.\r\n");

    }

    private static String WithMessagePart(String Subtype, String Content) => $"""
        From: author@example.org
        To: recipient@example.net
        Subject: What the server said
        MIME-Version: 1.0
        Content-Type: multipart/mixed; boundary="b1"

        --b1
        Content-Type: text/plain; charset=us-ascii

        See the part below.
        --b1
        Content-Type: message/{Subtype}

        {Content}
        --b1--

        """;

    [TestCaseSource(nameof(MessagesOfAnUnknownSubtype))]
    [Description("RFC 2046 §5.2.4: \"MIME implementations must in general treat unrecognized subtypes of \"message\" as being equivalent to \"application/octet-stream\"\" - which is an attachment; it is neither the text nor lost")]
    public void A_message_part_of_an_unknown_subtype_is_an_attachment(String Subtype, String Content)
    {

        var message = Parse(WithMessagePart(Subtype, Content));

        Assert.Multiple(() => {
            Assert.That(message.TextBody,     Is.SameAs(message.Root.Children[0]));
            Assert.That(message.Attachments,  Is.EqualTo(new[] { message.Root.Children[1] }));
        });

    }

    [Test(Description = "RFC 2046 §5.2.1: a message/rfc822 part is an attachment, its message read - a guard for E-27")]
    public void A_forwarded_message_is_an_attachment()
    {

        var message = Parse(WithMessagePart("rfc822", "From: other@example.net\r\nSubject: Forwarded\r\n\r\nThe text.\r\n"));

        Assert.Multiple(() => {
            Assert.That(message.Attachments,                                Is.EqualTo(new[] { message.Root.Children[1] }));
            Assert.That(message.Root.Children[1].EmbeddedMessage?.Subject,  Is.EqualTo("Forwarded"));
        });

    }

    [Test(Description = "RFC 3464 §2, RFC 6522 §3: the delivery-status of a bounce is its machine-readable part, not something attached - a guard for E-27")]
    public void The_report_parts_of_a_bounce_are_no_attachments()
    {

        var message = Parse("""
            From: MAILER-DAEMON@example.org
            To: author@example.net
            Subject: Undelivered Mail
            MIME-Version: 1.0
            Content-Type: multipart/report; report-type=delivery-status; boundary="b1"

            --b1
            Content-Type: text/plain; charset=us-ascii

            The mail could not be delivered.
            --b1
            Content-Type: message/delivery-status

            Reporting-MTA: dns; example.org

            Final-Recipient: rfc822; nobody@example.net
            Action: failed
            Status: 5.1.1
            --b1
            Content-Type: text/rfc822-headers

            From: author@example.net
            Subject: Hello
            --b1--

            """);

        Assert.Multiple(() => {
            Assert.That(message.TextBody,     Is.SameAs(message.Root.Children[0]));
            Assert.That(message.Attachments,  Is.Empty);
        });

    }

    #endregion

    #region E-28: an attached message with UTF-8 in its header

    private static IEnumerable<TestCaseData> MessagesWithUtf8InTheirHeader()
    {

        TestCaseData Case(String Name, String Message)
            => new TestCaseData(Message).SetName($"An attached message with UTF-8 in its header is message/global: {Name}")
                                        .SetProperty("Finding", "E-28");

        yield return Case("the subject",           "From: other@example.net\r\nSubject: Grüße aus Jena\r\n\r\nThe text.\r\n");
        yield return Case("the name of From",      "From: Jürgen Müller <other@example.net>\r\nSubject: Hello\r\n\r\nThe text.\r\n");
        yield return Case("the address of From",   "From: jürgen@bücher.example\r\nSubject: Hello\r\n\r\nThe text.\r\n");

    }

    [TestCaseSource(nameof(MessagesWithUtf8InTheirHeader))]
    [Description("RFC 6532 §3.7: a message is a \"message/global message\" if \"it contains 8-bit UTF-8 header values\", and message/global is the media type for one; RFC 2046 §5.2.1: message/rfc822 has \"the syntax of an RFC 822 message\" - its header US-ASCII (RFC 5322 §2.2)")]
    public void An_attached_message_with_UTF_8_in_its_header_is_message_global(String Message)
    {

        var header = HeaderOf(new MimeAttachedMessage(Encoding.UTF8.GetBytes(Message)));

        Assert.That(Field(header, "Content-Type"), Does.StartWith("message/global").IgnoreCase);

    }

    [Test(Description = "RFC 2046 §5.2.1: a message whose header is US-ASCII is message/rfc822 - its body in UTF-8 or not - a guard for E-28")]
    public void An_attached_message_with_an_ASCII_header_is_message_rfc822()
    {

        var header = HeaderOf(new MimeAttachedMessage(Encoding.UTF8.GetBytes("From: other@example.net\r\nSubject: Hello\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nGrüße.\r\n")));

        Assert.That(Field(header, "Content-Type"), Is.EqualTo("message/rfc822").IgnoreCase);

    }

    [Test(Description = "RFC 6532 §3.7: a message/global part is read as the message it carries - a guard for E-28")]
    public void A_message_global_part_is_read_as_its_message()
    {

        var message = Parse(WithMessagePart("global", "From: other@example.net\r\nSubject: Grüße\r\n\r\nThe text.\r\n"));

        Assert.That(message.Root.Children[1].EmbeddedMessage?.Subject, Is.EqualTo("Grüße"));

    }

    #endregion

    #region E-29: an attached message that is no 7bit and no 8bit data

    private static IEnumerable<TestCaseData> MessagesThatAreBinary()
    {

        TestCaseData Case(String Name, Byte[] Message)
            => new TestCaseData(Message).SetName($"An attached message that is no 7bit and no 8bit data is binary: {Name}")
                                        .SetProperty("Finding", "E-29");

        var head = "From: other@example.net\r\nSubject: Hello\r\n\r\n";

        yield return Case("a line of 1000 US-ASCII octets",  Encoding.ASCII.GetBytes(head + new String('a', 1000) + "\r\n"));
        yield return Case("a line of 1000 octets, 8-bit",     Encoding.UTF8.GetBytes(head + "Grüße " + new String('a', 1000) + "\r\n"));
        yield return Case("a NUL",                            [ .. Encoding.ASCII.GetBytes(head + "a"), 0, .. Encoding.ASCII.GetBytes("b\r\n") ]);

    }

    [TestCaseSource(nameof(MessagesThatAreBinary))]
    [Description("RFC 2045 §2.7, §2.8: 7bit and 8bit data are \"relatively short lines with 998 octets or less between CRLF line separation sequences\", and \"no NULs are allowed\"; §2.9: binary data is data \"where any sequence of octets whatsoever is allowed\"; §6.2: \"7bit\", \"8bit\" and \"binary\" \"serve simply as indicators of the domain of the body data\" - and RFC 2046 §5.2.1 permits message/rfc822 no encoding but these three")]
    public void An_attached_message_that_is_no_7bit_and_no_8bit_data_is_binary(Byte[] Message)
    {

        var header = HeaderOf(new MimeAttachedMessage(Message));

        Assert.That(Field(header, "Content-Transfer-Encoding"), Is.EqualTo("binary").IgnoreCase);

    }

    [Test(Description = "RFC 2045 §2.7: short lines of US-ASCII are 7bit data, and a message of them is written 7bit - a guard for E-29")]
    public void An_attached_message_of_short_US_ASCII_lines_is_7bit()
    {

        var header = HeaderOf(new MimeAttachedMessage(Encoding.ASCII.GetBytes("From: other@example.net\r\nSubject: Hello\r\n\r\n" + new String('a', 998) + "\r\n")));

        Assert.That(Field(header, "Content-Transfer-Encoding"), Is.EqualTo("7bit").IgnoreCase);

    }

    #endregion

}
