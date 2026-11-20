using System.Globalization;
using System.Text;

using NUnit.Framework;

using SMTPConformance.Core;

using org.GraphDefined.Vanaheimr.Hermod.Mail;

namespace SMTPConformance.MessageFormat.Tests;

/// <summary>
/// The message an application builds with Hermod - <see cref="MimeMessageBuilder"/> and the
/// older <see cref="TextEMailBuilder"/> (whose <see cref="EMail.ToText"/> MailSender sends) -
/// read with the suite's own <see cref="MessageGrammar"/>: RFC 5322 §2.1.1 line lengths, §2.2
/// header fields, §3.3 date-time, §3.6 the number of each field, §3.6.4 msg-id, RFC 2045 §4
/// MIME-Version, RFC 2919 List-ID - and read back by Hermod's own <see cref="MimeMessage"/>.
/// </summary>
[TestFixture]
public sealed class MessageBuilderTests
{

    private static readonly String[] SingularFields = [ "Date", "From", "Sender", "Reply-To", "To", "Cc", "Bcc", "Message-ID", "In-Reply-To", "References", "Subject" ];

    private static MimeMessageBuilder Full(DateTimeOffset? Date = null)
    {

        var builder = new MimeMessageBuilder {
                          From     = new MailboxAddress("Mary Smith", "mary@example.net"),
                          Sender   = new MailboxAddress("Secretary", "secretary@example.net"),
                          Subject  = "Re: Saying Hello, and the agenda of the meeting we talked about on the phone yesterday afternoon",
                          Date     = Date ?? new DateTimeOffset(2026, 11, 20, 10, 15, 30, TimeSpan.FromHours(1)),
                          Body     = new MimeTextPart("This is a reply to your hello.\r\n")
                      };

        for (var i = 1; i <= 8; i++)
            builder.To.Add(new MailboxAddress($"Recipient Number {i}", $"recipient{i}@example.org"));

        builder.Cc.     Add(new MailboxAddress("Müller, Jörg", "joerg@example.de"));
        builder.Bcc.    Add(new MailboxAddress(null, "hidden@example.com"));
        builder.ReplyTo.Add(new MailboxAddress("\"Giant\" Box", "box@example.net"));

        builder.InReplyTo.Add("1234@local.machine.example");

        for (var i = 1; i <= 12; i++)
            builder.References.Add($"thread-message-{i}.0123456789@mail{i}.example.org");

        builder.Headers.Add(("User-Agent", "Hermod conformance suite"));

        return builder;

    }

    private static String Text(MimeMessageBuilder Builder)
        => MessageGrammar.Text(Builder.ToBytes());

    private static Int32 Count(String Message, String Name)
        => MessageGrammar.Fields(Message).Count(field => field.Name.Equals(Name, StringComparison.OrdinalIgnoreCase));


    #region MimeMessageBuilder

    [Test(Description = "RFC 5322 §3.6: \"The only required header fields are the origination date field and the originator address field(s)\" - Date and From exactly once, Sender to Subject at most once; RFC 2045 §4: \"MIME-Version: 1.0\"")]
    public void Every_field_is_there_as_often_as_RFC_5322_says()
    {

        var message = Text(Full());

        Assert.Multiple(() => {

            Assert.That(Count(message, "Date"),  Is.EqualTo(1));
            Assert.That(Count(message, "From"),  Is.EqualTo(1));

            foreach (var name in SingularFields)
                Assert.That(Count(message, name), Is.LessThanOrEqualTo(1), name);

            Assert.That(MessageGrammar.Value(message, "MIME-Version"), Is.EqualTo("1.0"));

        });

    }


    [Test(Description = "RFC 5322 §2.2: a header field is field-name \":\" field-body, the name printable US-ASCII but colon, the body printable US-ASCII and WSP, \"MUST NOT include CR and LF except when used in folding\"; §2.1: lines end in CRLF")]
    public void The_header_is_fields_of_printable_ASCII_in_CRLF_lines()
    {

        var message = Text(Full());
        var header  = MessageGrammar.HeaderSection(message);

        Assert.Multiple(() => {
            Assert.That(MessageGrammar.HasBareLineBreak(message),                              Is.False);
            Assert.That(MessageGrammar.MalformedHeaderLines(message),                          Is.Empty);
            Assert.That(header.Where(character => character is not ('\r' or '\n' or '\t' or (>= ' ' and <= '~'))), Is.Empty);
        });

    }


    [Test(Description = "RFC 5322 §2.1.1: each line \"SHOULD be no more than 78 characters\" - a long subject, eight recipients, twelve references, folded")]
    public void Header_lines_are_folded_to_78_characters()
    {

        var message = Text(Full());

        Assert.That(MessageGrammar.Lines(MessageGrammar.HeaderSection(message)).Where(line => line.Length > 78), Is.Empty);

    }


    [TestCase( 60, TestName = "RFC 5322 §3.3 date-time, zone +0100")]
    [TestCase(-210, TestName = "RFC 5322 §3.3 date-time, zone -0330")]
    [TestCase(  0, TestName = "RFC 5322 §3.3 date-time, zone +0000")]
    [TestCase(345, TestName = "RFC 5322 §3.3 date-time, zone +0545")]
    [Test(Description = "RFC 5322 §3.3: date-time = [ day-of-week \",\" ] date time; \"the day-of-week (if included) MUST be the day implied by the date\"")]
    public void The_Date_is_a_date_time_of_RFC_5322(Int32 OffsetMinutes)
    {

        var date    = new DateTimeOffset(2026, 3, 1, 23, 5, 9, TimeSpan.FromMinutes(OffsetMinutes));
        var value   = MessageGrammar.Value(Text(Full(date)), "Date")!;

        Assert.That(MessageGrammar.DateTime().IsMatch(value), Is.True, value);

        var parsed  = DateTimeOffset.ParseExact(value.Insert(value.Length - 2, ":"), "ddd, d MMM yyyy HH:mm:ss zzz", CultureInfo.InvariantCulture);

        Assert.Multiple(() => {
            Assert.That(parsed,         Is.EqualTo(date));
            Assert.That(parsed.Offset,  Is.EqualTo(date.Offset));
        });

    }


    [Test(Description = "RFC 5322 §3.6.4: msg-id = [CFWS] \"<\" id-left \"@\" id-right \">\" [CFWS] - the Message-ID Hermod makes, and In-Reply-To and References as 1*msg-id")]
    public void Message_ID_In_Reply_To_and_References_are_msg_ids()
    {

        var message = Text(Full());

        Assert.Multiple(() => {

            Assert.That(MessageGrammar.MsgId().IsMatch(MessageGrammar.Value(message, "Message-ID")!), Is.True);

            foreach (var name in new[] { "In-Reply-To", "References" })
            {
                var ids = MessageGrammar.Value(message, name)!.Split([ ' ', '\t' ], StringSplitOptions.RemoveEmptyEntries);
                Assert.That(ids.Where(id => !MessageGrammar.MsgId().IsMatch(id)), Is.Empty, name);
            }

            Assert.That(MessageGrammar.Value(message, "References")!.Split(' ', StringSplitOptions.RemoveEmptyEntries), Has.Length.EqualTo(12));

        });

    }


    [Test(Description = "RFC 5322 §3.6: a message Hermod builds, read back by Hermod - From, To, Cc, Reply-To, Subject, Date, Message-ID, In-Reply-To, References and the text as built")]
    public void A_built_message_reads_back_as_built()
    {

        var builder = Full();
        var message = MimeMessage.Parse(builder.ToBytes());

        Assert.Multiple(() => {
            Assert.That(message.From,                Is.EqualTo(new[] { builder.From }));
            Assert.That(message.To,                  Is.EqualTo(builder.To));
            Assert.That(message.Cc,                  Is.EqualTo(builder.Cc));
            Assert.That(message.ReplyTo,             Is.EqualTo(builder.ReplyTo));
            Assert.That(message.Bcc,                 Is.Empty);
            Assert.That(message.Subject,             Is.EqualTo(builder.Subject));
            Assert.That(message.Date,                Is.EqualTo(builder.Date));
            Assert.That(message.MessageId,           Is.EqualTo(builder.MessageId));
            Assert.That(message.InReplyTo,           Is.EqualTo(builder.InReplyTo));
            Assert.That(message.References,          Is.EqualTo(builder.References));
            Assert.That(message.TextBody?.GetText(), Is.EqualTo("This is a reply to your hello.\r\n"));
        });

    }


    [TestCase("Subject",  "Hello\r\nBcc: everybody@example.org", TestName = "A line break in the Subject is refused")]
    [TestCase("Name",     "Mary\r\nBcc: everybody@example.org",  TestName = "A line break in a display name is refused")]
    [TestCase("Header",   "value\nX-Injected: yes",              TestName = "A bare LF in a further header is refused")]
    [Test(Description = "RFC 5322 §2.2: \"A field body MUST NOT include CR and LF except when used in folding and unfolding\" - a value with a line break is refused, not written")]
    public void A_line_break_in_a_header_value_is_refused(String Where, String Value)
    {

        var builder = Full();

        switch (Where)
        {
            case "Subject": builder.Subject = Value;                                         break;
            case "Name":    builder.From    = new MailboxAddress(Value, "mary@example.net"); break;
            default:        builder.Headers.Add(("X-Note", Value));                          break;
        }

        Assert.That(() => builder.ToBytes(), Throws.ArgumentException);

    }


    public static IEnumerable<TestCaseData> LongLines()
    {

        TestCaseData Case(String name, Func<String> message)
            => new TestCaseData(message).SetName(name).SetCategory(TestCategories.KnownIssue).SetProperty("Finding", "E-3");

        yield return Case("MimeMessageBuilder: a subject holding a URL of 1200 characters", () => {
            var builder = Full();
            builder.Subject = "See https://example.org/" + new String('a', 1200);
            return Text(builder);
        });

        yield return Case("MimeMessageBuilder: an Autocrypt header with 3000 characters of key data", () => {
            var builder = Full();
            builder.Headers.Add(("Autocrypt", "addr=mary@example.net; keydata=" + Convert.ToBase64String(new Byte[2250])));
            return Text(builder);
        });

        yield return Case("MimeMessageBuilder: an attachment named in 120 Chinese characters", () => {
            var builder = Full();
            builder.Body = new MimeMultipart("mixed", [ new MimeTextPart("Attached."), new MimeAttachment(new Byte[] { 1, 2, 3 }, "application/pdf", String.Concat(Enumerable.Repeat("报告", 60)) + ".pdf") ]);
            return Text(builder);
        });

        yield return Case("TextEMailBuilder: a subject holding a URL of 1200 characters", () => {
            var builder = new TextEMailBuilder {
                              From     = EMailAddress.Parse("Mary Smith <mary@example.net>"),
                              Subject  = "See https://example.org/" + new String('a', 1200),
                              Text     = "Hello."
                          };
            builder.To = EMailAddressListBuilder.Create(EMailAddress.Parse("john@example.org")!);
            return String.Join("\r\n", ((EMail) builder).ToText(false));
        });

    }


    [TestCaseSource(nameof(LongLines))]
    [Test(Description = "RFC 5322 §2.1.1: \"Each line of characters MUST be no more than 998 characters\" - a word longer than a line is folded into encoded words, an RFC 2231 parameter into continuations")]
    public void No_line_is_longer_than_998_characters(Func<String> Message)
    {

        var longest = MessageGrammar.LongestLine(Message());

        Assert.That(longest.Length, Is.LessThanOrEqualTo(998), longest[..60] + "...");

    }


    [TestCase("From",        "Mallory <mallory@example.com>",             TestName = "A further From is not written twice")]
    [TestCase("Date",        "Thu, 1 Jan 1970 00:00:00 +0000",            TestName = "A further Date is not written twice")]
    [TestCase("Subject",     "Another subject",                           TestName = "A further Subject is not written twice")]
    [TestCase("Message-ID",  "<another@example.com>",                     TestName = "A further Message-ID is not written twice")]
    [TestCase("To",          "everybody@example.com",                     TestName = "A further To is not written twice")]
    [Test(Description = "RFC 5322 §3.6: orig-date, from, sender, reply-to, to, cc, bcc, message-id, in-reply-to, references and subject have a maximum number of 1 - a further header of that name is refused, or replaces the builder's own")]
    [Category(TestCategories.KnownIssue), Property("Finding", "E-12")]
    public void A_singular_field_among_the_further_headers_is_not_written_twice(String Name, String Value)
    {

        var builder = Full();
        builder.Headers.Add((Name, Value));

        Byte[] octets;

        try
        {
            octets = builder.ToBytes();
        }
        catch (ArgumentException)
        {
            Assert.Pass("refused");
            return;
        }

        Assert.That(Count(MessageGrammar.Text(octets), Name), Is.EqualTo(1));

    }

    #endregion

    #region TextEMailBuilder

    private static TextEMailBuilder OlderBuilder()
    {

        var builder = new TextEMailBuilder {
                          From     = EMailAddress.Parse("Mary Smith <mary@example.net>"),
                          Subject  = "Grüße aus Köln",
                          Text     = "Hello.\r\nZweite Zeile mit Ümlaut.\r\n",
                          Date     = new DateTimeOffset(2026, 11, 20, 10, 15, 30, TimeSpan.FromHours(1))
                      };

        builder.To = EMailAddressListBuilder.Create(EMailAddress.Parse("John Doe <john@example.org>")!);

        return builder;

    }


    [Test(Description = "RFC 5322 §3.6, §3.3, §3.6.4, §2.2 and RFC 2045 §4 for the older TextEMailBuilder: Date and From once, a date-time, a msg-id, fields of printable ASCII in CRLF lines, MIME-Version: 1.0")]
    public void The_older_builders_message_has_its_fields_as_RFC_5322_says()
    {

        var message = String.Join("\r\n", ((EMail) OlderBuilder()).ToText(false));

        Assert.Multiple(() => {

            Assert.That(Count(message, "Date"),  Is.EqualTo(1));
            Assert.That(Count(message, "From"),  Is.EqualTo(1));

            foreach (var name in SingularFields)
                Assert.That(Count(message, name), Is.LessThanOrEqualTo(1), name);

            Assert.That(MessageGrammar.DateTime().IsMatch(MessageGrammar.Value(message, "Date")!),      Is.True);
            Assert.That(MessageGrammar.MsgId().   IsMatch(MessageGrammar.Value(message, "Message-ID")!), Is.True);
            Assert.That(MessageGrammar.Value(message, "MIME-Version"),                                  Is.EqualTo("1.0"));
            Assert.That(MessageGrammar.HasBareLineBreak(message),                                       Is.False);
            Assert.That(MessageGrammar.MalformedHeaderLines(message),                                   Is.Empty);
            Assert.That(MessageGrammar.HeaderSection(message).All(character => character < 128),       Is.True);

        });

    }


    [Test(Description = "RFC 2919 §3: \"The list header fields are subject to the encoding and character restrictions for mail headers\"; list-id-header = \"List-ID:\" [phrase] \"<\" list-id \">\" - a description that is not ASCII is an encoded word, one with a comma no bare phrase")]
    [Category(TestCategories.KnownIssue), Property("Finding", "E-13")]
    public void A_list_description_is_written_as_a_phrase_of_ASCII()
    {

        var builder = OlderBuilder();
        builder.ListId = ListId.Parse("=?UTF-8?Q?Gr=C3=BC=C3=9Fe=2C_Freunde?= <friends.list.example.org>");

        var message = String.Join("\r\n", ((EMail) builder).ToText(false));
        var value   = MessageGrammar.Value(message, "List-ID")!;

        Assert.Multiple(() => {
            Assert.That(value.All(character => character is >= ' ' and <= '~'), Is.True, value);
            Assert.That(ListId.Parse(value)?.Name,                                Is.EqualTo("Grüße, Freunde"));
        });

    }

    #endregion

}
