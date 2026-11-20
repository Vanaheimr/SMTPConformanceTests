using System.Text;
using System.Text.RegularExpressions;

using NUnit.Framework;

using SMTPConformance.Core;

using org.GraphDefined.Vanaheimr.Hermod.Mail;

namespace SMTPConformance.MessageFormat.Tests;

/// <summary>
/// The structure of a MIME message: RFC 2045 §5 Content-Type and its default, §6.4
/// Content-Transfer-Encoding, RFC 2046 §5.1 multipart - boundaries of 1 to 70 bchars that do
/// not occur in the parts, delimiter and close-delimiter lines, transport padding, preamble
/// and epilogue, multipart/digest - and §5.2.1 message/rfc822. Written by <see cref="MimeMultipart"/>
/// and the older <see cref="HTMLEMailBuilder"/>, read by <see cref="MimeMessage"/> and the
/// older <see cref="EMail"/> - and by hostile senders: deep nesting, endless parts, missing delimiters.
/// </summary>
[TestFixture]
public sealed class MimeStructureTests
{

    private static MimeMessage Parse(String Message)
        => MimeMessage.Parse(Encoding.UTF8.GetBytes(Message));

    private static String Nested()
    {

        var text     = new MimeTextPart("--=_ a line that looks like a delimiter\r\n--\r\n----=_\r\nGrüße.\r\n");
        var html     = new MimeTextPart("<p>--=_ Grüße.</p>", "html");
        var builder  = new MimeMessageBuilder {
                           From     = new MailboxAddress("Author", "author@example.org"),
                           Subject  = "Nested",
                           Body     = new MimeMultipart("mixed", [ new MimeMultipart("alternative", [ text, html ]),
                                                                  new MimeAttachment(Encoding.ASCII.GetBytes("--=_\r\n"), "text/plain", "delimiter.txt"),
                                                                  new MimeAttachedMessage(Encoding.UTF8.GetBytes("From: other@example.net\r\nSubject: Forwarded\r\n\r\nÄrger.\r\n")) ])
                       };

        builder.To.Add(new MailboxAddress(null, "recipient@example.net"));

        return MessageGrammar.Text(builder.ToBytes());

    }

    private static IEnumerable<String> Boundaries(String Message)
        => Regex.Matches(MessageGrammar.Unfold(Message), @"boundary=""(?<b>[^""]*)""|boundary=(?<b>[^;\s""]+)", RegexOptions.IgnoreCase).Select(match => match.Groups["b"].Value);


    #region Written

    [Test(Description = "RFC 2046 §5.1.1: boundary := 0*69<bchars> bcharsnospace - 1 to 70 characters from a set \"known to be very robust through mail gateways\"")]
    public void Hermods_boundaries_follow_the_grammar()
    {

        var boundaries = Boundaries(Nested()).ToList();

        Assert.That(boundaries, Has.Count.EqualTo(2));
        Assert.That(boundaries.Where(boundary => !MessageGrammar.Boundary().IsMatch(boundary)), Is.Empty);

    }


    [Test(Description = "RFC 2046 §5.1.1: \"Boundary delimiters must not appear within the encapsulated material\"; §5.1.2: the boundary of a nested multipart must not have that of an enclosing one as a prefix")]
    public void A_boundary_occurs_only_in_its_own_delimiter_lines()
    {

        var message    = Nested();
        var boundaries = Boundaries(message).ToList();
        var lines      = MessageGrammar.Lines(message);

        Assert.Multiple(() => {

            // mixed: three parts, alternative: two - and one more line each to close.
            Assert.That(lines.Count(line => line.StartsWith("--" + boundaries[0], StringComparison.Ordinal)), Is.EqualTo(4));
            Assert.That(lines.Count(line => line.StartsWith("--" + boundaries[1], StringComparison.Ordinal)), Is.EqualTo(3));

            Assert.That(boundaries[1].StartsWith(boundaries[0], StringComparison.Ordinal), Is.False);
            Assert.That(boundaries[0].StartsWith(boundaries[1], StringComparison.Ordinal), Is.False);

        });

    }


    [Test(Description = "RFC 2046 §5.1.1: multipart-body := [preamble CRLF] dash-boundary transport-padding CRLF body-part *encapsulation close-delimiter - Hermod's parts, split by the suite at its delimiters, are the parts it wrote")]
    public void A_multipart_Hermod_writes_splits_into_its_parts()
    {

        var message  = Nested();
        var outer    = MessageGrammar.Parts(MessageGrammar.Body(message), Boundaries(message).First());

        Assert.That(outer, Has.Count.EqualTo(3));

        var inner    = MessageGrammar.Parts(MessageGrammar.Body(outer[0]), Boundaries(outer[0]).Single());

        Assert.Multiple(() => {
            Assert.That(inner, Has.Count.EqualTo(2));
            Assert.That(MessageGrammar.Value(inner[0], "Content-Type"), Does.StartWith("text/plain"));
            Assert.That(MessageGrammar.Value(inner[1], "Content-Type"), Does.StartWith("text/html"));
            Assert.That(Encoding.UTF8.GetString(MessageGrammar.DecodeQuotedPrintable(MessageGrammar.Body(inner[0]))), Is.EqualTo("--=_ a line that looks like a delimiter\r\n--\r\n----=_\r\nGrüße.\r\n"));
            Assert.That(MessageGrammar.Value(outer[2], "Content-Type"), Is.EqualTo("message/rfc822"));
        });

    }


    [Test(Description = "RFC 2046 §5.2.1: \"No encoding other than \"7bit\", \"8bit\", or \"binary\" is permitted for the body of a \"message/rfc822\" entity\"; RFC 2045 §6.2: 8bit for octets above 127")]
    public void An_attached_message_is_7bit_or_8bit_as_its_octets_are()
    {

        var message = Nested();
        var outer   = MessageGrammar.Parts(MessageGrammar.Body(message), Boundaries(message).First());

        Assert.That(MessageGrammar.Value(outer[2], "Content-Transfer-Encoding"), Is.EqualTo("8bit"));

    }


    [Test(Description = "RFC 2045 §6.2: \"7bit\" data is short lines of US-ASCII - text that is not, is quoted-printable; RFC 2045 §5.1: the charset names what the octets are")]
    public void A_text_part_that_is_not_ASCII_is_quoted_printable_utf_8()
    {

        var message = Nested();
        var outer   = MessageGrammar.Parts(MessageGrammar.Body(message), Boundaries(message).First());
        var inner = MessageGrammar.Parts(MessageGrammar.Body(outer[0]), Boundaries(outer[0]).Single());

        Assert.Multiple(() => {
            Assert.That(MessageGrammar.Value(inner[0], "Content-Transfer-Encoding"),                     Is.EqualTo("quoted-printable"));
            Assert.That(MessageGrammar.Parameter(MessageGrammar.Value(inner[0], "Content-Type")!, "charset"), Is.EqualTo("utf-8").IgnoreCase);
            Assert.That(MessageGrammar.Body(inner[0]).All(character => character < 128),                Is.True);
        });

    }


    [Test(Description = "RFC 2046 §5.1.1: boundary := 0*69<bchars> bcharsnospace, bcharsnospace := DIGIT / ALPHA / \"'\" / \"(\" / \")\" / \"+\" / \"_\" / \",\" / \"-\" / \".\" / \"/\" / \":\" / \"=\" / \"?\" - the boundary of the older HTMLEMailBuilder")]
    [Property("Finding", "E-4")]
    public void The_older_builders_boundary_follows_the_grammar()
    {

        var builder = new HTMLEMailBuilder("<p>Hello.</p>", "Hello.") {
                          From     = EMailAddress.Parse("Author <author@example.org>"),
                          Subject  = "Hello"
                      };

        builder.To  = EMailAddressListBuilder.Create(EMailAddress.Parse("recipient@example.net")!);

        var message = String.Join("\r\n", ((EMail) builder).ToText(false));
        var boundary = Boundaries(message).Single();

        Assert.That(MessageGrammar.Boundary().IsMatch(boundary), Is.True, boundary);

    }

    #endregion

    #region Read

    private const String Section511Example = "From: Nathaniel Borenstein <nsb@bellcore.com>\r\n" +
                                             "To: Ned Freed <ned@innosoft.com>\r\n" +
                                             "Date: Sun, 21 Mar 1993 23:56:48 -0800 (PST)\r\n" +
                                             "Subject: Sample message\r\n" +
                                             "MIME-Version: 1.0\r\n" +
                                             "Content-type: multipart/mixed; boundary=\"simple boundary\"\r\n" +
                                             "\r\n" +
                                             "This is the preamble.  It is to be ignored, though it\r\n" +
                                             "is a handy place for composition agents to include an\r\n" +
                                             "explanatory note to non-MIME conformant readers.\r\n" +
                                             "\r\n" +
                                             "--simple boundary\r\n" +
                                             "\r\n" +
                                             "This is implicitly typed plain US-ASCII text.\r\n" +
                                             "It does NOT end with a linebreak.\r\n" +
                                             "--simple boundary\r\n" +
                                             "Content-type: text/plain; charset=us-ascii\r\n" +
                                             "\r\n" +
                                             "This is explicitly typed plain US-ASCII text.\r\n" +
                                             "It DOES end with a linebreak.\r\n" +
                                             "\r\n" +
                                             "--simple boundary--\r\n" +
                                             "\r\n" +
                                             "This is the epilogue.  It is also to be ignored.\r\n";


    [Test(Description = "RFC 2046 §5.1.1, the example: two parts, one implicitly typed; \"the initial CRLF is considered to be attached to the boundary delimiter line\"; preamble and epilogue \"to be ignored\"")]
    public void The_multipart_example_of_RFC_2046_reads_as_two_parts()
    {

        var parts = Parse(Section511Example).Root.Children;

        Assert.That(parts, Has.Count.EqualTo(2));

        Assert.Multiple(() => {
            Assert.That(parts[0].ContentType.MimeType,  Is.EqualTo("text/plain"));
            Assert.That(parts[0].GetText(),             Is.EqualTo("This is implicitly typed plain US-ASCII text.\r\nIt does NOT end with a linebreak."));
            Assert.That(parts[1].GetText(),             Is.EqualTo("This is explicitly typed plain US-ASCII text.\r\nIt DOES end with a linebreak.\r\n"));
        });

    }


    private const String Padded = "From: someone@example.org\r\n" +
                                  "MIME-Version: 1.0\r\n" +
                                  "Content-Type: multipart/mixed; boundary=\"xyz\"\r\n" +
                                  "\r\n" +
                                  "--xyz  \r\n" +
                                  "Content-Type: text/plain\r\n" +
                                  "\r\n" +
                                  "one\r\n" +
                                  "--xyz\t\r\n" +
                                  "Content-Type: text/plain\r\n" +
                                  "\r\n" +
                                  "two\r\n" +
                                  "--xyz-- \r\n";


    [Test(Description = "RFC 2046 §5.1.1: transport-padding := *LWSP-char - \"receivers MUST be able to handle padding added by message transports\"")]
    public void Delimiter_lines_with_transport_padding_are_read()
    {
        Assert.That(Parse(Padded).Root.Children.Select(part => part.GetText()), Is.EqualTo(new[] { "one", "two" }));
    }


    [Test(Description = "RFC 2046 §5.1.1: a multipart read by the older EMail.Parse")]
    public void A_multipart_is_read_by_EMail()
    {

        var mail = EMail.Parse(Padded.Replace("--xyz  \r\n", "--xyz\r\n").Replace("--xyz\t\r\n", "--xyz\r\n").Replace("--xyz-- \r\n", "--xyz--\r\n").Split("\r\n"));

        Assert.That(mail.Body.NestedBodyparts.Select(part => String.Join("\r\n", part.MailBody)), Is.EqualTo(new[] { "one", "two" }));

    }


    [Test(Description = "RFC 2046 §5.1.1: transport-padding := *LWSP-char - \"receivers MUST be able to handle padding added by message transports\" - in the older EMail.Parse")]
    [Property("Finding", "E-5")]
    public void Delimiter_lines_with_transport_padding_are_read_by_EMail()
    {

        EMail? mail = null;

        Assert.That(() => mail = EMail.Parse(Padded.Split("\r\n")), Throws.Nothing);
        Assert.That(mail!.Body.NestedBodyparts.Select(part => String.Join("\r\n", part.MailBody)), Is.EqualTo(new[] { "one", "two" }));

    }


    [Test(Description = "Hostile input: a multipart without a single delimiter line is read without an exception by the older EMail.Parse - which MdnGeneratingMailStorage runs on every message it stores")]
    [Property("Finding", "E-5")]
    public void A_multipart_without_delimiters_is_read_by_EMail()
    {
        Assert.That(() => EMail.Parse("From: someone@example.org\r\nContent-Type: multipart/mixed; boundary=xyz\r\n\r\nNo delimiter anywhere.".Split("\r\n")), Throws.Nothing);
    }


    /// <summary>
    /// A multipart of two text parts, "one" and "two", under the given Content-Type, whose
    /// boundary is "xyz" - for the older EMail.Parse.
    /// </summary>
    private static EMail ParseByEMail(String ContentType)

        => EMail.Parse(("From: someone@example.org\r\n" +
                        "MIME-Version: 1.0\r\n" +
                        "Content-Type: " + ContentType + "\r\n" +
                        "\r\n" +
                        "--xyz\r\n" +
                        "Content-Type: text/plain\r\n" +
                        "\r\n" +
                        "one\r\n" +
                        "--xyz\r\n" +
                        "Content-Type: text/plain\r\n" +
                        "\r\n" +
                        "two\r\n" +
                        "--xyz--\r\n").Split("\r\n"));

    private static IEnumerable<String> PartsOf(EMail Mail)
        => Mail.Body.NestedBodyparts.Select(part => String.Join("\r\n", part.MailBody));


    [TestCase("Multipart/Mixed; boundary=xyz",                                          Description = "type and subtype capitalised")]
    [TestCase("MULTIPART/MIXED; boundary=xyz",                                          Description = "type and subtype in upper case")]
    [TestCase("multipart/mixed; Boundary=xyz",                                          Description = "the parameter name capitalised")]
    [TestCase("multipart/mixed; BOUNDARY=\"xyz\"",                                      Description = "the parameter name in upper case, the value quoted")]
    [TestCase("Multipart/Report; report-type=disposition-notification; boundary=xyz",   Description = "a read receipt as some agents write it")]
    [Test(Description = "RFC 2045 §5.1: \"The type, subtype, and parameter names are not case sensitive\" - the older EMail.Parse finds the parts of a multipart whatever the case of its type and of \"boundary\"")]
    [Property("Finding", "E-14")]
    public void The_media_type_and_parameter_names_are_read_without_case_by_EMail(String ContentType)
    {
        Assert.That(PartsOf(ParseByEMail(ContentType)), Is.EqualTo(new[] { "one", "two" }));
    }


    [TestCase("multipart/mixed; boundary=xyz",   Description = "lower case")]
    [TestCase("multipart/mixed; boundary=\"xyz\"", Description = "the value quoted")]
    [Test(Description = "RFC 2046 §5.1.1: the parts of a multipart, read by the older EMail.Parse - the guard for E-14 and E-15")]
    public void A_multipart_in_the_usual_spelling_is_read_by_EMail(String ContentType)
    {
        Assert.That(PartsOf(ParseByEMail(ContentType)), Is.EqualTo(new[] { "one", "two" }));
    }


    [TestCase("multipart/mixed; boundary = xyz",              Description = "white space around \"=\"")]
    [TestCase("multipart/mixed; boundary=xyz (a comment)",    Description = "a comment after the value")]
    [TestCase("multipart/mixed (a comment); boundary=xyz",    Description = "a comment after the subtype")]
    [Test(Description = "RFC 2045 §1: the MIME header fields \"are subject to the general syntactic rules for header fields specified in RFC 822\" - white space between the tokens of a structured field - and \"can include RFC 822 comments, which have no semantic content and should be ignored\" - the older EMail.Parse reads such a Content-Type as the MIME reader does")]
    [Property("Finding", "E-15")]
    public void White_space_and_comments_in_the_Content_Type_are_read_by_EMail(String ContentType)
    {
        Assert.That(PartsOf(ParseByEMail(ContentType)), Is.EqualTo(new[] { "one", "two" }));
    }


    [Test(Description = "RFC 2046 §5.1.7: \"MIME implementations must in general treat unrecognized subtypes of \"multipart\" as being equivalent to \"multipart/mixed\"\" - the older EMail.Parse finds the parts of multipart/related")]
    [Property("Finding", "E-16")]
    public void An_unrecognised_multipart_subtype_is_read_as_mixed_by_EMail()
    {
        Assert.That(PartsOf(ParseByEMail("multipart/related; boundary=xyz")), Is.EqualTo(new[] { "one", "two" }));
    }


    [Test(Description = "RFC 2045 §5.1: parameters are \"modifiers of the media subtype\", and RFC 2046 §5.1.1 defines \"boundary\" for multipart only - a text/plain with a parameter that ends in \"boundary\" is no multipart, and a line \"--\" in it is text")]
    [Property("Finding", "E-16")]
    public void A_text_with_a_parameter_ending_in_boundary_is_not_split_by_EMail()
    {

        var mail = EMail.Parse("From: someone@example.org\r\nContent-Type: text/plain; x-boundary=xyz\r\n\r\nabove\r\n--\r\nbelow\r\n".Split("\r\n"));

        Assert.Multiple(() => {
            Assert.That(mail.Body.NestedBodyparts,                    Is.Empty);
            Assert.That(String.Join("\r\n", mail.Body.MailBody),      Does.Contain("above\r\n--\r\nbelow"));
        });

    }


    [Test(Description = "RFC 2045 §5.2: \"Content-type: text/plain; charset=us-ascii ... is assumed if no Content-Type header field is specified\"")]
    public void A_message_without_Content_Type_is_plain_US_ASCII_text()
    {

        var root = Parse("From: someone@example.org\r\nSubject: Plain\r\n\r\nJust text.\r\n").Root;

        Assert.Multiple(() => {
            Assert.That(root.ContentType.MimeType,  Is.EqualTo("text/plain"));
            Assert.That(root.ContentType.Charset,   Is.EqualTo("us-ascii"));
        });

    }


    [Test(Description = "RFC 2046 §5.1.1: \"If no Content-Type field is present it is assumed to be \"message/rfc822\" in a \"multipart/digest\" and \"text/plain\" otherwise\"")]
    public void A_part_of_a_digest_without_Content_Type_is_a_message()
    {

        var message = Parse("From: list@example.org\r\nMIME-Version: 1.0\r\nContent-Type: multipart/digest; boundary=\"---- next message ----\"\r\n\r\n" +
                            "------ next message ----\r\n\r\nFrom: someone@example.net\r\nSubject: First\r\n\r\nOne.\r\n" +
                            "------ next message ----\r\n\r\nFrom: someone@example.net\r\nSubject: Second\r\n\r\nTwo.\r\n" +
                            "------ next message ------\r\n");

        Assert.That(message.Root.Children.Select(part => part.EmbeddedMessage?.Subject), Is.EqualTo(new[] { "First", "Second" }));

    }


    [Test(Description = "RFC 2045 §6.4: \"Any entity with an unrecognized Content-Transfer-Encoding must be treated as if it has a Content-Type of \"application/octet-stream\", regardless of what the Content-Type header field actually says\"")]
    [Property("Finding", "E-10")]
    public void A_part_with_an_unknown_transfer_encoding_is_no_text()
    {

        var message = Parse("From: someone@example.org\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=us-ascii\r\nContent-Transfer-Encoding: x-private-scheme\r\n\r\nQmluYXJ5IGRhdGE=\r\n");

        Assert.Multiple(() => {
            Assert.That(message.TextBody,     Is.Null, "shown as the text of the message");
            Assert.That(message.Attachments,  Has.Count.EqualTo(1));
        });

    }

    #endregion

    #region Hostile

    [Test(Description = "Hostile input: a multipart nested 5000 deep, a message/rfc822 nested 5000 deep, 100 000 parts, and a multipart without its close delimiter are read in time, with bounded depth")]
    public async Task Deep_wide_and_unfinished_multiparts_are_read_in_time()
    {

        var deep     = new StringBuilder("From: someone@example.org\r\n");
        for (var i = 0; i < 5000; i++)
            deep.Append($"Content-Type: multipart/mixed; boundary=b{i}\r\n\r\n--b{i}\r\n");
        deep.Append("Content-Type: text/plain\r\n\r\nInnermost.\r\n");

        var digest   = new StringBuilder("From: someone@example.org\r\n");
        for (var i = 0; i < 5000; i++)
            digest.Append("Content-Type: message/rfc822\r\n\r\n");
        digest.Append("Subject: Innermost\r\n\r\nx\r\n");

        var wide     = new StringBuilder("From: someone@example.org\r\nContent-Type: multipart/mixed; boundary=w\r\n\r\n");
        for (var i = 0; i < 100_000; i++)
            wide.Append("--w\r\n\r\nx\r\n");
        wide.Append("--w--\r\n");

        var unfinished = "From: someone@example.org\r\nContent-Type: multipart/mixed; boundary=u\r\n\r\n--u\r\n\r\nfirst\r\n--u\r\n\r\nsecond, and no close delimiter\r\n";

        var parsed   = await Task.Run(() => (Parse(deep.ToString()), Parse(digest.ToString()), Parse(wide.ToString()), Parse(unfinished))).WaitAsync(TimeSpan.FromSeconds(20));

        Assert.Multiple(() => {
            Assert.That(parsed.Item1.Root.Descendants().Count(),                    Is.LessThanOrEqualTo(MimeMessage.MaxDepth + 1));
            Assert.That(parsed.Item3.Root.Children.Count,                           Is.LessThanOrEqualTo(MimeMessage.MaxParts));
            Assert.That(parsed.Item4.Root.Children.Select(part => part.GetText()),  Is.EqualTo(new[] { "first", "second, and no close delimiter\r\n" }));
        });

    }

    #endregion

}
