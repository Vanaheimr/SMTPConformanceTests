using System.Diagnostics;
using System.Text;

using NUnit.Framework;

using SMTPConformance.Core;

using org.GraphDefined.Vanaheimr.Hermod.Mail;

namespace SMTPConformance.MessageFormat.Tests;

/// <summary>
/// The encodings of a mail as Hermod writes and reads them: RFC 2045 §6.7 quoted-printable
/// and §6.8 base64 (<see cref="MimeEncoding"/>, <see cref="TransferEncodings"/>), RFC 2047
/// encoded words (<see cref="EncodedWords"/> and the words <see cref="MimeMessageBuilder"/>
/// writes), RFC 2231 parameter values (<see cref="MimeContentType"/>, <see cref="MimeAttachment"/>).
/// What Hermod writes is read back with <see cref="MessageGrammar"/>, which shares no code with it.
/// </summary>
[TestFixture]
public sealed class MimeEncodingTests
{

    private static readonly String Text = "Grüße aus Köln, wo der Dom steht und = Zeichen stehen.\r\n" +
                                          "Eine Zeile mit Leerzeichen am Ende   \r\n" +
                                          "Eine mit Tab am Ende\t\r\n" +
                                          "From here on it is a line that begins like an mbox separator.\r\n" +
                                          new String('x', 75) + "=" + new String('y', 200) + "\r\n" +
                                          String.Concat(Enumerable.Repeat("€ ", 120)) + "\r\n" +
                                          "\u0001 control and \u007F delete\r\n";

    private static IEnumerable<String> EncodedLines()
        => MessageGrammar.Lines(Encoding.ASCII.GetString(MimeEncoding.QuotedPrintable(Encoding.UTF8.GetBytes(Text))));


    #region Quoted-printable, written

    [Test(Description = "RFC 2045 §6.7 (5): \"The Quoted-Printable encoding REQUIRES that encoded lines be no more than 76 characters long\"")]
    public void Quoted_printable_lines_are_at_most_76_characters()
    {
        Assert.That(EncodedLines().Where(line => line.Length > 76), Is.Empty);
    }


    [Test(Description = "RFC 2045 §6.7 (3): \"Any TAB (HT) or SPACE characters on an encoded line MUST thus be followed on that line by a printable character\"")]
    public void No_encoded_line_ends_in_white_space()
    {
        Assert.That(EncodedLines().Where(line => line.EndsWith(' ') || line.EndsWith('\t')), Is.Empty);
    }


    [Test(Description = "RFC 2045 §6.7 (1), (2): an octet that is not printable ASCII other than \"=\" is \"=\" and two hex digits - \"Uppercase letters must be used\"")]
    public void Every_octet_outside_the_literal_range_is_escaped_in_upper_case()
    {

        Assert.That(EncodedLines().Where(line => !line.All(character => character is '\t' or (>= ' ' and <= '~'))), Is.Empty);

        // Every "=" is an upper-case escape or a soft line break: the strict decoder throws otherwise.
        Assert.DoesNotThrow(() => MessageGrammar.DecodeQuotedPrintable(String.Join("\r\n", EncodedLines())));

    }


    [Test(Description = "RFC 2045 §6.7: the encoded text, decoded, is the text - CRLF line breaks of the canonical form (rule 4), soft line breaks removed (rule 5)")]
    public void Quoted_printable_decodes_to_the_text_it_encodes()
    {

        var decoded = MessageGrammar.DecodeQuotedPrintable(String.Join("\r\n", EncodedLines()) + "\r\n");

        Assert.That(Encoding.UTF8.GetString(decoded), Is.EqualTo(Text));

    }

    #endregion

    #region Quoted-printable, read

    [TestCase("Soft=\r\nbreak",            "Softbreak",          TestName = "A soft line break is removed")]
    [TestCase("Gr=C3=BC=C3=9Fe",           "Grüße",              TestName = "An escape is the octet")]
    [TestCase("a=3Db",                     "a=b",                TestName = "An escaped equals sign is one")]
    [TestCase("tab=09\r\nnext",            "tab\t\r\nnext",      TestName = "An escaped tab before a hard line break stays")]
    [Test(Description = "RFC 2045 §6.7 rules 1, 4 and 5, decoded")]
    public void Quoted_printable_is_decoded(String Encoded, String Expected)
    {
        Assert.That(Encoding.UTF8.GetString(TransferEncodings.DecodeQuotedPrintable(Encoding.ASCII.GetBytes(Encoded))), Is.EqualTo(Expected));
    }


    [Test(Description = "RFC 2045 §6.7 (3): \"when decoding a Quoted-Printable body, any trailing white space on a line must be deleted, as it will necessarily have been added by intermediate transport agents\"")]
    [Property("Finding", "E-11")]
    public void Trailing_white_space_is_deleted_when_decoding()
    {

        var decoded = TransferEncodings.DecodeQuotedPrintable("padded by a relay  \r\nand a tab\t\r\nlast"u8);

        Assert.That(Encoding.ASCII.GetString(decoded), Is.EqualTo("padded by a relay\r\nand a tab\r\nlast"));

    }

    #endregion

    #region Base64

    [Test(Description = "RFC 2045 §6.8: \"The encoded output stream must be represented in lines of no more than 76 characters each\"")]
    public void Base64_lines_are_at_most_76_characters_and_decode_to_the_octets()
    {

        var octets  = new Byte[5000];
        new Random(2045).NextBytes(octets);

        var encoded = Encoding.ASCII.GetString(MimeEncoding.Base64(octets));

        Assert.That(MessageGrammar.Lines(encoded).Where(line => line.Length > 76), Is.Empty);
        Assert.That(MessageGrammar.HasBareLineBreak(encoded), Is.False);
        Assert.That(Convert.FromBase64String(encoded.Replace("\r\n", "")), Is.EqualTo(octets));

    }


    [Test(Description = "RFC 2045 §6.8: \"All line breaks or other characters not found in Table 1 must be ignored by decoding software\"")]
    public void Base64_decoding_ignores_line_breaks_and_characters_outside_the_alphabet()
    {

        var base64  = Convert.ToBase64String(Encoding.UTF8.GetBytes("Größenänderung"));
        var mangled = base64[..4] + "\r\n" + base64[4..8] + "\t*!" + base64[8..] + "\r\n";

        var decoded = TransferEncodings.DecodeBase64(Encoding.ASCII.GetBytes(mangled));

        Assert.That(Encoding.UTF8.GetString(decoded), Is.EqualTo("Größenänderung"));

    }

    #endregion

    #region Encoded words, read

    public static IEnumerable<TestCaseData> Section8Comments()
    {

        TestCaseData Case(String encoded, String displayed)
            => new TestCaseData(encoded, displayed).SetName($"RFC 2047 §8: {encoded.Replace("\r\n", "CRLF")} is displayed as {displayed}");

        yield return Case("(=?ISO-8859-1?Q?a?=)",                                  "(a)");
        yield return Case("(=?ISO-8859-1?Q?a?= b)",                                "(a b)");
        yield return Case("(=?ISO-8859-1?Q?a?= =?ISO-8859-1?Q?b?=)",               "(ab)");
        yield return Case("(=?ISO-8859-1?Q?a?=  =?ISO-8859-1?Q?b?=)",              "(ab)");
        yield return Case("(=?ISO-8859-1?Q?a?=\r\n    =?ISO-8859-1?Q?b?=)",        "(ab)");
        yield return Case("(=?ISO-8859-1?Q?a_b?=)",                                "(a b)");
        yield return Case("(=?ISO-8859-1?Q?a?= =?ISO-8859-2?Q?_b?=)",              "(a b)");

    }


    [TestCaseSource(nameof(Section8Comments))]
    [Test(Description = "RFC 2047 §6.2: \"any 'linear-white-space' that separates a pair of adjacent 'encoded-word's is ignored\"; §4.2 (2): \"_\" represents a space")]
    public void Encoded_words_in_a_comment_are_displayed_as_RFC_2047_shows(String Encoded, String Displayed)
    {
        Assert.That(EncodedWords.Decode(Encoded), Is.EqualTo(Displayed));
    }


    [Test(Description = "RFC 2047 §8: the example headers - Q and B encoding, ISO-8859-1 and -2, a subject in two words of different charsets - decode to what they say")]
    public void The_example_headers_of_RFC_2047_decode()
    {

        var message = MimeMessage.Parse(Encoding.ASCII.GetBytes(
                          "From: =?US-ASCII?Q?Keith_Moore?= <moore@cs.utk.edu>\r\n" +
                          "To: =?ISO-8859-1?Q?Keld_J=F8rn_Simonsen?= <keld@dkuug.dk>\r\n" +
                          "CC: =?ISO-8859-1?Q?Andr=E9?= Pirard <PIRARD@vm1.ulg.ac.be>\r\n" +
                          "Subject: =?ISO-8859-1?B?SWYgeW91IGNhbiByZWFkIHRoaXMgeW8=?=\r\n" +
                          " =?ISO-8859-2?B?dSB1bmRlcnN0YW5kIHRoZSBleGFtcGxlLg==?=\r\n" +
                          "\r\n" +
                          "Body\r\n"));

        Assert.Multiple(() => {
            Assert.That(message.From[0].Name,  Is.EqualTo("Keith Moore"));
            Assert.That(message.To  [0].Name,  Is.EqualTo("Keld Jørn Simonsen"));
            Assert.That(message.Cc  [0].Name,  Is.EqualTo("André Pirard"));
            Assert.That(message.Subject,       Is.EqualTo("If you can read this you understand the example."));
        });

    }


    [Test(Description = "RFC 2231 §5: \"=?US-ASCII*EN?Q?Keith_Moore?=\" - an encoded word may name its language after the charset")]
    public void An_encoded_word_with_a_language_is_decoded()
    {
        Assert.That(EncodedWords.Decode("=?US-ASCII*EN?Q?Keith_Moore?="), Is.EqualTo("Keith Moore"));
    }


    [Test(Description = "Hostile input: a single base64 encoded word of 4 MB, and 400 000 starts of encoded words that never end, are decoded in linear time")]
    public async Task Huge_and_unfinished_encoded_words_are_decoded_in_time()
    {

        var huge      = "=?UTF-8?B?" + new String('A', 4_000_000) + "?=";
        var unended   = String.Concat(Enumerable.Repeat("=?UTF-8?Q?", 400_000));

        var decoded   = await Task.Run(() => (EncodedWords.Decode(huge).Length, EncodedWords.Decode(unended).Length)).WaitAsync(TimeSpan.FromSeconds(10));

        Assert.That(decoded.Item1, Is.EqualTo(3_000_000));

    }

    #endregion

    #region Encoded words, written

    private static String Built(String Subject, String DisplayName)
    {

        var builder = new MimeMessageBuilder {
                          From     = new MailboxAddress(DisplayName, "author@example.org"),
                          Subject  = Subject,
                          Date     = new DateTimeOffset(2026, 11, 20, 10, 0, 0, TimeSpan.FromHours(1)),
                          Body     = new MimeTextPart("Hello.")
                      };

        builder.To.Add(new MailboxAddress("Ännchen von Tharau, Vertrieb", "recipient@example.net"));

        return MessageGrammar.Text(builder.ToBytes());

    }

    private static readonly String LongSubject = "Grüße aus Köln: Einladung zur Sitzung über das Budget 2027, die Räume, " +
                                                 "die Öffnungszeiten und alles, was sonst noch zu besprechen ist - mit € und ✓ und 🙂 " +
                                                 "und einem Unterstrich_und einem Fragezeichen? und =Gleichheitszeichen=";

    private static readonly String LongName    = "Jörg-Friedrich Müller-Lüdenscheidt (Geschäftsführung, \"Vertrieb\" & Ölförderung) 🙂";


    [Test(Description = "RFC 2047 §2: \"An 'encoded-word' may not be more than 75 characters long\", and \"each line of a header field that contains one or more 'encoded-word's is limited to 76 characters\"")]
    public void Encoded_words_and_their_lines_are_within_75_and_76_characters()
    {

        var message = Built(LongSubject, LongName);
        var words   = MessageGrammar.EncodedWord().Matches(MessageGrammar.HeaderSection(message));

        Assert.That(words, Is.Not.Empty);

        Assert.Multiple(() => {
            Assert.That(words.Select(word => word.Value).Where(word => word.Length > 75), Is.Empty);
            Assert.That(MessageGrammar.Lines(MessageGrammar.HeaderSection(message)).
                            Where(line => MessageGrammar.EncodedWord().IsMatch(line) && line.Length > 76), Is.Empty);
        });

    }


    [Test(Description = "RFC 2047 §5 (3): in a phrase, a \"Q\" encoded-word may hold only \"upper and lower case ASCII letters, decimal digits, \"!\", \"*\", \"+\", \"-\", \"/\", \"=\", and \"_\"\"")]
    public void Encoded_words_in_a_display_name_use_only_what_a_phrase_allows()
    {

        var from   = MessageGrammar.Value(Built("Hi", LongName), "From")!;
        var words  = MessageGrammar.EncodedWord().Matches(from);

        Assert.That(words, Is.Not.Empty, from);
        Assert.That(words.Where(word => word.Groups["encoding"].Value is "Q" or "q" && !MessageGrammar.PhraseQText().IsMatch(word.Groups["text"].Value)).Select(word => word.Value), Is.Empty);

    }


    [Test(Description = "RFC 2047 §5: \"Each 'encoded-word' MUST represent an integral number of characters. A multi-octet character may not be split across adjacent 'encoded-word's\"")]
    public void No_character_is_split_between_two_encoded_words()
    {

        var strict  = new UTF8Encoding(false, throwOnInvalidBytes: true);
        var message = Built(String.Concat(Enumerable.Repeat("€🙂", 60)), LongName);

        foreach (var word in MessageGrammar.EncodedWord().Matches(MessageGrammar.HeaderSection(message)).Where(word => word.Groups["charset"].Value.Equals("UTF-8", StringComparison.OrdinalIgnoreCase)))
            Assert.DoesNotThrow(() => strict.GetString(word.Groups["encoding"].Value is "Q" or "q"
                                                           ? MessageGrammar.DecodeQ(word.Groups["text"].Value)
                                                           : Convert.FromBase64String(word.Groups["text"].Value)), word.Value);

    }


    [Test(Description = "RFC 2047 §6.2: the encoded words Hermod writes, with the white space between them ignored, are the subject and the display name again")]
    public void Encoded_subject_and_display_name_read_back_as_written()
    {

        var message = MimeMessage.Parse(Encoding.ASCII.GetBytes(Built(LongSubject, LongName)));

        Assert.Multiple(() => {
            Assert.That(message.Subject,       Is.EqualTo(LongSubject));
            Assert.That(message.From[0].Name,  Is.EqualTo(LongName));
            Assert.That(message.To  [0].Name,  Is.EqualTo("Ännchen von Tharau, Vertrieb"));
        });

    }

    #endregion

    #region RFC 2231 parameters

    [Test(Description = "RFC 2231 §3: \"The original parameter value is recovered by concatenating the various sections of the parameter, in order\" - the URL*0/URL*1 example")]
    public void Parameter_continuations_are_joined()
    {

        var type = MimeContentType.Parse("message/external-body; access-type=URL; URL*0=\"ftp://\"; URL*1=\"cs.utk.edu/pub/moore/bulk-mailer/bulk-mailer.tar\"", MimeContentType.TextPlain);

        Assert.That(type.Parameters["url"], Is.EqualTo("ftp://cs.utk.edu/pub/moore/bulk-mailer/bulk-mailer.tar"));

    }


    [Test(Description = "RFC 2231 §4: title*=us-ascii'en-us'This%20is%20%2A%2A%2Afun%2A%2A%2A - charset, language and percent-encoded octets")]
    public void An_extended_parameter_value_is_decoded()
    {

        var type = MimeContentType.Parse("application/x-stuff; title*=us-ascii'en-us'This%20is%20%2A%2A%2Afun%2A%2A%2A", MimeContentType.TextPlain);

        Assert.That(type.Parameters["title"], Is.EqualTo("This is ***fun***"));

    }


    [Test(Description = "RFC 2231 §4.1: continuations, encoded and not, with the charset and language in the first - the title*0* example")]
    public void Encoded_and_plain_continuations_are_combined()
    {

        var type = MimeContentType.Parse("application/x-stuff; title*0*=us-ascii'en'This%20is%20even%20more%20; title*1*=%2A%2A%2Afun%2A%2A%2A%20; title*2=\"isn't it!\"", MimeContentType.TextPlain);

        Assert.That(type.Parameters["title"], Is.EqualTo("This is even more ***fun*** isn't it!"));

    }


    [Test(Description = "RFC 2231 §4, §7: a file name that is not ASCII is written as an extended-initial-value - charset \"'\" language \"'\" and percent-encoded octets - and reads back as it was")]
    public void A_file_name_that_is_not_ASCII_is_written_as_RFC_2231_has_it()
    {

        const String fileName = "Präsentation für das Treffen (Entwurf) 100%.pdf";

        var builder = new MimeMessageBuilder {
                          From     = new MailboxAddress(null, "author@example.org"),
                          Subject  = "Anhang",
                          Body     = new MimeMultipart("mixed", [ new MimeTextPart("Anbei."), new MimeAttachment(new Byte[] { 1, 2, 3 }, "application/pdf", fileName) ])
                      };

        var text        = MessageGrammar.Text(builder.ToBytes());
        var boundary    = MessageGrammar.Parameter(MessageGrammar.Value(text, "Content-Type")!, "boundary")!;
        var attachment  = MessageGrammar.Parts(MessageGrammar.Body(text), boundary)[1];
        var disposition = MessageGrammar.Value(attachment, "Content-Disposition")!;
        var extended    = System.Text.RegularExpressions.Regex.Match(disposition, @"filename\*=(?<v>[^;\s]+)");

        Assert.That(extended.Success, Is.True, disposition);
        Assert.That(MessageGrammar.ExtendedInitialValue().IsMatch(extended.Groups["v"].Value), Is.True, extended.Groups["v"].Value);
        Assert.That(MimeMessage.Parse(Encoding.ASCII.GetBytes(text)).Attachments.Single().FileName, Is.EqualTo(fileName));

    }


    [Test(Description = "Hostile input: 200 000 parameter sections, and a comment nested a million deep, are parsed in time")]
    public async Task Endless_continuations_and_nested_comments_are_parsed_in_time()
    {

        var sections  = "application/x-stuff; " + String.Join("; ", Enumerable.Range(0, 200_000).Select(i => $"n{i}*{i % 999}*=%41"));
        var comments  = "text/plain; charset=utf-8 " + new String('(', 1_000_000) + new String(')', 1_000_000);

        var types     = await Task.Run(() => (MimeContentType.Parse(sections, MimeContentType.TextPlain), MimeContentType.Parse(comments, MimeContentType.TextPlain))).
                                   WaitAsync(TimeSpan.FromSeconds(10));

        Assert.That(types.Item2.Charset, Is.EqualTo("utf-8"));

    }

    #endregion

}
