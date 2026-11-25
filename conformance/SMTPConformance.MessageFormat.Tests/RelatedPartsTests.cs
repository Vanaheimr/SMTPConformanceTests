using System.Text;
using System.Text.RegularExpressions;

using NUnit.Framework;

using SMTPConformance.Core;

using org.GraphDefined.Vanaheimr.Hermod.Mail;

namespace SMTPConformance.MessageFormat.Tests;

/// <summary>
/// The parts an HTML mail refers to, and what a part is for: RFC 2045 §7 Content-ID - a
/// msg-id (RFC 5322 §3.6.4), what a cid: URL names (RFC 2392) - RFC 2387 multipart/related,
/// its type and start parameters, and RFC 2183 Content-Disposition, inline, attachment and
/// a type the reader does not know. Written by <see cref="MimeAttachment"/> and
/// <see cref="MimeMultipart"/>, read by <see cref="MimeMessage"/>.
/// </summary>
[TestFixture]
public sealed class RelatedPartsTests
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

    /// <summary>
    /// A multipart/related of an image and the HTML that shows it, the HTML its root by start=.
    /// </summary>
    private static String Related(String ImageId, String RootId, String Start) => $"""
        From: author@example.org
        To: recipient@example.net
        Subject: A picture
        MIME-Version: 1.0
        Content-Type: multipart/related; type="text/html"; start="{Start}"; boundary="b1"

        --b1
        Content-Type: image/png
        Content-Transfer-Encoding: base64
        Content-ID: {ImageId}

        iVBORw0KGgo=
        --b1
        Content-Type: text/html; charset=us-ascii
        Content-ID: {RootId}

        <p><img src="cid:logo@example.org"></p>
        --b1--

        """;


    #region E-17: a Content-ID with a comment around it

    private static IEnumerable<TestCaseData> ContentIdsWithComments()
    {

        TestCaseData Case(String Name, String ContentId)
            => new TestCaseData(ContentId).SetName($"A Content-ID with a comment names its part: {Name}")
                                          .SetCategory(TestCategories.KnownIssue)
                                          .SetProperty("Finding", "E-17");

        yield return Case("a comment after it",  "<logo@example.org> (the logo)");
        yield return Case("a comment before it", "(the logo) <logo@example.org>");

    }

    [TestCaseSource(nameof(ContentIdsWithComments))]
    [Description("RFC 2045 §7: id := \"Content-ID\" \":\" msg-id; RFC 5322 §3.6.4: msg-id = [CFWS] \"<\" id-left \"@\" id-right \">\" [CFWS] - the comment no part of the id; RFC 2392 §2: a cid: URL names the part by it")]
    public void A_Content_ID_with_a_comment_names_its_part(String ContentId)
    {

        var message = Parse(Related(ContentId, "<root@example.org>", "<root@example.org>"));

        Assert.Multiple(() => {
            Assert.That(message.Root.Children[0].ContentId,                Is.EqualTo("logo@example.org"));
            Assert.That(message.FindByContentId("logo@example.org"),       Is.SameAs(message.Root.Children[0]));
        });

    }

    [Test(Description = "RFC 2387 §3.2: start = msg-id, the Content-ID of the root - one with a comment after it is the root all the same, and the HTML of the message")]
    [Property("Finding", "E-17")]
    [Category(TestCategories.KnownIssue)]
    public void The_root_start_names_is_found_by_a_Content_ID_with_a_comment()
    {

        var message = Parse(Related("<logo@example.org>", "<root@example.org> (the root)", "<root@example.org>"));

        Assert.That(message.HtmlBody, Is.SameAs(message.Root.Children[1]));

    }

    [Test(Description = "RFC 2045 §7, RFC 2387 §3.2: a Content-ID without comments names its part, and the root start names is the HTML of the message - a guard for E-17")]
    public void A_Content_ID_of_the_usual_kind_names_its_part()
    {

        var message = Parse(Related("<logo@example.org>", "<root@example.org>", "<root@example.org>"));

        Assert.Multiple(() => {
            Assert.That(message.FindByContentId("logo@example.org"),       Is.SameAs(message.Root.Children[0]));
            Assert.That(message.HtmlBody,                                  Is.SameAs(message.Root.Children[1]));
        });

    }

    #endregion

    #region E-18 and E-19: what Content-Disposition says a part is for

    private const String UnknownDisposition = """
        From: author@example.org
        To: recipient@example.net
        Subject: Two texts
        MIME-Version: 1.0
        Content-Type: multipart/mixed; boundary="b1"

        --b1
        Content-Type: text/plain; charset=us-ascii

        The text.
        --b1
        Content-Type: text/plain; charset=us-ascii
        Content-Disposition: x-archive

        The second text.
        --b1--

        """;

    [Test(Description = "RFC 2183 §2.8: \"Unrecognized disposition types should be treated as `attachment'\" - a text that is not the body is listed, not lost")]
    [Property("Finding", "E-18")]
    [Category(TestCategories.KnownIssue)]
    public void A_part_of_an_unknown_disposition_type_is_an_attachment()
    {

        var message = Parse(UnknownDisposition);

        Assert.Multiple(() => {
            Assert.That(message.TextBody,     Is.SameAs(message.Root.Children[0]));
            Assert.That(message.Attachments,  Is.EqualTo(new[] { message.Root.Children[1] }));
        });

    }

    [Test(Description = "RFC 2183 §2.2: a text marked attachment is listed as one - a guard for E-18")]
    public void A_text_marked_attachment_is_an_attachment()
    {

        var message = Parse(UnknownDisposition.Replace("Content-Disposition: x-archive", "Content-Disposition: attachment"));

        Assert.That(message.Attachments, Is.EqualTo(new[] { message.Root.Children[1] }));

    }

    private const String InlineText = """
        From: author@example.org
        To: recipient@example.net
        Subject: Notes
        MIME-Version: 1.0
        Content-Type: text/plain; charset=us-ascii
        Content-Disposition: {0}

        The notes.

        """;

    [Test(Description = "RFC 2183 §2.1: \"A bodypart should be marked `inline' if it is intended to be displayed automatically upon display of the message\", and §2.3: the filename parameter is for either disposition - a text marked inline is the body, a file name or not")]
    [Property("Finding", "E-19")]
    [Category(TestCategories.KnownIssue)]
    public void A_text_marked_inline_with_a_file_name_is_the_body()
    {

        var message = Parse(String.Format(InlineText, "inline; filename=\"notes.txt\""));

        Assert.Multiple(() => {
            Assert.That(message.TextBody,     Is.SameAs(message.Root));
            Assert.That(message.Attachments,  Is.Empty);
        });

    }

    [TestCase("inline",                         TestName = "A text marked inline is the body")]
    [TestCase("attachment; filename=\"notes.txt\"", TestName = "A text marked attachment with a file name is no body")]
    [Description("RFC 2183 §2.1, §2.2: inline is shown, attachment is not - a guard for E-19")]
    public void Inline_is_shown_and_attachment_is_not(String Disposition)
    {

        var message = Parse(String.Format(InlineText, Disposition));

        Assert.That(message.TextBody is not null, Is.EqualTo(Disposition == "inline"));

    }

    #endregion

    #region E-20 and E-21: the Content-ID and the multipart/related written

    // RFC 5322 §3.6.4: msg-id = "<" id-left "@" id-right ">", id-left = dot-atom-text,
    // id-right = dot-atom-text / no-fold-literal - printable US-ASCII, no white space.
    private static readonly Regex MsgId = new(@"^<[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@([A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\[[\x21-\x5A\x5E-\x7E]*\])>$");

    private static IEnumerable<TestCaseData> ContentIdsThatAreNoMsgId()
    {

        TestCaseData Case(String Name, String ContentId)
            => new TestCaseData(ContentId).SetName($"A Content-ID that is no msg-id is not written: {Name}")
                                          .SetCategory(TestCategories.KnownIssue)
                                          .SetProperty("Finding", "E-20");

        yield return Case("no @",                 "logo");
        yield return Case("a space",              "my logo@example.org");
        yield return Case("a non-ASCII character", "bild-\u00E4@example.org");

    }

    [TestCaseSource(nameof(ContentIdsThatAreNoMsgId))]
    [Description("RFC 2045 §7: id := \"Content-ID\" \":\" msg-id; RFC 5322 §3.6.4: msg-id = \"<\" id-left \"@\" id-right \">\", of printable US-ASCII - what is none is refused, or written as the msg-id it is, not changed into another")]
    public void A_Content_ID_that_is_no_msg_id_is_not_written(String ContentId)
    {

        String[] header;

        try
        {
            header = HeaderOf(new MimeAttachment(new Byte[] { 0x89, 0x50, 0x4E, 0x47 }, "image/png", "logo.png", Inline: true, ContentId: ContentId));
        }
        catch (ArgumentException)
        {
            return;
        }

        var field = header.Single(line => line.StartsWith("Content-ID:", StringComparison.OrdinalIgnoreCase));

        Assert.That(field["Content-ID:".Length..].Trim(), Does.Match(MsgId).And.EqualTo($"<{ContentId}>"));

    }

    [Test(Description = "RFC 2045 §7: a Content-ID that is a msg-id is written as one, in angle brackets - a guard for E-20")]
    public void A_Content_ID_that_is_a_msg_id_is_written()
    {

        var header = HeaderOf(new MimeAttachment(new Byte[] { 0x89, 0x50, 0x4E, 0x47 }, "image/png", "logo.png", Inline: true, ContentId: "logo.1@example.org"));

        Assert.That(header, Has.Member("Content-ID: <logo.1@example.org>"));

    }

    [Test(Description = "RFC 2387 §3.1: \"The type parameter must be specified and its value is the MIME media type of the \"root\" body part\" - the first part, where there is no start")]
    [Property("Finding", "E-21")]
    [Category(TestCategories.KnownIssue)]
    public void A_multipart_related_has_the_type_of_its_root()
    {

        var related = new MimeMultipart("related", [ new MimeTextPart("<p><img src=\"cid:logo@example.org\"></p>", "html"),
                                                     new MimeAttachment(new Byte[] { 0x89, 0x50, 0x4E, 0x47 }, "image/png", null, Inline: true, ContentId: "logo@example.org") ]);

        var message = MimeMessage.Parse(related.ToBytes());

        Assert.That(message.Root.ContentType.Parameters.GetValueOrDefault("type"), Is.EqualTo("text/html"));

    }

    [Test(Description = "RFC 2387 §3.1: a type the caller gives is the one written - a guard for E-21")]
    public void A_multipart_related_keeps_the_type_it_is_given()
    {

        var related = new MimeMultipart("related", [ new MimeMultipart("alternative", [ new MimeTextPart("x"), new MimeTextPart("<p>x</p>", "html") ]) ],
                                        [ ("type", "multipart/alternative") ]);

        var message = MimeMessage.Parse(related.ToBytes());

        Assert.That(message.Root.ContentType.Parameters.GetValueOrDefault("type"), Is.EqualTo("multipart/alternative"));

    }

    #endregion

}
