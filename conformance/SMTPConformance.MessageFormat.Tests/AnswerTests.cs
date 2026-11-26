using System.Text;
using System.Text.RegularExpressions;

using NUnit.Framework;

using SMTPConformance.Core;

using org.GraphDefined.Vanaheimr.Hermod.Mail;

namespace SMTPConformance.MessageFormat.Tests;

/// <summary>
/// What an answer takes from the message it answers, and the list it came through: RFC 5322
/// §3.6.5 the subject of a reply, RFC 2369 §2 and §3.4 List-Post - read by
/// <see cref="MailReplies"/>, written by the older <see cref="TextEMailBuilder"/> - and RFC
/// 6068 §2 the mailto URL it names the list by.
/// </summary>
[TestFixture]
public sealed class AnswerTests
{

    private static MimeMessage WithListPost(String ListPost)
        => MimeMessage.Parse(Encoding.UTF8.GetBytes($"From: author@example.org\r\nTo: list@example.org\r\nList-Post: {ListPost}\r\nSubject: A post\r\n\r\nText.\r\n"));


    #region E-22: one "Re: " in the subject of a reply

    private static IEnumerable<TestCaseData> SubjectsWithAListTag()
    {

        TestCaseData Case(String Subject)
            => new TestCaseData(Subject).SetName($"The subject of a reply has one Re: - \"{Subject}\"")
                                        .SetProperty("Finding", "E-22");

        yield return Case("[dev] Re: Hello");
        yield return Case("Re: [dev] Re: Hello");

    }

    [TestCaseSource(nameof(SubjectsWithAListTag))]
    [Description("RFC 5322 §3.6.5: the subject of a reply \"MAY start with the string \"Re: \" (an abbreviation of the Latin \"in re\", meaning \"in the matter of\") followed by the contents of the \"Subject:\" field body of the original message. If this is done, only one instance of the literal string \"Re: \" ought to be used\" - a list's tag before the subject notwithstanding")]
    public void The_subject_of_a_reply_has_one_Re(String Subject)
    {

        var reply = MailReplies.ReplySubject(Subject);

        Assert.Multiple(() => {
            Assert.That(Regex.Matches(reply, @"(?<![A-Za-z])re\s*:", RegexOptions.IgnoreCase).Count,  Is.EqualTo(1), reply);
            Assert.That(reply,                                                                         Does.Contain("[dev]").And.EndsWith("Hello"));
        });

    }

    [TestCase("[dev] Hello",   "Re: [dev] Hello", TestName = "The subject of a reply to a list's post: Re: before the tag")]
    [TestCase("Re: Re: Hello", "Re: Hello",       TestName = "The subject of a reply to a reply: one Re:")]
    [Description("RFC 5322 §3.6.5: one \"Re: \", followed by the subject of the original - a guard for E-22")]
    public void The_subject_of_a_reply_is_Re_and_the_original(String Subject, String Reply)

        => Assert.That(MailReplies.ReplySubject(Subject), Is.EqualTo(Reply));

    #endregion

    #region E-23 and E-24: the list a post goes to (List-Post)

    private static IEnumerable<TestCaseData> ListPostsWithWhiteSpace()
    {

        TestCaseData Case(String Name, String ListPost)
            => new TestCaseData(ListPost).SetName($"White space inside the angle brackets of List-Post is ignored: {Name}")
                                         .SetProperty("Finding", "E-23");

        yield return Case("folded inside the URL", "<mailto:list@\r\n example.org>");
        yield return Case("around the URL",        "< mailto:list@example.org >");

    }

    [TestCaseSource(nameof(ListPostsWithWhiteSpace))]
    [Description("RFC 2369 §2: \"The contents of the list header fields mostly consist of angle-bracket ('<', '>') enclosed URLs, with internal whitespace being ignored. MTAs MUST NOT insert whitespace within the brackets, but client applications should treat any whitespace, that might be inserted by poorly behaved MTAs, as characters to ignore\"")]
    public void White_space_inside_the_angle_brackets_of_List_Post_is_ignored(String ListPost)

        => Assert.That(MailReplies.ListPost(WithListPost(ListPost)), Is.EqualTo("list@example.org"));

    private static IEnumerable<TestCaseData> ListPostsWithWhatIsToBeIgnored()
    {

        TestCaseData Case(String Name, String ListPost, String? Address)
            => new TestCaseData(ListPost, Address).SetName($"List-Post is read as RFC 2369 says: {Name}")
                                                  .SetProperty("Finding", "E-24");

        yield return Case("a URL in a comment before the field's is none",           "(not <mailto:wrong@example.org>) <mailto:list@example.org>",       "list@example.org");
        yield return Case("a URL after another and no comma is ignored",             "<https://example.org/post> (moderated) <mailto:other@example.org>", null);
        yield return Case("a URL after a sub-item that is no URL is ignored",        "<https://example.org/post>, by mail: <mailto:other@example.org>",   null);

    }

    [TestCaseSource(nameof(ListPostsWithWhatIsToBeIgnored))]
    [Description("RFC 2369 §2: \"client applications MUST follow the following guidelines\": 1. a field that, \"following any leading whitespace, including comments\", begins with no '<' SHOULD be ignored; 2. \"Any characters following an angle bracket enclosed URL SHOULD be ignored, unless a comma is the first non-whitespace/comment character after the closing angle bracket\"; 3. \"If a sub-item (comma-separated item) within the field is not an angle-bracket enclosed URL, the remainder of the field (the current, and all subsequent, sub-items) SHOULD be ignored\"")]
    public void List_Post_is_read_as_RFC_2369_says(String ListPost, String? Address)

        => Assert.That(MailReplies.ListPost(WithListPost(ListPost)), Is.EqualTo(Address));

    [TestCase("<mailto:list@example.org>",                             "list@example.org", TestName = "List-Post: a mailto URL")]
    [TestCase("<https://example.org/post>,\r\n <mailto:list@example.org>", "list@example.org", TestName = "List-Post: a mailto URL after another, a comma between")]
    [TestCase("<mailto:list@example.org> (moderated)",                 "list@example.org", TestName = "List-Post: a comment after the URL")]
    [TestCase("NO (posting not allowed on this list)",                 null,               TestName = "List-Post: NO")]
    [Description("RFC 2369 §2, §3.4: List-Post's mailto URL, alternatives separated by commas, \"NO\" for a list that takes no posts - a guard for E-23 and E-24")]
    public void List_Post_names_the_list_its_mailto_URL_names(String ListPost, String? Address)

        => Assert.That(MailReplies.ListPost(WithListPost(ListPost)), Is.EqualTo(Address));

    #endregion

    #region E-25: the List-Post the older builder writes

    private static String ListPostWritten(String Address)
    {

        var builder = new TextEMailBuilder {
                          From     = EMailAddress.Parse("Mary Smith <mary@example.net>"),
                          Subject  = "A post",
                          Text     = "Hello.\r\n"
                      };

        builder.To       = EMailAddressListBuilder.Create(EMailAddress.Parse("John Doe <john@example.org>")!);
        builder.ListPost = SimpleEMailAddress.Parse(Address);

        var message = String.Join("\r\n", ((EMail) builder).ToText(false));

        return MessageGrammar.Value(message, "List-Post")!;

    }

    private static IEnumerable<TestCaseData> AddressesToBeEncoded()
    {

        TestCaseData Case(String Name, String Address)
            => new TestCaseData(Address).SetName($"List-Post names the list's address: {Name}")
                                        .SetProperty("Finding", "E-25");

        yield return Case("a slash in it",           "dev/announce@lists.example.org");
        yield return Case("a question mark in it",   "dev?announce@lists.example.org");
        yield return Case("a number sign in it",     "list#1@lists.example.org");
        yield return Case("a percent sign in it",    "list%1@lists.example.org");

    }

    [TestCaseSource(nameof(AddressesToBeEncoded))]
    [Description("RFC 2369 §2: the list header fields hold URLs; RFC 6068 §2: \"A number of characters that can appear in <addr-spec> MUST be percent-encoded: these are the characters that cannot appear in a URI according to [STD66] as well as \"%\" (because it is used for percent-encoding) and all the characters in gen-delims except \"@\" and \":\" (i.e., \"/\", \"?\", \"#\", \"[\", and \"]\")\" - a \"?\" begins the header fields, a \"#\" a fragment")]
    public void List_Post_names_the_lists_address(String Address)
    {

        var value = ListPostWritten(Address);
        var match = Regex.Match(value, @"^<mailto:([^>]*)>$");

        Assert.Multiple(() => {
            Assert.That(match.Success,                                                       Is.True, value);
            Assert.That(match.Groups[1].Value,                                               Does.Not.Match(@"[/?#\[\]]|%(?![0-9A-Fa-f]{2})"), value);
            Assert.That(Uri.UnescapeDataString(match.Groups[1].Value),                       Is.EqualTo(Address), value);
        });

    }

    [Test(Description = "RFC 2369 §3.4, RFC 6068 §2: List-Post: <mailto:list@...> for an address with nothing to encode - a guard for E-25")]
    public void List_Post_of_an_address_of_the_usual_kind()

        => Assert.That(ListPostWritten("dev-announce@lists.example.org"), Is.EqualTo("<mailto:dev-announce@lists.example.org>"));

    #endregion

}
