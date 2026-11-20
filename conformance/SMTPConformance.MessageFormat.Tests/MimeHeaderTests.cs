using System.Text;

using NUnit.Framework;

using SMTPConformance.Core;

using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

namespace SMTPConformance.MessageFormat.Tests;

/// <summary>
/// RFC 5322 header fields as Hermod reads them: §2.2.3 unfolding, §3.3 date-time and the
/// obsolete dates of §4.3 (<see cref="MimeMessage"/>, which reads with <see cref="MimeDate"/>,
/// and the older <see cref="EMail"/>), §3.4 addresses with their comments and the obsolete
/// forms of §4.4 (<see cref="MailboxAddress"/>), §3.6.4 message identifiers and the threading
/// of a reply (<see cref="MailReplies"/>). §4: obsolete forms "MUST be accepted and parsed by
/// a conformant receiver".
/// </summary>
[TestFixture]
public sealed class MimeHeaderTests
{

    private static MimeMessage Message(String Header)
        => MimeMessage.Parse(Encoding.UTF8.GetBytes(Header + "\r\n\r\nBody.\r\n"));

    private static EMail OldMessage(String Header)
        => EMail.Parse((Header + "\r\n\r\nBody.").Split("\r\n"));


    #region Unfolding

    [Test(Description = "RFC 5322 §2.2.3: \"Unfolding is accomplished by simply removing any CRLF that is immediately followed by WSP\"")]
    public void A_folded_header_field_is_unfolded()
    {

        var message = Message("From: John Doe <jdoe@machine.example>\r\nSubject: This\r\n is a\r\n\ttest");

        Assert.That(message.Subject, Is.EqualTo("This is a\ttest"));

    }


    [Test(Description = "RFC 5322 Appendix A.6.3: \"folding lines that are made up entirely of white space are legal\" (obsolete), and white space before the colon")]
    public void Obsolete_white_space_in_the_header_is_read()
    {

        var message = Message("From  : John Doe <jdoe@machine.example>\r\nTo    : Mary Smith\r\n  \r\n          <mary@example.net>\r\nSubject     : Saying Hello");

        Assert.Multiple(() => {
            Assert.That(message.Subject,        Is.EqualTo("Saying Hello"));
            Assert.That(message.To[0].Address,  Is.EqualTo("mary@example.net"));
            Assert.That(message.To[0].Name,     Is.EqualTo("Mary Smith"));
        });

    }

    #endregion

    #region Dates

    public static IEnumerable<TestCaseData> CurrentDates()
    {

        TestCaseData Case(String source, String date, String expected)
            => new TestCaseData(date, DateTimeOffset.Parse(expected)).SetName($"{source}: {date.Replace("\r\n", " ")}");

        yield return Case("RFC 5322 A.1.1",       "Fri, 21 Nov 1997 09:55:06 -0600",                     "1997-11-21T09:55:06-06:00");
        yield return Case("RFC 5322 A.1.2",       "Tue, 1 Jul 2003 10:52:37 +0200",                      "2003-07-01T10:52:37+02:00");
        yield return Case("RFC 5322 A.4",         "Fri, 21 Nov 1997 11:00:00 -0600",                     "1997-11-21T11:00:00-06:00");
        yield return Case("RFC 5322 §3.3",        "21 Nov 1997 09:55:06 -0600",                          "1997-11-21T09:55:06-06:00");
        yield return Case("RFC 5322 §3.3",        "Fri, 21 Nov 1997 09:55 -0600",                        "1997-11-21T09:55:00-06:00");
        yield return Case("RFC 5322 §3.3",        "Mon, 2 Mar 2026 23:30:00 -0000",                      "2026-03-02T23:30:00+00:00");
        yield return Case("RFC 5322 A.5",         "Thu,\r\n      13\r\n        Feb\r\n          1969\r\n      23:32\r\n               -0330 (Newfoundland Time)",
                                                                                                          "1969-02-13T23:32:00-03:30");

    }

    public static IEnumerable<TestCaseData> ObsoleteDates()
    {

        TestCaseData Case(String source, String date, String expected)
            => new TestCaseData(date, DateTimeOffset.Parse(expected)).SetName($"{source}: {date}");

        yield return Case("RFC 5322 A.6.2",               "21 Nov 97 09:55:06 GMT",               "1997-11-21T09:55:06+00:00");
        yield return Case("RFC 5322 §4.3 two-digit year", "21 Nov 49 09:55:06 +0000",        "2049-11-21T09:55:06+00:00");
        yield return Case("RFC 5322 §4.3 two-digit year", "21 Nov 50 09:55:06 +0000",        "1950-11-21T09:55:06+00:00");
        yield return Case("RFC 5322 §4.3 three-digit year", "Fri, 21 Nov 097 09:55:06 +0000",     "1997-11-21T09:55:06+00:00");
        yield return Case("RFC 5322 §4.3 obs-zone",       "Fri, 21 Nov 1997 09:55:06 UT",         "1997-11-21T09:55:06+00:00");
        yield return Case("RFC 5322 §4.3 obs-zone",       "Fri, 21 Nov 1997 09:55:06 EST",        "1997-11-21T09:55:06-05:00");
        yield return Case("RFC 5322 §4.3 obs-zone",       "Fri, 21 Nov 1997 09:55:06 EDT",        "1997-11-21T09:55:06-04:00");
        yield return Case("RFC 5322 §4.3 obs-zone",       "Fri, 21 Nov 1997 09:55:06 CST",        "1997-11-21T09:55:06-06:00");
        yield return Case("RFC 5322 §4.3 obs-zone",       "Fri, 21 Nov 1997 09:55:06 MDT",        "1997-11-21T09:55:06-06:00");
        yield return Case("RFC 5322 §4.3 obs-zone",       "Fri, 21 Nov 1997 09:55:06 PST",        "1997-11-21T09:55:06-08:00");
        yield return Case("RFC 5322 §4.3 military zone",  "Fri, 21 Nov 1997 09:55:06 Z",          "1997-11-21T09:55:06+00:00");

    }


    [TestCaseSource(nameof(CurrentDates))]
    [Test(Description = "RFC 5322 §3.3: date-time = [ day-of-week \",\" ] date time [CFWS]; the zone is +hhmm or -hhmm")]
    public void A_date_is_parsed(String Date, DateTimeOffset Expected)
    {

        var parsed = Message("Date: " + Date).Date;

        Assert.That(parsed, Is.EqualTo(Expected));
        Assert.That(parsed!.Value.Offset, Is.EqualTo(Expected.Offset));

    }


    [TestCaseSource(nameof(ObsoleteDates))]
    [Test(Description = "RFC 5322 §4.3: two-digit years 00-49 are 20xx, 50-99 and three digits 19xx; \"EDT\" is semantically equivalent to \"-0400\" ...; military zones \"SHOULD all be considered equivalent to \"-0000\"\"")]
    public void An_obsolete_date_is_parsed(String Date, DateTimeOffset Expected)
    {
        Assert.That(Message("Date: " + Date).Date, Is.EqualTo(Expected));
    }


    [TestCase("Fri, 21 Nov 1997 09(comment):   55  :  06 -0600", TestName = "RFC 5322 A.6.3: a comment and white space inside the time")]
    [TestCase("Fri, 21 Nov 1997 09 : 55 : 06 -0600",            TestName = "RFC 5322 §4.3: obs-hour, obs-minute, obs-second with CFWS")]
    [Test(Description = "RFC 5322 §4.3: obs-hour = [CFWS] 2DIGIT [CFWS], obs-minute and obs-second alike; §4: obsolete forms \"MUST be accepted and parsed by a conformant receiver\"")]
    [Property("Finding", "E-6")]
    public void White_space_and_comments_inside_the_time_are_parsed(String Date)
    {
        Assert.That(Message("Date: " + Date).Date, Is.EqualTo(DateTimeOffset.Parse("1997-11-21T09:55:06-06:00")));
    }


    [Test(Description = "RFC 5322 §3.2.2: comment = \"(\" *([FWS] ccontent) [FWS] \")\", ccontent = ctext / quoted-pair / comment - nested comments are legal; a date with a 20 KB comment nested 10 000 deep is parsed in time")]
    [Property("Finding", "E-2")]
    public async Task A_date_with_deeply_nested_comments_is_parsed_in_time()
    {

        var header = "From: someone@example.org\r\nDate: Fri, 21 Nov 1997 09:55:06 -0600 " + new String('(', 10_000) + new String(')', 10_000);

        MimeMessage? message = null;

        try
        {
            message = await Task.Run(() => Message(header)).WaitAsync(TimeSpan.FromSeconds(2));
        }
        catch (TimeoutException)
        {
        }

        Assert.That(message?.Date, Is.EqualTo(DateTimeOffset.Parse("1997-11-21T09:55:06-06:00")),
                    "no result within 2 s - every pass of the comment remover takes away one level and copies the whole header");

    }


    [TestCaseSource(nameof(CurrentDates))]
    [Test(Description = "RFC 5322 §3.3 dates, read by the older EMail.Parse")]
    public void A_date_is_parsed_by_EMail(String Date, DateTimeOffset Expected)
    {
        Assert.That(OldMessage("From: someone@example.org\r\nDate: " + Date).Date, Is.EqualTo(Expected));
    }


    [TestCase("Fri, 21 Nov 1997 09:55:06 EST",                     "1997-11-21T09:55:06-05:00", TestName = "EMail: obs-zone EST")]
    [TestCase("Fri, 21 Nov 1997 09:55:06 PDT",                     "1997-11-21T09:55:06-07:00", TestName = "EMail: obs-zone PDT")]
    [TestCase("Fri, 21 Nov 1997 09:55:06 UT",                      "1997-11-21T09:55:06+00:00", TestName = "EMail: obs-zone UT")]
    [TestCase("Fri, 21 Nov 1997 09(comment):   55  :  06 -0600",   "1997-11-21T09:55:06-06:00", TestName = "EMail: RFC 5322 A.6.3 comment in the time")]
    [Test(Description = "RFC 5322 §4.3 obs-zone and obs-time, read by the older EMail.Parse; §4: obsolete forms \"MUST be accepted and parsed by a conformant receiver\"")]
    [Property("Finding", "E-7")]
    public void An_obsolete_date_is_parsed_by_EMail(String Date, String Expected)
    {
        Assert.That(OldMessage("From: someone@example.org\r\nDate: " + Date).Date, Is.EqualTo(DateTimeOffset.Parse(Expected)));
    }

    #endregion

    #region Addresses

    public static IEnumerable<TestCaseData> Mailboxes()
    {

        TestCaseData Case(String source, String header, params String[] expected)
            => new TestCaseData(header, expected).SetName($"{source}: {header.Replace("\r\n", " ")}");

        yield return Case("RFC 5322 A.1.1", "John Doe <jdoe@machine.example>",                                       "John Doe|jdoe@machine.example");
        yield return Case("RFC 5322 A.1.2", "\"Joe Q. Public\" <john.q.public@example.com>",                         "Joe Q. Public|john.q.public@example.com");
        yield return Case("RFC 5322 A.1.2", "Mary Smith <mary@x.test>, jdoe@example.org, Who? <one@y.test>",          "Mary Smith|mary@x.test", "|jdoe@example.org", "Who?|one@y.test");
        yield return Case("RFC 5322 A.1.2", "<boss@nil.test>, \"Giant; \\\"Big\\\" Box\" <sysservices@example.net>", "|boss@nil.test", "Giant; \"Big\" Box|sysservices@example.net");
        yield return Case("RFC 5322 A.1.3", "A Group:Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>;",       "Ed Jones|c@a.test", "|joe@where.test", "John|jdoe@one.test");
        yield return Case("RFC 5322 A.1.3", "Undisclosed recipients:;");
        yield return Case("RFC 5322 A.5",   "(Empty list)(start)Hidden recipients  :(nobody(that I know))  ;");
        yield return Case("RFC 5322 A.6.1", "Joe Q. Public <john.q.public@example.com>",                             "Joe Q. Public|john.q.public@example.com");
        yield return Case("RFC 5322 A.6.1", "Mary Smith <@node.test:mary@example.net>, , jdoe@example.org",          "Mary Smith|mary@example.net", "|jdoe@example.org");
        yield return Case("RFC 2047 §8",    "Nathaniel Borenstein <nsb@thumper.bellcore.com>\r\n      (=?iso-8859-8?b?7eXs+SDv4SDp7Oj08A==?=)",
                                                                                                                     "Nathaniel Borenstein|nsb@thumper.bellcore.com");

    }

    private static String[] Pairs(IEnumerable<MailboxAddress> Mailboxes)
        => [ .. Mailboxes.Select(mailbox => $"{mailbox.Name}|{mailbox.Address}") ];


    [TestCaseSource(nameof(Mailboxes))]
    [Test(Description = "RFC 5322 §3.4: mailbox = name-addr / addr-spec, group = display-name \":\" [group-list] \";\" - the examples of Appendix A, display names unquoted")]
    public void Mailboxes_are_read_with_their_display_names(String Header, String[] Expected)
    {
        Assert.That(Pairs(Message("To: " + Header).To), Is.EqualTo(Expected));
    }


    public static IEnumerable<TestCaseData> CommentedMailboxes()
    {

        TestCaseData Case(String source, String header, params String[] expected)
            => new TestCaseData(header, expected).SetName($"{source}: {header.Replace("\r\n", " ")}").
                   SetProperty("Finding", "E-1");

        yield return Case("RFC 5322 A.5",          "Pete(A nice \\) chap) <pete(his account)@silly.test(his host)>",          "Pete|pete@silly.test");
        yield return Case("RFC 5322 A.5",          "A Group(Some people)\r\n     :Chris Jones <c@(Chris's host.)public.example>,\r\n         joe@example.org,\r\n  John <jdoe@one.test> (my dear friend); (the end of the group)",
                                                                                                                              "Chris Jones|c@public.example", "|joe@example.org", "John|jdoe@one.test");
        yield return Case("RFC 5322 A.6.1",        "jdoe@test  . example",                                                    "|jdoe@test.example");
        yield return Case("RFC 5322 A.6.3",        "John Doe <jdoe@machine(comment).  example>",                              "John Doe|jdoe@machine.example");
        yield return Case("a comment after it",    "Alice <alice@example.org> (sent via <mallory@evil.example>)",             "Alice|alice@example.org");
        yield return Case("a comment after it",    "mallory@evil.example (<ceo@company.example>)",                            "|mallory@evil.example");

    }


    [TestCaseSource(nameof(CommentedMailboxes))]
    [Test(Description = "RFC 5322 §3.4: angle-addr = [CFWS] \"<\" addr-spec \">\" [CFWS]; §3.4.1 and §4.4: comments and white space around the parts of an addr-spec are not part of it")]
    public void Comments_are_no_part_of_the_address(String Header, String[] Expected)
    {
        Assert.That(Pairs(Message("To: " + Header).To), Is.EqualTo(Expected));
    }


    [Test(Description = "RFC 5322 §3.4: a comment after the addr-spec names no mailbox - the From domain Hermod signs for (DKIM) is the one RFC 5322 and its own DMARC check read")]
    [Property("Finding", "E-1")]
    public void The_DKIM_signing_domain_is_the_From_domain_RFC_5322_reads()
    {

        const String from = "mallory@evil.example (<ceo@company.example>)";

        Assert.Multiple(() => {
            Assert.That(MailAddressParser.ParseAddressList(from),                                                             Is.EqualTo(new[] { "mallory@evil.example" }), "the address parser the DMARC check uses");
            Assert.That(DkimSigning.FromDomain($"From: {from}\r\nTo: <a@example.net>\r\nSubject: Hi\r\n\r\nBody.\r\n"),     Is.EqualTo("evil.example"),                     "the domain whose DKIM key signs the message");
            Assert.That(OldMessage($"From: {from}\r\nSubject: Hi").From.Address.ToString(),                                   Is.EqualTo("mallory@evil.example"),             "EMail.From");
        });

    }

    #endregion

    #region Message identifiers and threads

    [TestCase("<1234@local.machine.example>",                     "1234@local.machine.example",      TestName = "RFC 5322 A.1.1 msg-id")]
    [TestCase("              <testabcd.1234@silly.test>",         "testabcd.1234@silly.test",        TestName = "RFC 5322 A.5 msg-id after white space")]
    [TestCase("<5678.21-Nov-1997@example.com>",                    "5678.21-Nov-1997@example.com",    TestName = "RFC 5322 A.6.1 msg-id")]
    [TestCase("<abcd.1234@local.machine.test> (a comment)",       "abcd.1234@local.machine.test",    TestName = "RFC 5322 §3.6.4 msg-id with CFWS")]
    [TestCase("<id@[192.0.2.1]>",                                  "id@[192.0.2.1]",                   TestName = "RFC 5322 §3.6.4 id-right as no-fold-literal")]
    [Test(Description = "RFC 5322 §3.6.4: msg-id = [CFWS] \"<\" id-left \"@\" id-right \">\" [CFWS]")]
    public void A_message_id_is_read(String Header, String Expected)
    {
        Assert.That(Message("Message-ID: " + Header).MessageId, Is.EqualTo(Expected));
    }


    [Test(Description = "RFC 5322 Appendix A.6.3, §4.5.4: obs-id-left = local-part, obs-id-right = domain - with their CFWS: \"<1234   @   local(blah)  .machine .example>\"; §4: \"MUST be accepted and parsed\"")]
    [Property("Finding", "E-8")]
    public void An_obsolete_message_id_is_read()
    {
        Assert.That(Message("Message-ID  : <1234   @   local(blah)  .machine .example>").MessageId, Is.EqualTo("1234@local.machine.example"));
    }


    [Test(Description = "RFC 5322 §3.6.4: references = \"References:\" 1*msg-id CRLF; obs-references = \"References:\" *(phrase / msg-id) - the phrases are no identifiers")]
    public void References_and_In_Reply_To_are_read_in_their_order()
    {

        var message = Message("In-Reply-To: <3456@example.net>\r\nReferences: <1234@local.machine.example>\r\n <3456@example.net> \"and a phrase\" <7890@example.org>");

        Assert.Multiple(() => {
            Assert.That(message.InReplyTo,   Is.EqualTo(new[] { "3456@example.net" }));
            Assert.That(message.References,  Is.EqualTo(new[] { "1234@local.machine.example", "3456@example.net", "7890@example.org" }));
        });

    }


    [Test(Description = "RFC 5322 §3.6.4: \"The \"In-Reply-To:\" field will contain the contents of the \"Message-ID:\" field of the message to which this one is a reply\"; References: the parent's References followed by its Message-ID (Appendix A.2)")]
    public void A_reply_names_its_parent_and_the_thread()
    {

        var parent = Message("From: Mary Smith <mary@example.net>\r\nMessage-ID: <3456@example.net>\r\nIn-Reply-To: <1234@local.machine.example>\r\nReferences: <1234@local.machine.example>");

        Assert.Multiple(() => {
            Assert.That(MailReplies.InReplyTo (parent), Is.EqualTo(new[] { "3456@example.net" }));
            Assert.That(MailReplies.References(parent), Is.EqualTo(new[] { "1234@local.machine.example", "3456@example.net" }));
        });

    }


    [Test(Description = "RFC 5322 §3.6.4: \"If the parent message does not contain a \"References:\" field but does have an \"In-Reply-To:\" field containing a single message identifier, then the \"References:\" field will contain the contents of the parent's \"In-Reply-To:\" field followed by the contents of the parent's \"Message-ID:\" field\"")]
    [Property("Finding", "E-9")]
    public void A_reply_to_a_parent_without_References_takes_its_In_Reply_To()
    {

        var parent = Message("From: Mary Smith <mary@example.net>\r\nMessage-ID: <3456@example.net>\r\nIn-Reply-To: <1234@local.machine.example>");

        Assert.That(MailReplies.References(parent), Is.EqualTo(new[] { "1234@local.machine.example", "3456@example.net" }));

    }


    [Test(Description = "RFC 5322 §3.6.5: \"only one instance of the literal string \"Re: \" ought to be used\"")]
    public void A_reply_subject_has_one_Re()
    {
        Assert.That(MailReplies.ReplySubject("Re: Re: Saying Hello"), Is.EqualTo("Re: Saying Hello"));
    }

    #endregion

}
