using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 5321 §4.1.2: the paths of MAIL and RCPT as the grammar has them - Path = "&lt;" [ A-d-l
/// ":" ] Mailbox "&gt;", Local-part = Dot-string / Quoted-string - and RFC 6533 §3, the UTF-8
/// address type in ORCPT. Relaying is open here (no AUTH needed), so that a relayed recipient is
/// a queued one.
/// </summary>
[TestFixture]
public sealed class PathSyntaxTests : HermodServerTestBase
{

    protected override HermodSmtpServerFixtureOptions Options
        => new() { RequireAuthForRelay = false };


    /// <summary>
    /// MAIL, RCPT and a message with a marker, as the commands are given; the replies and what
    /// was stored with the marker.
    /// </summary>
    private async Task<(SmtpReply Mail, SmtpReply Rcpt, SmtpReply? Final, StoredMessage? Stored, String Marker, RawSmtpClient Client)> Send(String MailFrom, String RcptTo)
    {

        var client = await Server.ConnectAndEhloAsync();
        var marker = Marker();

        var mail   = await client.CommandAsync(MailFrom);
        var rcpt   = await client.CommandAsync(RcptTo);

        SmtpReply? final = null;

        if (mail.Code == 250 && rcpt.Code == 250)
            (_, final) = await client.DataAsync(RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", marker, "hello"));

        var stored = final?.Code == 250 ? await Server.Storage.WaitForMarkerAsync(marker, TimeSpan.FromSeconds(2)) : null;

        return (mail, rcpt, final, stored, marker, client);

    }


    #region S-31: source routes

    public static IEnumerable<TestCaseData> RoutedLocalRecipients()
    {

        TestCaseData Case(String Path)
            => new TestCaseData(Path).SetName($"RCPT TO:{Path} is delivered to alice@hermod.test")
                                     .SetProperty("Finding", "S-31");

        yield return Case("<@relay.example:alice@hermod.test>");
        yield return Case("<@one.example,@two.example:alice@hermod.test>");

    }

    [TestCaseSource(nameof(RoutedLocalRecipients))]
    [Description("RFC 5321 §4.1.2: A-d-l, \"the so-called \"source route\", MUST BE accepted, SHOULD NOT be generated, and SHOULD be ignored\"; §4.1.1.3: \"Receiving systems MUST recognize source route syntax but SHOULD strip off the source route specification and utilize the domain name associated with the mailbox as if the source route had not been provided\"")]
    public async Task A_source_route_before_a_local_mailbox_is_ignored(String Path)
    {

        var (_, rcpt, final, stored, _, client) = await Send("MAIL FROM:<sender@client.example>", $"RCPT TO:{Path}");
        await using var _ = client;

        Assert.Multiple(() => {
            Assert.That(rcpt.Code,          Is.EqualTo(250),                         Explain(client));
            Assert.That(final?.Code,        Is.EqualTo(250),                         Explain(client));
            Assert.That(stored?.EnvelopeTo, Is.EqualTo(new[] { "alice@hermod.test" }), Explain(client));
        });

    }


    [Test(Description = "RFC 5321 §4.1.2: Reverse-path = Path / \"<>\", Path = \"<\" [ A-d-l \":\" ] Mailbox \">\" - the source route \"SHOULD be ignored\" in the reverse-path too; Appendix C: \"source routes SHOULD NOT appear in the reverse-path\" - what remains is the mailbox bounces go to")]
    [Property("Finding", "S-31")]
    public async Task A_source_route_in_the_reverse_path_is_ignored()
    {

        var (mail, _, final, stored, _, client) = await Send("MAIL FROM:<@relay.example:sender@client.example>", "RCPT TO:<alice@hermod.test>");
        await using var _ = client;

        Assert.Multiple(() => {
            Assert.That(mail.Code,            Is.EqualTo(250),                     Explain(client));
            Assert.That(final?.Code,          Is.EqualTo(250),                     Explain(client));
            Assert.That(stored?.EnvelopeFrom, Is.EqualTo("sender@client.example"), Explain(client));
        });

    }


    [Test(Description = "RFC 5321 §3.3: servers \"SHOULD ignore the routes or MAY decline to support the relaying they imply\"; Appendix C: \"The mailbox (here, JOE@THREE) is an absolute address, and the route is information about how to get there\" - a relayed recipient behind a route is refused, or queued for the domain of its mailbox, without the route")]
    [Property("Finding", "S-31")]
    public async Task A_source_route_before_a_remote_mailbox_is_ignored_or_refused()
    {

        var (_, rcpt, final, _, marker, client) = await Send("MAIL FROM:<sender@client.example>", "RCPT TO:<@hop.example:bob@elsewhere.example>");
        await using var _ = client;

        if (rcpt.Class == 5)
            return;     // "MAY decline to support the relaying they imply"

        var relayed = Server.Queue.Queued.Where(mail => mail.MessageContent.Contains(marker)).ToArray();

        Assert.Multiple(() => {
            Assert.That(final?.Code,                            Is.EqualTo(250),                             Explain(client));
            Assert.That(relayed.Select(mail => mail.TargetDomain), Is.EqualTo(new[] { "elsewhere.example" }),     Explain(client));
            Assert.That(relayed.SelectMany(mail => mail.EnvelopeTo), Is.EqualTo(new[] { "bob@elsewhere.example" }), Explain(client));
        });

    }

    #endregion


    #region S-32: quoted local parts

    public static IEnumerable<TestCaseData> QuotedLocalRecipients()
    {

        TestCaseData Case(String Mailbox, String Why)
            => new TestCaseData(Mailbox).SetName($"RCPT TO:<{Mailbox}> is a local recipient - {Why}")
                                        .SetProperty("Finding", "S-32");

        yield return Case("\"alice@home\"@hermod.test", "an @ in the quoted local part");
        yield return Case("\"a>b\"@hermod.test",        "a > in the quoted local part");

    }

    [TestCaseSource(nameof(QuotedLocalRecipients))]
    [Description("RFC 5321 §4.1.2: Mailbox = Local-part \"@\" ( Domain / address-literal ), Local-part = Dot-string / Quoted-string, qtextSMTP = %d32-33 / %d35-91 / %d93-126 - \"within a quoted string, any ASCII graphic or space is permitted\", the \"@\" and the \">\" too: the domain is what follows the local part, and the path ends at the \">\" after it")]
    public async Task A_quoted_local_part_is_one_local_part(String Mailbox)
    {

        var (_, rcpt, final, stored, _, client) = await Send("MAIL FROM:<sender@client.example>", $"RCPT TO:<{Mailbox}>");
        await using var _ = client;

        Assert.Multiple(() => {
            Assert.That(rcpt.Code,          Is.EqualTo(250),             Explain(client));
            Assert.That(final?.Code,        Is.EqualTo(250),             Explain(client));
            Assert.That(stored?.EnvelopeTo, Is.EqualTo(new[] { Mailbox }), Explain(client));
        });

    }


    [Test(Description = "RFC 5321 §4.1.2: Reverse-path = Path / \"<>\", with a Quoted-string local part that holds a \">\" - the path ends at the \">\" after the mailbox, and the parameters come after it")]
    [Property("Finding", "S-32")]
    public async Task A_quoted_local_part_with_an_angle_bracket_is_a_reverse_path()
    {

        var (mail, _, final, stored, _, client) = await Send("MAIL FROM:<\"x>y\"@client.example> BODY=8BITMIME", "RCPT TO:<alice@hermod.test>");
        await using var _ = client;

        Assert.Multiple(() => {
            Assert.That(mail.Code,            Is.EqualTo(250),                    Explain(client));
            Assert.That(final?.Code,          Is.EqualTo(250),                    Explain(client));
            Assert.That(stored?.EnvelopeFrom, Is.EqualTo("\"x>y\"@client.example"), Explain(client));
        });

    }


    [Test(Description = "RFC 5321 §4.1.2: a Quoted-string local part with an \"@\" in a relayed recipient - queued for the domain after the local part")]
    [Property("Finding", "S-32")]
    public async Task A_quoted_local_part_with_an_at_sign_is_relayed_to_its_domain()
    {

        var (_, rcpt, final, _, marker, client) = await Send("MAIL FROM:<sender@client.example>", "RCPT TO:<\"bob@inside\"@elsewhere.example>");
        await using var _ = client;

        var relayed = Server.Queue.Queued.Where(mail => mail.MessageContent.Contains(marker)).ToArray();

        Assert.Multiple(() => {
            Assert.That(rcpt.Code,                                   Is.EqualTo(250),                                  Explain(client));
            Assert.That(final?.Code,                                 Is.EqualTo(250),                                  Explain(client));
            Assert.That(relayed.Select(mail => mail.TargetDomain),   Is.EqualTo(new[] { "elsewhere.example" }),          Explain(client));
            Assert.That(relayed.SelectMany(mail => mail.EnvelopeTo), Is.EqualTo(new[] { "\"bob@inside\"@elsewhere.example" }), Explain(client));
        });

    }


    [Test(Description = "RFC 5321 §4.1.2: a Quoted-string local part with a space in it, and Rcpt-parameters after the path")]
    public async Task A_quoted_local_part_with_a_space_is_a_local_recipient()
    {

        var (_, rcpt, final, stored, _, client) = await Send("MAIL FROM:<sender@client.example>", "RCPT TO:<\"john doe\"@hermod.test> NOTIFY=NEVER");
        await using var _ = client;

        Assert.Multiple(() => {
            Assert.That(rcpt.Code,          Is.EqualTo(250),                              Explain(client));
            Assert.That(final?.Code,        Is.EqualTo(250),                              Explain(client));
            Assert.That(stored?.EnvelopeTo, Is.EqualTo(new[] { "\"john doe\"@hermod.test" }), Explain(client));
        });

    }

    #endregion


    #region S-34: the UTF-8 address type in ORCPT

    [Test(Description = "RFC 6533 §3: \"An SMTP server that advertises both the SMTPUTF8 extension [RFC6531] and the DSN extension [RFC3461] MUST accept a UTF-8 address type in the ORCPT parameter including 8-bit UTF-8 characters\" - utf-8-addr-unitext, the address in UTF-8")]
    [Property("Finding", "S-34")]
    public async Task An_ORCPT_of_the_UTF_8_address_type_in_UTF_8_is_accepted()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        await client.CommandAsync("MAIL FROM:<sender@client.example> SMTPUTF8");
        var rcpt = await client.CommandAsync("RCPT TO:<jörg@hermod.test> ORCPT=utf-8;jörg@hermod.test");

        Assert.That(rcpt.Code, Is.EqualTo(250), Explain(client));

    }


    [Test(Description = "RFC 6533 §3: utf-8-addr-xtext = 1*(QCHAR / EmbeddedUnicodeChar), \"Safe for use in the ORCPT [RFC3461] parameter even when SMTPUTF8 SMTP extension is not advertised\" - \"\\x{F6}\" for the ö")]
    public async Task An_ORCPT_of_the_UTF_8_address_type_in_ASCII_is_accepted()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        await client.CommandAsync("MAIL FROM:<sender@client.example> SMTPUTF8");
        var rcpt = await client.CommandAsync("RCPT TO:<jörg@hermod.test> ORCPT=utf-8;j\\x{F6}rg@hermod.test");

        Assert.That(rcpt.Code, Is.EqualTo(250), Explain(client));

    }

    #endregion

}
