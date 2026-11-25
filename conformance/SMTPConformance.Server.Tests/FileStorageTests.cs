using System.Text;
using System.Text.RegularExpressions;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// The server's default store - <c>FileMailStorage</c>, which a server given no store of its
/// own keeps local mail in: one file per message, the message as delivered, with what the
/// server found out about it (the envelope, SPF, DKIM, DMARC) written on top as header
/// fields. What it writes has to be a message still (RFC 5322 §2.2), beginning with its
/// Return-Path (RFC 5321 §4.4); and a valid message has to be one it can store.
/// </summary>
[TestFixture]
public sealed class FileStorageTests : HermodServerTestBase
{

    protected override HermodSmtpServerFixtureOptions Options
        => new() { DefaultFileStorage = true };


    #region Helpers

    /// <summary>
    /// The stored file that holds the marker, as text - null if none comes in time.
    /// </summary>
    private async Task<String?> StoredFile(String Marker)
    {

        var until = DateTime.UtcNow.AddSeconds(10);

        while (DateTime.UtcNow < until)
        {

            foreach (var file in Directory.GetFiles(Server.StorageDirectory, "*.eml"))
            {
                var text = Encoding.UTF8.GetString(await File.ReadAllBytesAsync(file));
                if (text.Contains(Marker, StringComparison.Ordinal))
                    return text;
            }

            await Task.Delay(50);

        }

        return null;

    }

    /// <summary>
    /// The stored files that hold the marker.
    /// </summary>
    private async Task<Int32> StoredFiles(String Marker, Int32 Expected)
    {

        var until = DateTime.UtcNow.AddSeconds(10);
        var count = 0;

        while (DateTime.UtcNow < until)
        {

            count = 0;

            foreach (var file in Directory.GetFiles(Server.StorageDirectory, "*.eml"))
                if (Encoding.UTF8.GetString(await File.ReadAllBytesAsync(file)).Contains(Marker, StringComparison.Ordinal))
                    count++;

            if (count >= Expected)
                break;

            await Task.Delay(50);

        }

        return count;

    }

    /// <summary>
    /// The header section of a stored message: up to its first empty line.
    /// </summary>
    private static String Header(String Stored)
    {
        var end = Stored.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        return end >= 0 ? Stored[..(end + 2)] : Stored;
    }

    /// <summary>
    /// The lines of a text, as a reader that takes CR, LF or CR LF for a line end reads them.
    /// </summary>
    private static String[] Lines(String Text)
        => Regex.Split(Text, "\r\n|\r|\n");

    private static TXT Txt(String Name, String Text)
        => new (DNSServiceName.Parse(Name), DNSQueryClasses.IN, TimeSpan.FromHours(1), Text);

    /// <summary>
    /// Publish an SPF record for a domain of the test's own, send a message from it, and give
    /// the stored file.
    /// </summary>
    private async Task<(String? Stored, String Marker, RawSmtpClient Client)> SendFromDomainWithSpf(String Spf)
    {

        var marker = Marker();
        var domain = $"{marker}.spf.example";

        Server.Dns.Answer(domain, DNSResourceRecordTypes.TXT, [ Txt(domain, Spf) ]);

        var client = await Server.ConnectAndEhloAsync();

        await client.SendMailAsync($"sender@{domain}", "alice@hermod.test",
                                   RawSmtpClientExtensions.Message($"sender@{domain}", "alice@hermod.test", marker, "hello"));

        return (await StoredFile(marker), marker, client);

    }

    /// <summary>
    /// A message with the given Message-ID, and the marker as its subject.
    /// </summary>
    private static String MessageWithId(String MessageId, String Marker)

        => "From: <sender@client.example>\r\n" +
           "To: <alice@hermod.test>\r\n" +
           $"Subject: {Marker}\r\n" +
           $"Message-ID: {MessageId}\r\n" +
           "Date: Wed, 25 Nov 2026 12:00:00 +0000\r\n" +
           "\r\n" +
           "hello\r\n";

    #endregion


    #region S-48: what DNS says, written into the header as it is

    public static IEnumerable<TestCaseData> LineBreaks()
    {

        TestCaseData Case(String Name, String LineBreak)
            => new TestCaseData(LineBreak).SetName($"A line break in a DNS record makes no header field of the stored message: {Name}")
                                          .SetProperty("Finding", "S-48");

        yield return Case("CR LF",  "\r\n");
        yield return Case("LF",     "\n");
        yield return Case("CR",     "\r");

    }

    [TestCaseSource(nameof(LineBreaks))]
    [Description("RFC 5322 §2.2: \"A field body MUST NOT include CR and LF except when used in 'folding' and 'unfolding'\" - a TXT record is octets, a line break among them too, and the SPF record of the sender's domain is the sender's to publish: written into the stored header as it is, \"v=spf1 -all<CR><LF>X-DMARC-Result: Pass\" is a field of its own, a DMARC pass the server never found")]
    public async Task A_line_break_in_a_DNS_record_makes_no_header_field_of_the_stored_message(String LineBreak)
    {

        var (stored, _, client) = await SendFromDomainWithSpf($"v=spf1 -all{LineBreak}X-DMARC-Result: Pass");
        await using var _ = client;

        Assert.That(stored,                  Is.Not.Null, Explain(client));
        Assert.That(Lines(Header(stored!)),  Has.None.EqualTo("X-DMARC-Result: Pass"), Header(stored!));

    }


    [Test(Description = "RFC 5322 §2.1: \"A message consists of header fields [...] optionally followed by a message body\", the header ending at the first empty line - an empty line in the SPF record of the sender's domain, written into the stored header, ends it there, and the message's own header fields are its body")]
    [Property("Finding", "S-48")]
    public async Task An_empty_line_in_a_DNS_record_does_not_end_the_stored_header()
    {

        var (stored, marker, client) = await SendFromDomainWithSpf("v=spf1 -all\r\n\r\nX-Injected: body");
        await using var _ = client;

        Assert.That(stored,          Is.Not.Null, Explain(client));
        Assert.That(Header(stored!), Does.Contain($"\r\nSubject: {marker}\r\n"), Header(stored!));

    }


    [Test(Description = "RFC 5322 §2.2: header fields are lines \"terminated by CRLF\" - with an SPF record of the usual kind, the stored header is the message's header, and its own fields are in it")]
    [Property("Finding", "S-48")]
    public async Task With_an_SPF_record_of_the_usual_kind_the_stored_header_is_whole()
    {

        var (stored, marker, client) = await SendFromDomainWithSpf("v=spf1 ip4:127.0.0.1 -all");
        await using var _ = client;

        Assert.That(stored,          Is.Not.Null, Explain(client));
        Assert.That(Header(stored!), Does.Contain($"\r\nSubject: {marker}\r\n"));
        Assert.That(Header(stored!), Does.Not.Match("\r(?!\n)|(?<!\r)\n"), "no bare CR, no bare LF");

    }

    #endregion

    #region S-49: the Return-Path first

    [Test(Description = "RFC 5321 §4.4: \"When the delivery SMTP server makes the 'final delivery' of a message, it inserts a return-path line at the beginning of the mail data\"; RFC 5322 §3.6: \"the trace header fields and resent header fields MUST NOT be reordered, and SHOULD be kept in blocks prepended to the message\" - the stored message begins with its Return-Path, not with fields of the store's own")]
    [Property("Finding", "S-49")]
    public async Task A_stored_message_begins_with_its_Return_Path()
    {

        await using var client = await Server.ConnectAndEhloAsync();
        var marker = Marker();

        await client.SendMailAsync("sender@client.example", "alice@hermod.test",
                                   RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", marker, "hello"));

        var stored = await StoredFile(marker);

        Assert.That(stored, Is.Not.Null, Explain(client));
        Assert.That(stored, Does.StartWith("Return-Path: <sender@client.example>\r\n"), Header(stored!));

    }


    [Test(Description = "RFC 5321 §4.4: Return-path-line = \"Return-Path:\" FWS Reverse-path, at the beginning of the mail data - a bounce, sent with the null reverse-path, is stored beginning with \"Return-Path: <>\"")]
    [Property("Finding", "S-49")]
    public async Task A_stored_bounce_begins_with_an_empty_Return_Path()
    {

        await using var client = await Server.ConnectAndEhloAsync();
        var marker = Marker();

        await client.CommandAsync("MAIL FROM:<>");
        await client.CommandAsync("RCPT TO:<alice@hermod.test>");
        await client.DataAsync(RawSmtpClientExtensions.Message("mailer-daemon@client.example", "alice@hermod.test", marker, "returned"));

        var stored = await StoredFile(marker);

        Assert.That(stored, Is.Not.Null, Explain(client));
        Assert.That(stored, Does.StartWith("Return-Path: <>\r\n"), Header(stored!));

    }

    #endregion

    #region S-50: a message the store cannot keep

    [TestCase(300)]
    [TestCase(900)]
    [Description("RFC 5322 §3.6.4: msg-id = \"<\" id-left \"@\" id-right \">\", of no length of its own but the line's (§2.1.1: 998 characters); RFC 5321 §4.5.3.1: \"To the maximum extent possible, implementation techniques that impose no limits on the length of these objects should be used\" - a message whose Message-ID is longer than a file name may be is a valid message all the same, and is stored, not refused with 451 at every try until its sender gives up")]
    [Property("Finding", "S-50")]
    public async Task A_message_with_a_long_Message_ID_is_stored(Int32 Length)
    {

        await using var client = await Server.ConnectAndEhloAsync();
        var marker = Marker();

        await client.CommandAsync("MAIL FROM:<sender@client.example>");
        await client.CommandAsync("RCPT TO:<alice@hermod.test>");

        var (_, final) = await client.DataAsync(MessageWithId("<" + new String('m', Length) + "@client.example>", marker));

        Assert.That(final?.Code, Is.EqualTo(250), Explain(client));
        Assert.That(await StoredFile(marker), Is.Not.Null, Explain(client));

    }


    [Test(Description = "RFC 5321 §6.1: \"the receiver MUST NOT lose the message\" - two messages with one Message-ID, a copy and its original, are two messages, and both are stored")]
    [Property("Finding", "S-50")]
    public async Task Two_messages_with_one_Message_ID_are_both_stored()
    {

        await using var client = await Server.ConnectAndEhloAsync();
        var marker = Marker();
        var id     = $"<{marker}@client.example>";

        for (var i = 0; i < 2; i++)
        {
            await client.CommandAsync("MAIL FROM:<sender@client.example>");
            await client.CommandAsync("RCPT TO:<alice@hermod.test>");
            var (_, final) = await client.DataAsync(MessageWithId(id, marker));
            Assert.That(final?.Code, Is.EqualTo(250), Explain(client));
        }

        Assert.That(await StoredFiles(marker, 2), Is.EqualTo(2), Explain(client));

    }

    #endregion

}
