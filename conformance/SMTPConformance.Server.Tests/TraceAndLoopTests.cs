using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 5321 §4.4 and §6.3: what the server writes on top of a message - the Return-Path line
/// at final delivery, the Received line of its hop, from what the TCP connection says and not
/// from what the client claims - and how it stops a message that goes round in circles.
/// Relaying is open here (no AUTH needed), so that a relayed message is a queued one.
/// </summary>
[TestFixture]
public sealed partial class TraceAndLoopTests : HermodServerTestBase
{

    protected override HermodSmtpServerFixtureOptions Options
        => new() { RequireAuthForRelay = false };


    #region Helpers

    /// <summary>
    /// A message with the given number of Received fields on top - as many hops as it says it
    /// went through - and a marker in its subject.
    /// </summary>
    private static String MessageWithHops(Int32 Hops, String From, String To, String Marker)
    {

        var trace = new StringBuilder();
        var date  = DateTimeOffset.UtcNow.ToString("ddd, dd MMM yyyy HH:mm:ss +0000", CultureInfo.InvariantCulture);

        for (var hop = Hops; hop > 0; hop--)
            trace.Append($"Received: from hop{hop - 1}.example ([192.0.2.{hop % 250 + 1}])\r\n\tby hop{hop}.example with ESMTP id H{hop};\r\n\t{date}\r\n");

        return trace + RawSmtpClientExtensions.Message(From, To, Marker, "around and around");

    }

    /// <summary>
    /// The header section of a stored message, its fields unfolded, in order.
    /// </summary>
    private static IReadOnlyList<String> Fields(String Raw)
    {

        var end    = Raw.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var header = end >= 0 ? Raw[..(end + 2)] : Raw;

        return [.. Regex.Split(header, "\r\n(?![ \t])").Where(field => field.Length > 0).Select(field => Regex.Replace(field, "\r\n[ \t]+", " "))];

    }

    private static String Unfolded(StoredMessage Stored, String Name)
        => Fields(Stored.Raw).First(field => field.StartsWith(Name + ":", StringComparison.OrdinalIgnoreCase));

    // RFC 5321 §4.1.2: Domain = sub-domain *("." sub-domain), sub-domain = Let-dig [Ldh-str].
    private const String Domain         = @"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*";
    private const String AddressLiteral = @"\[[^\[\]\s]+\]";

    // RFC 5321 §4.4: From-domain = "FROM" FWS Extended-Domain; Extended-Domain = Domain /
    // ( Domain FWS "(" TCP-info ")" ) / ( address-literal FWS "(" TCP-info ")" ); TCP-info =
    // address-literal / ( Domain FWS address-literal ) - and then By-domain = CFWS "BY" ...
    [GeneratedRegex(@"^Received:\s+from\s+(?<helo>" + Domain + "|" + AddressLiteral + @")\s+\((?:(?<name>" + Domain + @")\s+)?(?<literal>" + AddressLiteral + @")\)\s+by\s", RegexOptions.IgnoreCase)]
    private static partial Regex FromDomain();

    #endregion


    #region S-28: loops

    [Test(Description = "RFC 5321 §6.3: \"servers MUST contain provisions for detecting and stopping trivial loops\"; counting Received fields \"has proven to be an effective\" method, with \"a large rejection threshold, normally at least 100\" - a message that has been through 150 hops is refused, with X.4.6 \"Routing loop detected\" (RFC 3463 §3.5)")]
    [Property("Finding", "S-28")]
    public async Task A_message_with_150_Received_fields_is_refused()
    {

        await using var client = await Server.ConnectAndEhloAsync();
        var marker = Marker();

        await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");
        var (_, final) = await client.DataAsync(MessageWithHops(150, "sender@client.example", "alice@hermod.test", marker));

        await Task.Delay(300);

        Assert.Multiple(() => {
            Assert.That(final?.Class,        Is.EqualTo(5),       Explain(client));
            Assert.That(final?.EnhancedCode, Is.EqualTo("5.4.6"), Explain(client));
            Assert.That(Server.Storage.Messages.Where(stored => stored.Raw.Contains(marker)), Is.Empty, "the looping message is not delivered");
        });

    }


    [Test(Description = "RFC 5321 §6.3: a relay that does not stop a loop sends the message on and on - the message with 150 Received fields for another domain is not queued for relay")]
    [Property("Finding", "S-28")]
    public async Task A_message_with_150_Received_fields_is_not_relayed()
    {

        await using var client = await Server.ConnectAndEhloAsync();
        var marker = Marker();

        var (_, rcpts) = await client.EnvelopeAsync("sender@client.example", "bob@elsewhere.example");
        Assume.That(rcpts[0].Code, Is.EqualTo(250), Explain(client));

        var (_, final) = await client.DataAsync(MessageWithHops(150, "sender@client.example", "bob@elsewhere.example", marker));

        Assert.Multiple(() => {
            Assert.That(final?.Class, Is.EqualTo(5), Explain(client));
            Assert.That(Server.Queue.Queued.Where(mail => mail.MessageContent.Contains(marker)), Is.Empty, "the looping message is not relayed");
        });

    }


    [Test(Description = "RFC 5321 §6.3: \"a large rejection threshold, normally at least 100 Received entries\" - a message that has been through 50 hops is delivered and relayed as any other")]
    public async Task A_message_with_50_Received_fields_is_delivered_and_relayed()
    {

        await using var client = await Server.ConnectAndEhloAsync();
        var marker = Marker();

        await client.EnvelopeAsync("sender@client.example", "alice@hermod.test", "bob@elsewhere.example");
        var (_, final) = await client.DataAsync(MessageWithHops(50, "sender@client.example", "alice@hermod.test", marker));

        var stored = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.Multiple(() => {
            Assert.That(final?.Code, Is.EqualTo(250), Explain(client));
            Assert.That(stored,      Is.Not.Null,     Explain(client));
            Assert.That(Server.Queue.Queued.Where(mail => mail.MessageContent.Contains(marker)), Is.Not.Empty, Explain(client));
        });

    }

    #endregion


    #region S-29: Return-Path

    [Test(Description = "RFC 5321 §4.4: \"When the delivery SMTP server makes the \"final delivery\" of a message, it inserts a return-path line at the beginning of the mail data. This use of return-path is required; mail systems MUST support it\" - Return-path-line = \"Return-Path:\" FWS Reverse-path, the first line of the stored message")]
    [Property("Finding", "S-29")]
    public async Task A_delivered_message_begins_with_the_Return_Path()
    {

        await using var client = await Server.ConnectAndEhloAsync();
        var marker = Marker();

        await client.SendMailAsync("sender@client.example", "alice@hermod.test",
                                   RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", marker, "hello"));

        var stored = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.That(stored, Is.Not.Null, Explain(client));
        Assert.That(stored!.Raw, Does.StartWith("Return-Path: <sender@client.example>\r\n"), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.4: Return-path-line = \"Return-Path:\" FWS Reverse-path, Reverse-path = Path / \"<>\" - a bounce, sent with the null reverse-path, is delivered with \"Return-Path: <>\"")]
    [Property("Finding", "S-29")]
    public async Task A_delivered_bounce_begins_with_an_empty_Return_Path()
    {

        await using var client = await Server.ConnectAndEhloAsync();
        var marker = Marker();

        await client.CommandAsync("MAIL FROM:<>");
        await client.CommandAsync("RCPT TO:<alice@hermod.test>");
        await client.DataAsync(RawSmtpClientExtensions.Message("mailer-daemon@client.example", "alice@hermod.test", marker, "returned"));

        var stored = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.That(stored, Is.Not.Null, Explain(client));
        Assert.That(stored!.Raw, Does.StartWith("Return-Path: <>\r\n"), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.4: \"exactly one return path SHOULD be present when the message is delivered\"; \"SMTP servers making final delivery MAY remove Return-path header fields before adding their own\" - a Return-Path the client wrote into the message is not what the mailbox reads as where bounces go")]
    [Property("Finding", "S-29")]
    public async Task A_Return_Path_in_the_message_is_not_the_one_delivered()
    {

        await using var client = await Server.ConnectAndEhloAsync();
        var marker = Marker();

        await client.SendMailAsync("sender@client.example", "alice@hermod.test",
                                   "Return-Path: <forged@evil.example>\r\n" +
                                   RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", marker, "hello"));

        var stored = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.That(stored, Is.Not.Null, Explain(client));

        var returnPaths = Fields(stored!.Raw).Where(field => field.StartsWith("Return-Path:", StringComparison.OrdinalIgnoreCase)).ToArray();

        Assert.That(returnPaths, Is.EqualTo(new[] { "Return-Path: <sender@client.example>" }), stored.Raw);

    }


    [Test(Description = "RFC 8098 §2.3: the delivering MTA inserts Original-Recipient \"at the beginning of the message (along with the Return-Path header field)\"; RFC 5321 §4.4: the Return-Path line is the first - also for the copy that carries an Original-Recipient")]
    [Property("Finding", "S-29")]
    public async Task A_copy_with_an_Original_Recipient_begins_with_the_Return_Path()
    {

        await using var client = await Server.ConnectAndEhloAsync();
        var marker = Marker();

        await client.CommandAsync("MAIL FROM:<sender@client.example>");
        await client.CommandAsync("RCPT TO:<alice@hermod.test> ORCPT=rfc822;team@hermod.test");
        await client.DataAsync(RawSmtpClientExtensions.Message("sender@client.example", "team@hermod.test", marker, "hello"));

        var stored = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.That(stored, Is.Not.Null, Explain(client));
        Assert.Multiple(() => {
            Assert.That(stored!.Raw,               Does.StartWith("Return-Path: <sender@client.example>\r\n"), Explain(client));
            Assert.That(Fields(stored.Raw).Take(3), Has.Some.StartsWith("Original-Recipient: rfc822;team@hermod.test"), stored.Raw);
        });

    }


    [Test(Description = "RFC 5321 §4.4: the Return-Path line marks final delivery, \"the message has left the SMTP environment\"; a message relayed on goes on with its envelope - no Return-Path is added to it")]
    public async Task A_relayed_message_gets_no_Return_Path()
    {

        await using var client = await Server.ConnectAndEhloAsync();
        var marker = Marker();

        await client.SendMailAsync("sender@client.example", "bob@elsewhere.example",
                                   RawSmtpClientExtensions.Message("sender@client.example", "bob@elsewhere.example", marker, "hello"));

        var relayed = Server.Queue.Queued.SingleOrDefault(mail => mail.MessageContent.Contains(marker));

        Assert.That(relayed, Is.Not.Null, Explain(client));
        Assert.That(Fields(relayed!.MessageContent).Where(field => field.StartsWith("Return-Path:", StringComparison.OrdinalIgnoreCase)), Is.Empty, relayed.MessageContent);

    }

    #endregion


    #region S-30: the Received line says what the connection says

    public static IEnumerable<TestCaseData> ClaimsInEhlo()
    {

        TestCaseData Case(String Ehlo, String Name)
            => new TestCaseData(Ehlo).SetName($"Received from a client that says \"EHLO {Name}\"")
                                     .SetProperty("Finding", "S-30");

        yield return Case("client.example (mail.trusted.example [203.0.113.5])", "client.example (mail.trusted.example [203.0.113.5])");
        yield return Case("mail.trusted.example by mx.trusted.example",         "mail.trusted.example by mx.trusted.example");
        yield return Case("client.example; Mon, 1 Jan 2001 00:00:00 +0000",     "client.example; Mon, 1 Jan 2001 ...");

    }

    [TestCaseSource(nameof(ClaimsInEhlo))]
    [Description("RFC 5321 §4.4: TCP-info is \"Information derived by server from TCP connection not client EHLO\"; Extended-Domain = Domain / ( Domain FWS \"(\" TCP-info \")\" ) / ( address-literal FWS \"(\" TCP-info \")\" ) - an EHLO argument that is no Domain is refused (§4.1.4: \"501, 500, 502, or 550 failure replies MUST be returned as appropriate\"), or kept out of the Received line, whose TCP-info names the client's address")]
    public async Task The_Received_line_names_the_address_of_the_connection(String Ehlo)
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var _ = client;

        var ehlo = await client.CommandAsync("EHLO " + Ehlo);

        if (ehlo.Class == 5)
            return;     // refused: there is no Received line to forge

        var marker = Marker();
        await client.SendMailAsync("sender@client.example", "alice@hermod.test",
                                   RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", marker, "hello"));

        var stored = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.That(stored, Is.Not.Null, Explain(client));

        var received = Unfolded(stored!, "Received");
        var match    = FromDomain().Match(received);

        Assert.Multiple(() => {
            Assert.That(match.Success,                  Is.True,                 "From-domain = \"FROM\" FWS Extended-Domain, then BY: " + received);
            Assert.That(match.Groups["literal"].Value,  Is.EqualTo("[127.0.0.1]"), "TCP-info: " + received);
        });

    }


    [Test(Description = "RFC 5321 §4.4: Extended-Domain = address-literal FWS \"(\" TCP-info \")\" - a client that greets with its address literal is in the Received line with it, and with the address of the connection")]
    public async Task The_Received_line_takes_an_address_literal_from_EHLO()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var _ = client;

        await client.CommandAsync("EHLO [127.0.0.1]");

        var marker = Marker();
        await client.SendMailAsync("sender@client.example", "alice@hermod.test",
                                   RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", marker, "hello"));

        var stored = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.That(stored, Is.Not.Null, Explain(client));

        var received = Unfolded(stored!, "Received");
        var match    = FromDomain().Match(received);

        Assert.Multiple(() => {
            Assert.That(match.Success,                 Is.True,                    received);
            Assert.That(match.Groups["helo"].Value,    Is.EqualTo("[127.0.0.1]"),  received);
            Assert.That(match.Groups["literal"].Value, Is.EqualTo("[127.0.0.1]"),  received);
        });

    }

    #endregion

}
