using System.Text;

using NUnit.Framework;

using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 5321 §4.1.1.4, §4.5.2 and §4.5.3.1.6: the DATA phase and its transparency.
/// </summary>
[TestFixture]
public sealed class DataTransferTests : HermodServerTestBase
{

    private async Task<(SmtpReply? Final, StoredMessage? Stored, RawSmtpClient Client)> Deliver(params String[] BodyLines)
    {

        var client = await Server.ConnectAndEhloAsync();
        var marker = Marker();

        await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");
        var (_, final) = await client.DataAsync(RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", marker, BodyLines));

        return (final, await Server.Storage.WaitForMarkerAsync(marker), client);

    }


    [Test(Description = "RFC 5321 §4.1.1.4: DATA is answered with 354, the end of data with 250")]
    public async Task Data_is_354_and_end_of_data_is_250()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");
        var (data, final) = await client.DataAsync(RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", Marker(), "hello"));

        Assert.Multiple(() => {
            Assert.That(data.Code,   Is.EqualTo(354), Explain(client));
            Assert.That(final?.Code, Is.EqualTo(250), Explain(client));
        });

    }


    [Test(Description = "RFC 5321 §4.5.2: the receiver deletes the first period of a line that begins with one")]
    public async Task A_leading_period_is_removed()
    {

        var (final, stored, client) = await Deliver(".starts with one period", "..starts with two");
        await using var _ = client;

        Assert.That(stored, Is.Not.Null, Explain(client));
        Assert.Multiple(() => {
            Assert.That(stored!.Raw, Does.Contain("\r\n.starts with one period\r\n"));
            Assert.That(stored.Raw,  Does.Contain("\r\n..starts with two\r\n"));
        });

    }


    [Test(Description = "RFC 5321 §4.5.2: a body line consisting of a single period, sent stuffed as \"..\", arrives as \".\" and does not end the message")]
    public async Task A_lone_period_line_survives()
    {

        var (final, stored, client) = await Deliver("before", ".", "after");
        await using var _ = client;

        Assert.That(stored, Is.Not.Null, Explain(client));
        Assert.That(stored!.Raw, Does.Contain("\r\nbefore\r\n.\r\nafter\r\n"));

    }


    [Test(Description = "RFC 5321 §4.5.3.1.6: a text line of 1000 octets including CRLF must be accepted")]
    public async Task A_1000_octet_text_line_is_accepted()
    {

        var line = new String('y', 998);

        var (final, stored, client) = await Deliver(line);
        await using var _ = client;

        Assert.Multiple(() => {
            Assert.That(final?.Code, Is.EqualTo(250), Explain(client));
            Assert.That(stored?.Raw, Does.Contain("\r\n" + line + "\r\n"));
        });

    }


    [Test(Description = "RFC 5321 §4.2.5, §4.5.3.1.6: an overlong text line is rejected only after the end of data, and the session stays in sync")]
    public async Task An_overlong_text_line_is_rejected_after_the_terminator()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");
        var (_, final) = await client.DataAsync(RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", Marker(),
                                                                                new String('z', Server.Config.MaxTextLineLength + 10)));
        var noop       = await client.CommandAsync("NOOP");

        Assert.Multiple(() => {
            Assert.That(final?.Class, Is.EqualTo(5),   Explain(client));
            Assert.That(noop.Code,    Is.EqualTo(250), "the session must still be in command mode" + Explain(client));
        });

    }


    [Test(Description = "RFC 5321 §4.5.2, §2.3.1: the message content reaches storage unchanged — headers, empty line, body, CRLFs")]
    public async Task Content_is_stored_byte_exact_behind_the_trace_headers()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var marker  = Marker();
        var message = RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", marker,
                                                      "line one", "", "\tindented", "trailing spaces   ", "end");

        await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");
        var (_, final) = await client.DataAsync(message);
        Assume.That(final?.Code, Is.EqualTo(250), Explain(client));

        var stored = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.That(stored,       Is.Not.Null, Explain(client));
        Assert.That(stored!.Raw,  Does.EndWith(message), "everything after the prepended trace headers must be the message as sent");

    }


    [Test(Description = "RFC 5321 §4.4: the server prepends a Received: trace field; it is the first header of the stored message")]
    public async Task A_received_header_is_prepended()
    {

        var (final, stored, client) = await Deliver("hello");
        await using var _ = client;

        Assert.That(stored, Is.Not.Null, Explain(client));

        var headers = stored!.Raw[..stored.Raw.IndexOf("\r\n\r\n", StringComparison.Ordinal)];

        Assert.That(headers, Does.Contain("Received: from client.example"));
        Assert.That(headers.IndexOf("Received:", StringComparison.Ordinal),
                    Is.LessThan(headers.IndexOf("From:", StringComparison.Ordinal)),
                    "the trace header goes on top of the existing headers");

    }


    [Test(Description = "RFC 5321 §4.4: Received = \"Received:\" FWS Stamp; Stamp = From-domain By-domain Opt-info [CFWS] \";\" FWS date-time")]
    public async Task The_received_header_has_from_by_and_a_date()
    {

        var (final, stored, client) = await Deliver("hello");
        await using var _ = client;

        Assert.That(stored, Is.Not.Null, Explain(client));

        // The header field runs from "Received:" to the first CRLF that is not
        // followed by whitespace (RFC 5322 §2.2.3 folding).
        var raw      = stored!.Raw;
        var start    = raw.IndexOf("Received:", StringComparison.Ordinal);
        var end      = start;
        do
            end = raw.IndexOf("\r\n", end + 2, StringComparison.Ordinal);
        while (end >= 0 && end + 2 < raw.Length && raw[end + 2] is ' ' or '\t');

        Assert.That(start, Is.GreaterThanOrEqualTo(0), raw);

        var unfolded = raw[start..end].Replace("\r\n\t", " ").Replace("\r\n ", " ");

        Assert.That(unfolded, Does.Match(@"^Received: from \S+ .*\bby \S+ .*;\s*\w{3}, \d{1,2} \w{3} \d{4} \d{2}:\d{2}:\d{2} [+-]\d{4}"),
                    unfolded);

    }


    [Test(Description = "RFC 3848 §2, RFC 5321 §4.4: the 'with' clause names ESMTP after EHLO and SMTP after HELO")]
    public async Task The_with_clause_reflects_helo_or_ehlo()
    {

        var markerEsmtp = Marker();
        var markerSmtp  = Marker();

        await using (var ehlo = await Server.ConnectAndEhloAsync())
            await ehlo.SendMailAsync("sender@client.example", "alice@hermod.test",
                                     RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", markerEsmtp, "x"));

        var (helo, _) = await Server.ConnectMtaAsync();
        await using (helo)
        {
            await helo.CommandAsync("HELO client.example");
            await helo.SendMailAsync("sender@client.example", "alice@hermod.test",
                                     RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", markerSmtp, "x"));
        }

        var esmtp = await Server.Storage.WaitForMarkerAsync(markerEsmtp);
        var smtp  = await Server.Storage.WaitForMarkerAsync(markerSmtp);

        Assert.Multiple(() => {
            Assert.That(esmtp?.Raw, Does.Match(@"\bwith ESMTP\b"));
            Assert.That(smtp?.Raw,  Does.Match(@"\bwith SMTP\b"));
        });

    }


    [Test(Description = "RFC 5321 §4.1.1.4, RFC 5322 §3.5: a message with a header section and an empty body is accepted")]
    public async Task Empty_body_message_is_accepted()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var marker = Marker();

        await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");
        var data = await client.CommandAsync("DATA");
        Assume.That(data.Code, Is.EqualTo(354), Explain(client));

        await client.WriteRawAsync(Encoding.ASCII.GetBytes($"Subject: {marker}\r\n\r\n.\r\n"));
        var final = await client.ReadReplyAsync();

        Assert.That(final.Code, Is.EqualTo(250), Explain(client));

    }

}
