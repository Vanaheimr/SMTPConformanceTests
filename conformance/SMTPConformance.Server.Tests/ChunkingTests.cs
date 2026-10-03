using System.Text;

using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 3030: SMTP Service Extensions for Transmission of Large and Binary MIME Messages (CHUNKING / BDAT).
/// </summary>
/// <remarks>
/// BDAT is length-delimited: the server has to read exactly the announced number
/// of octets as data, whatever it decides about the command. Every test that
/// rejects a BDAT therefore sends a chunk that consists of valid SMTP commands —
/// if the server answers them, it read data as commands.
/// </remarks>
[TestFixture]
public sealed class ChunkingTests : HermodServerTestBase
{

    private static Byte[] Bdat(String Payload, Boolean Last)
    {
        var bytes = Encoding.UTF8.GetBytes(Payload);
        return [.. Encoding.ASCII.GetBytes($"BDAT {bytes.Length}{(Last ? " LAST" : "")}\r\n"), .. bytes];
    }


    [Test(Description = "RFC 3030 §2: CHUNKING is advertised")]
    public async Task Chunking_is_advertised()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        var (_, extensions) = await client.EhloAsync();

        Assert.That(extensions.Keys, Does.Contain("CHUNKING"), Explain(client));

    }


    [Test(Description = "RFC 3030 §2: BDAT n LAST delivers exactly n octets — no dot-stuffing, a lone \".\" line is data")]
    public async Task Bdat_last_delivers_the_chunk_verbatim()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var marker  = Marker();
        var message = $"Subject: {marker}\r\n\r\n..two periods\r\n.\r\nafter a lone period\r\n";

        await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");
        await client.WriteRawAsync(Bdat(message, Last: true));
        var reply  = await client.ReadReplyAsync();

        var stored = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.Multiple(() => {
            Assert.That(reply.Code,  Is.EqualTo(250), Explain(client));
            Assert.That(stored?.Raw, Does.EndWith(message), "BDAT content must be stored as sent, periods included" + Explain(client));
        });

    }


    [Test(Description = "RFC 3030 §2: several chunks are concatenated; each non-final chunk is acknowledged with 250")]
    public async Task Chunks_are_concatenated()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var marker = Marker();

        await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");

        await client.WriteRawAsync(Bdat($"Subject: {marker}\r\n\r\nfirst ", Last: false));
        var r1 = await client.ReadReplyAsync();
        await client.WriteRawAsync(Bdat("second ", Last: false));
        var r2 = await client.ReadReplyAsync();
        await client.WriteRawAsync(Bdat("third\r\n", Last: true));
        var r3 = await client.ReadReplyAsync();

        var stored = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.Multiple(() => {
            Assert.That(new[] { r1.Code, r2.Code, r3.Code }, Is.All.EqualTo(250), Explain(client));
            Assert.That(stored?.Raw, Does.EndWith("\r\n\r\nfirst second third\r\n"), Explain(client));
        });

    }


    [Test(Description = "RFC 3030 §2: BDAT 0 LAST is a valid way to end a chunked message")]
    public async Task Bdat_zero_last_ends_the_message()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var marker = Marker();

        await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");
        await client.WriteRawAsync(Bdat($"Subject: {marker}\r\n\r\nbody\r\n", Last: false));
        var r1 = await client.ReadReplyAsync();
        await client.WriteRawAsync("BDAT 0 LAST\r\n");
        var r2 = await client.ReadReplyAsync();

        Assert.Multiple(async () => {
            Assert.That(r1.Code, Is.EqualTo(250), Explain(client));
            Assert.That(r2.Code, Is.EqualTo(250), Explain(client));
            Assert.That(await Server.Storage.WaitForMarkerAsync(marker), Is.Not.Null, Explain(client));
        });

    }


    [Test(Description = "RFC 3030 §2: \"If a failure occurs after a BDAT command is received, the receiver-SMTP MUST accept and discard the associated message data\" — here: BDAT without a recipient")]
    [Category(TestCategories.KnownIssue), Property("Finding", "S-2")]
    public async Task A_rejected_bdat_still_consumes_its_chunk()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        // No MAIL/RCPT: the BDAT is out of sequence. Its 12 octets of data are two
        // perfectly good NOOP commands, which must be discarded, not executed.
        await client.WriteRawAsync(Bdat("NOOP\r\nNOOP\r\n", Last: true));

        var replies = await client.DrainRepliesAsync(TimeSpan.FromSeconds(2));

        Assert.That(replies.Select(r => r.Code).ToArray(), Is.EqualTo(new[] { 503 }),
                    "one 503 for the BDAT; the chunk's content is data and must not be answered" + Explain(client));

    }


    [Test(Description = "RFC 3030 §2: a BDAT refused for its size must still have its data consumed")]
    [Category(TestCategories.KnownIssue), Property("Finding", "S-2")]
    public async Task An_oversized_bdat_still_consumes_its_chunk()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");

        // Announce more than the limit, then actually send that much: the first
        // octets are commands, which must be swallowed with the rest of the chunk.
        var size    = Server.Config.MaxMessageSize + 1;
        var payload = new Byte[size];
        Array.Fill(payload, (Byte) 'x');
        Encoding.ASCII.GetBytes("NOOP\r\nNOOP\r\n").CopyTo(payload, 0);

        await client.WriteRawAsync([.. Encoding.ASCII.GetBytes($"BDAT {size} LAST\r\n"), .. payload]);

        var replies = await client.DrainRepliesAsync(TimeSpan.FromSeconds(3));

        Assert.That(replies.Select(r => r.Code).ToArray(), Is.EqualTo(new[] { 552 }),
                    "one 552 for the BDAT; nothing inside the chunk may be answered" + Explain(client));

    }


    [Test(Description = "RFC 3030 §2: \"If a DATA statement is issued after a BDAT for the current transaction, a 503 'Bad sequence of commands' MUST be issued.\"")]
    [Category(TestCategories.KnownIssue), Property("Finding", "S-3")]
    public async Task Data_after_bdat_in_the_same_transaction_is_503()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");
        await client.WriteRawAsync(Bdat("Subject: chunk\r\n\r\n", Last: false));
        var bdat = await client.ReadReplyAsync();
        Assume.That(bdat.Code, Is.EqualTo(250), Explain(client));

        var data = await client.CommandAsync("DATA");

        Assert.That(data.Code, Is.EqualTo(503), Explain(client));

    }


    [Test(Description = "RFC 3030 §2: chunk data containing CRLF.CRLF is still data — BDAT has no in-band terminator")]
    public async Task A_dot_line_inside_a_chunk_does_not_end_anything()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var marker = Marker();

        await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");
        await client.WriteRawAsync(Bdat($"Subject: {marker}\r\n\r\nbefore\r\n.\r\nQUIT\r\n", Last: true));

        var replies = await client.DrainRepliesAsync(TimeSpan.FromSeconds(2));

        Assert.That(replies.Select(r => r.Code).ToArray(), Is.EqualTo(new[] { 250 }), Explain(client));

    }

}
