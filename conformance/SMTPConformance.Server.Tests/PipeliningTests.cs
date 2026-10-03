using System.Text;

using NUnit.Framework;

using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 2920: SMTP Service Extension for Command Pipelining.
/// </summary>
[TestFixture]
public sealed class PipeliningTests : HermodServerTestBase
{

    [Test(Description = "RFC 2920 §3: PIPELINING is advertised in the EHLO reply")]
    public async Task Pipelining_is_advertised()
    {

        var (client, _) = await Server.ConnectMtaAsync();
        await using var __ = client;

        var (_, extensions) = await client.EhloAsync();

        Assert.That(extensions.Keys, Does.Contain("PIPELINING"), Explain(client));

    }


    [Test(Description = "RFC 2920 §3.1: a whole envelope sent in one write is answered reply by reply, in order")]
    public async Task A_pipelined_envelope_is_answered_in_order()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        await client.WriteRawAsync("MAIL FROM:<sender@client.example>\r\n" +
                                   "RCPT TO:<alice@hermod.test>\r\n" +
                                   "RCPT TO:<someone@elsewhere.example>\r\n" +
                                   "RCPT TO:<bob@hermod.test>\r\n" +
                                   "DATA\r\n");

        var codes = new List<Int32>();
        for (var i = 0; i < 5; i++)
            codes.Add((await client.ReadReplyAsync()).Code);

        // The relay recipient is refused (unauthenticated), the others accepted —
        // and each reply sits in the position of its command.
        Assert.That(codes, Is.EqualTo(new[] { 250, 250, 550, 250, 354 }), Explain(client));

    }


    [Test(Description = "RFC 2920 §3.1: end of data and QUIT pipelined together are both answered")]
    public async Task End_of_data_and_quit_pipelined()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var marker = Marker();

        await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");
        var data = await client.CommandAsync("DATA");
        Assume.That(data.Code, Is.EqualTo(354), Explain(client));

        await client.WriteRawAsync(Encoding.ASCII.GetBytes(
                                       RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", marker, "x") +
                                       ".\r\nQUIT\r\n"));

        var final = await client.ReadReplyAsync();
        var quit  = await client.ReadReplyAsync();

        Assert.Multiple(async () => {
            Assert.That(final.Code, Is.EqualTo(250), Explain(client));
            Assert.That(quit.Code,  Is.EqualTo(221), Explain(client));
            Assert.That(await Server.Storage.WaitForMarkerAsync(marker), Is.Not.Null);
        });

    }


    [Test(Description = "RFC 2920 §3.1: two complete transactions in two writes on one connection, without waiting between commands")]
    public async Task Back_to_back_pipelined_transactions()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var first  = Marker();
        var second = Marker();

        String Transaction(String marker)
            => "MAIL FROM:<sender@client.example>\r\nRCPT TO:<alice@hermod.test>\r\nDATA\r\n";

        await client.WriteRawAsync(Transaction(first));
        var r1 = new[] { await client.ReadReplyAsync(), await client.ReadReplyAsync(), await client.ReadReplyAsync() };
        await client.WriteRawAsync(Encoding.ASCII.GetBytes(RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", first, "1") + ".\r\n" + Transaction(second)));
        var r2 = new[] { await client.ReadReplyAsync(), await client.ReadReplyAsync(), await client.ReadReplyAsync(), await client.ReadReplyAsync() };
        await client.WriteRawAsync(Encoding.ASCII.GetBytes(RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", second, "2") + ".\r\n"));
        var r3 = await client.ReadReplyAsync();

        Assert.Multiple(() => {
            Assert.That(r1.Select(r => r.Code), Is.EqualTo(new[] { 250, 250, 354 }),      Explain(client));
            Assert.That(r2.Select(r => r.Code), Is.EqualTo(new[] { 250, 250, 250, 354 }), Explain(client));
            Assert.That(r3.Code,                Is.EqualTo(250),                          Explain(client));
        });

    }

}
