using System.Text;

using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 5321 §2.3.8: "Conforming implementations MUST NOT recognize or generate any
/// other character or character sequence as a line terminator" than CR LF.
/// </summary>
/// <remarks>
/// <para>
/// This is the requirement SMTP smuggling (CVE-2023-51764, -51765, -51766 and
/// relatives, SEC Consult, December 2023) exploits. An outbound server passes a
/// <c>&lt;LF&gt;.&lt;LF&gt;</c> through as data, because to it that is not the end of the
/// message; an inbound server that does treat it as the end then reads what
/// follows as a second, smuggled transaction — with a sender the outbound
/// server never authenticated.
/// </para>
/// <para>
/// Each test sends one DATA block that contains an ambiguous terminator followed
/// by a complete second transaction, then the real CRLF.CRLF. A conforming
/// server sees one message and sends exactly one reply to the end of data; a
/// vulnerable one stores two, and answers the smuggled commands.
/// </para>
/// </remarks>
[TestFixture]
public sealed class LineTerminatorTests : HermodServerTestBase
{

    public static IEnumerable<TestCaseData> AmbiguousTerminators()
    {
        yield return new TestCaseData("\n.\n")    .SetName("Smuggling: <LF>.<LF> does not end DATA");
        yield return new TestCaseData("\n.\r\n")  .SetName("Smuggling: <LF>.<CR><LF> does not end DATA");
        yield return new TestCaseData("\r\n.\n")  .SetName("Smuggling: <CR><LF>.<LF> does not end DATA");
        yield return new TestCaseData("\r.\r")    .SetName("Smuggling: <CR>.<CR> does not end DATA");
        yield return new TestCaseData("\r.\r\n")  .SetName("Smuggling: <CR>.<CR><LF> does not end DATA");
        yield return new TestCaseData("\r\n.\r")  .SetName("Smuggling: <CR><LF>.<CR> does not end DATA");
    }


    [TestCaseSource(nameof(AmbiguousTerminators))]
    [Property("Finding", "S-1")]
    public async Task An_ambiguous_end_of_data_does_not_end_the_message(String Terminator)
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var outer    = Marker();
        var smuggled = Marker();

        await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");
        var data = await client.CommandAsync("DATA");
        Assume.That(data.Code, Is.EqualTo(354), Explain(client));

        var payload = $"Subject: {outer}\r\n\r\nfirst message" + Terminator +
                      "MAIL FROM:<smuggled@victim.example>\r\n" +
                      "RCPT TO:<alice@hermod.test>\r\n" +
                      "DATA\r\n" +
                      $"Subject: {smuggled}\r\n\r\nsmuggled message\r\n" +
                      ".\r\n";

        await client.WriteRawAsync(Encoding.ASCII.GetBytes(payload));

        var replies = await client.DrainRepliesAsync(TimeSpan.FromSeconds(2));

        Assert.Multiple(() => {

            Assert.That(replies.Select(r => r.Code).ToArray(), Is.EqualTo(new[] { 250 }).Or.EqualTo(new[] { 550 }).Or.EqualTo(new[] { 554 }),
                        "exactly one reply to one end of data — the commands inside the data must not be answered" + Explain(client));

            Assert.That(Server.Storage.CountWithMarker(smuggled), Is.Zero,
                        "the smuggled message must not be stored as a message of its own" + Explain(client));

        });

    }


    [Test(Description = "RFC 5321 §2.3.8: a bare LF does not terminate a command line — 'NOOP<LF>NOOP<CRLF>' is one line, so at most one reply")]
    [Property("Finding", "S-1")]
    public async Task A_bare_LF_does_not_terminate_a_command()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        await client.WriteRawAsync("NOOP\nNOOP\r\n");

        var replies = await client.DrainRepliesAsync(TimeSpan.FromSeconds(2));

        Assert.That(replies, Has.Count.EqualTo(1), Explain(client));

    }


    [Test(Description = "RFC 5321 §2.3.8: a bare CR does not terminate a command line — 'NOOP<CR>NOOP<CRLF>' is one line, so at most one reply")]
    [Property("Finding", "S-1")]
    public async Task A_bare_CR_does_not_terminate_a_command()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        await client.WriteRawAsync("NOOP\rNOOP\r\n");

        var replies = await client.DrainRepliesAsync(TimeSpan.FromSeconds(2));

        Assert.That(replies, Has.Count.EqualTo(1), Explain(client));

    }


    [Test(Description = "RFC 5321 §2.3.8, §4.2: the server generates CRLF and nothing else — no reply line ends in a bare LF")]
    public async Task Replies_end_in_CRLF()
    {

        var (client, greeting) = await Server.ConnectMtaAsync();
        await using var _ = client;

        var (ehlo, __) = await client.EhloAsync();
        var noop       = await client.CommandAsync("NOOP");

        Assert.That(new[] { greeting, ehlo, noop }.SelectMany(r => r.Violations), Is.Empty, Explain(client));

    }

}
