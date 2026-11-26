using System.Text;

using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 3030 §2 - the BDAT command as its grammar has it, and the commands a client may send
/// between two chunks of one message:
/// <code>
///   bdat-cmd   ::= "BDAT" SP chunk-size [ SP end-marker ] CR LF
///   chunk-size ::= 1*DIGIT
///   end-marker ::= "LAST"
/// </code>
/// A chunk follows its BDAT without a reply in between, so whatever the server makes of the
/// command, the chunk is not a command: "If a failure occurs after a BDAT command is received,
/// the receiver-SMTP MUST accept and discard the associated message data before sending the
/// appropriate 5XX or 4XX code". Every chunk of these tests that is refused is made of two NOOP
/// commands - a server that answers them read data as commands.
/// </summary>
[TestFixture]
public sealed class ChunkingCommandTests : HermodServerTestBase
{

    #region Setup

    /// <summary>
    /// Twelve octets of data that are two good commands.
    /// </summary>
    private const String TwoNoops = "NOOP\r\nNOOP\r\n";

    private static Byte[] Raw(String Command, String Chunk)
        => [.. Encoding.ASCII.GetBytes(Command + "\r\n"), .. Encoding.UTF8.GetBytes(Chunk)];

    private static Byte[] Bdat(String Chunk, Boolean Last)
        => Raw($"BDAT {Encoding.UTF8.GetByteCount(Chunk)}{(Last ? " LAST" : "")}", Chunk);

    private static String Codes(IEnumerable<SmtpReply> Replies)
        => "[" + String.Join(", ", Replies.Select(reply => reply.Code)) + "]";

    private async Task<RawSmtpClient> TransactionAsync()
    {

        var client = await Server.ConnectAndEhloAsync();

        var (mail, rcpts) = await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");
        Assume.That(mail.Code,      Is.EqualTo(250),           Explain(client));
        Assume.That(rcpts[0].Code,  Is.EqualTo(250),           Explain(client));

        return client;

    }

    #endregion


    #region S-53: BDAT outside the grammar

    private static IEnumerable<TestCaseData> BdatOutsideTheGrammar()
    {

        static TestCaseData Case(String Command, String Name)
            => new TestCaseData(Command).SetName($"A BDAT outside the grammar is a syntax error: {Name}")
                                        .SetCategory(TestCategories.KnownIssue)
                                        .SetProperty("Finding", "S-53");

        yield return Case("BDAT 12 FOO",     "an end-marker that is not LAST");
        yield return Case("BDAT 12 LAST X",  "an argument after LAST");
        yield return Case("BDAT +12 LAST",   "a chunk-size with a sign");

    }

    [TestCaseSource(nameof(BdatOutsideTheGrammar))]
    [Description("RFC 3030 §2: bdat-cmd ::= \"BDAT\" SP chunk-size [ SP end-marker ] CR LF, chunk-size ::= 1*DIGIT, end-marker ::= \"LAST\"; RFC 5321 §4.2.2: \"501 Syntax error in parameters or arguments\" - a BDAT with anything else is answered as one, not taken as a chunk; its chunk is not answered as commands (RFC 3030 §2: \"MUST accept and discard the associated message data\"), or the server closes the connection, as Postfix does with 521")]
    public async Task A_BDAT_outside_the_grammar_is_a_syntax_error(String Command)
    {

        await using var client = await TransactionAsync();

        await client.WriteRawAsync(Raw(Command, TwoNoops));
        var replies = await client.DrainRepliesAsync(TimeSpan.FromSeconds(2));

        Assert.That(replies.Select(reply => reply.Code).ToArray(), Is.EqualTo(new[] { 501 }).Or.EqualTo(new[] { 421 }).Or.EqualTo(new[] { 521 }),
                    $"one reply, a syntax error, to \"{Command}\" - not 250, and nothing to the chunk's NOOPs; got {Codes(replies)}" + Explain(client));

    }


    private static IEnumerable<TestCaseData> BdatTheGrammarAllows()
    {

        static TestCaseData Case(String Format, String Name)
            => new TestCaseData(Format).SetName($"A BDAT the grammar allows is taken: {Name}")
                                       .SetProperty("Finding", "S-53");

        yield return Case("bdat {0} last",    "the verb and LAST in lower case (RFC 5321 §2.4)");
        yield return Case("BDAT 00{0} LAST",  "a chunk-size with leading zeros (1*DIGIT)");

    }

    [TestCaseSource(nameof(BdatTheGrammarAllows))]
    [Description("RFC 3030 §2: chunk-size ::= 1*DIGIT; RFC 5321 §2.4: \"Verbs and argument values [...] are not case sensitive\" - a BDAT LAST written so is the end of the message, and the message is delivered (a guard for S-53)")]
    public async Task A_BDAT_the_grammar_allows_is_taken(String Format)
    {

        await using var client = await TransactionAsync();

        var marker  = Marker();
        var message = $"Subject: {marker}\r\n\r\nbody\r\n";

        await client.WriteRawAsync(Raw(String.Format(Format, Encoding.UTF8.GetByteCount(message)), message));
        var reply   = await client.ReadReplyAsync();

        Assert.That(reply.Code,                                         Is.EqualTo(250),  Explain(client));
        Assert.That(await Server.Storage.WaitForMarkerAsync(marker),    Is.Not.Null,      "the message, delivered" + Explain(client));

    }

    #endregion

    #region S-54: a BDAT whose size cannot be read

    private static IEnumerable<TestCaseData> BdatOfASizeNotRead()
    {

        static TestCaseData Case(String Command, String Name)
            => new TestCaseData(Command).SetName($"The chunk of a BDAT whose size is not read is no command: {Name}")
                                        .SetCategory(TestCategories.KnownIssue)
                                        .SetProperty("Finding", "S-54");

        yield return Case("BDAT LAST 12",                      "LAST where the size goes");
        yield return Case("BDAT -12 LAST",                     "a negative size");
        yield return Case("BDAT 99999999999999999999 LAST",    "a size of 20 digits");

    }

    [TestCaseSource(nameof(BdatOfASizeNotRead))]
    [Description("RFC 3030 §2: \"The message data is sent immediately after the trailing <CR> <LF> of the BDAT command line\", \"If a failure occurs after a BDAT command is received, the receiver-SMTP MUST accept and discard the associated message data before sending the appropriate 5XX or 4XX code\" - a server that cannot tell where the chunk ends cannot go on reading commands after it: Postfix answers 521 and closes the connection. The octets that follow are the chunk, and none of them is answered as a command")]
    public async Task The_chunk_of_a_BDAT_whose_size_is_not_read_is_no_command(String Command)
    {

        await using var client = await TransactionAsync();

        await client.WriteRawAsync(Raw(Command, TwoNoops));
        var replies = await client.DrainRepliesAsync(TimeSpan.FromSeconds(2));

        Assert.That(replies.Count(reply => reply.Code / 100 == 2), Is.Zero,
                    $"the chunk's NOOPs, answered as commands: {Codes(replies)}" + Explain(client));
        Assert.That(replies,                                       Has.Count.LessThanOrEqualTo(1),
                    $"one reply at most, to \"{Command}\": {Codes(replies)}" + Explain(client));

    }

    #endregion

    #region S-55: RCPT between two chunks

    [Test(Description = "RFC 5321 §4.1.4: \"a mail transaction consists of a transaction beginning command, one or more RCPT commands, and a DATA command, in that order\" - RFC 3030 §2: \"After all MAIL and RCPT responses are collected and processed, the message is sent using a series of BDAT commands\" -, and \"If the commands in a transaction are out of order to the degree that they cannot be processed by the server, a 503 failure reply MUST be returned\": a RCPT after the first chunk of the message is 503, as Postfix has it (\"503 5.5.1 Error: RCPT after BDAT\"), and the message does not go to its recipient")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-55")]
    public async Task A_RCPT_between_two_chunks_is_503()
    {

        await using var client = await TransactionAsync();

        var marker = Marker();

        await client.WriteRawAsync(Bdat($"Subject: {marker}\r\n", Last: false));
        var first  = await client.ReadReplyAsync();
        Assume.That(first.Code, Is.EqualTo(250), Explain(client));

        var rcpt   = await client.CommandAsync("RCPT TO:<bob@hermod.test>");

        await client.WriteRawAsync(Bdat("\r\nbody\r\n", Last: true));
        await client.DrainRepliesAsync(TimeSpan.FromSeconds(1));

        var stored = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.That(rcpt.Code,                      Is.EqualTo(503),                     "the reply to RCPT after a chunk" + Explain(client));
        Assert.That(stored?.EnvelopeTo ?? [],       Does.Not.Contain("bob@hermod.test"), "the recipient named after the first chunk" + Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.4: \"MAIL [...] MUST NOT be sent if a mail transaction is already open\" - a MAIL between two chunks is 503 (a guard for S-55)")]
    [Property("Finding", "S-55")]
    public async Task A_MAIL_between_two_chunks_is_503()
    {

        await using var client = await TransactionAsync();

        await client.WriteRawAsync(Bdat("Subject: first chunk\r\n", Last: false));
        var first = await client.ReadReplyAsync();
        Assume.That(first.Code, Is.EqualTo(250), Explain(client));

        var mail  = await client.CommandAsync("MAIL FROM:<other@client.example>");

        Assert.That(mail.Code, Is.EqualTo(503), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.4: \"The NOOP, HELP, EXPN, VRFY, and RSET commands can be used at any time during a session\"; §4.1.1.9: NOOP \"does not affect any parameters or previously entered commands\" - a NOOP between two chunks leaves the message as it is (a guard for S-55)")]
    [Property("Finding", "S-55")]
    public async Task A_NOOP_between_two_chunks_changes_nothing()
    {

        await using var client = await TransactionAsync();

        var marker = Marker();

        await client.WriteRawAsync(Bdat($"Subject: {marker}\r\n\r\nfirst ", Last: false));
        var first  = await client.ReadReplyAsync();
        var noop   = await client.CommandAsync("NOOP");
        await client.WriteRawAsync(Bdat("second\r\n", Last: true));
        var last   = await client.ReadReplyAsync();

        var stored = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.That(new[] { first.Code, noop.Code, last.Code }, Is.All.EqualTo(250),                  Explain(client));
        Assert.That(stored?.Raw,                                Does.EndWith("\r\n\r\nfirst second\r\n"), Explain(client));
        Assert.That(stored?.EnvelopeTo ?? [],                   Is.EqualTo(new[] { "alice@hermod.test" }), Explain(client));

    }


    [Test(Description = "RFC 3030 §2: \"The RSET command, when issued after the first BDAT and before the BDAT LAST, clears all segments sent during that transaction and resets the session\" - a BDAT after it has no transaction (503), and the next message has nothing of the first (a guard for S-55)")]
    [Property("Finding", "S-55")]
    public async Task A_RSET_between_two_chunks_clears_them()
    {

        await using var client = await TransactionAsync();

        var cleared = Marker();
        var marker  = Marker();

        await client.WriteRawAsync(Bdat($"X-Cleared: {cleared}\r\n", Last: false));
        var first   = await client.ReadReplyAsync();
        var rset    = await client.CommandAsync("RSET");

        await client.WriteRawAsync(Bdat(TwoNoops, Last: true));
        var orphan  = await client.DrainRepliesAsync(TimeSpan.FromSeconds(1));

        var (mail, rcpts) = await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");
        await client.WriteRawAsync(Bdat($"Subject: {marker}\r\n\r\nbody\r\n", Last: true));
        var last    = await client.ReadReplyAsync();

        var stored  = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.That(new[] { first.Code, rset.Code },                Is.All.EqualTo(250),            Explain(client));
        Assert.That(orphan.Select(reply => reply.Code).ToArray(),   Is.EqualTo(new[] { 503 }),      "a BDAT after RSET, and nothing to its chunk" + Explain(client));
        Assert.That(new[] { mail.Code, rcpts[0].Code, last.Code },  Is.All.EqualTo(250),            Explain(client));
        Assert.That(stored?.Raw,                                    Does.Not.Contain(cleared),      "the chunk sent before RSET" + Explain(client));
        Assert.That(Server.Storage.CountWithMarker(cleared),        Is.Zero,                        "the chunk sent before RSET, delivered" + Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.4: an EHLO later in the session - \"the SMTP server MUST clear all buffers and reset the state exactly as if a RSET command had been issued\" - aborts a message sent in chunks: a BDAT LAST after it has no transaction, and nothing is delivered (a guard for S-55)")]
    [Property("Finding", "S-55")]
    public async Task An_EHLO_between_two_chunks_aborts_the_message()
    {

        await using var client = await TransactionAsync();

        var marker = Marker();

        await client.WriteRawAsync(Bdat($"Subject: {marker}\r\n\r\n", Last: false));
        var first  = await client.ReadReplyAsync();
        var (ehlo, _) = await client.EhloAsync();

        await client.WriteRawAsync(Bdat("body\r\n", Last: true));
        var last   = await client.DrainRepliesAsync(TimeSpan.FromSeconds(1));

        Assert.That(new[] { first.Code, ehlo.Code },             Is.All.EqualTo(250),         Explain(client));
        Assert.That(last.Select(reply => reply.Code).ToArray(),  Is.EqualTo(new[] { 503 }),   "BDAT LAST after the EHLO" + Explain(client));
        Assert.That(Server.Storage.CountWithMarker(marker),      Is.Zero,                     "the message aborted by EHLO, delivered" + Explain(client));

    }

    #endregion

}
