using System.Text;

using NUnit.Framework;

using SMTPConformance.Core;

using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// Binary data from the submission client: a line of more than 998 octets, a NUL. RFC 2045
/// §2.7, §2.8: 7bit and 8bit data are lines of "998 octets or less", and "neither are NULs"
/// allowed; §2.9: binary data is "any sequence of octets whatsoever". RFC 6152 §3: 8BITMIME
/// "DOES NOT provide a means of transferring an object with the BINARY content-transfer-encoding";
/// RFC 3030 §3: that is BODY=BINARYMIME, over BDAT, and to a server that does not offer it "the
/// sender-SMTP MUST NOT, under any circumstances, send binary data".
/// </summary>
public sealed partial class SubmissionClientTests
{

    #region Binary data

    /// <summary>
    /// A message whose body is binary data - written so, Content-Transfer-Encoding: binary.
    /// </summary>
    internal static EMailEnvelop BinaryMessage(String BodyLine)

        => new (EMail.Parse([
                    "From: app@client.example",
                    "To: you@scripted.test",
                    "Subject: binary data",
                    "MIME-Version: 1.0",
                    "Content-Type: application/octet-stream",
                    "Content-Transfer-Encoding: binary",
                    "",
                    BodyLine
                ]));

    /// <summary>
    /// The binary data of the tests: a line of 1200 octets, a NUL.
    /// </summary>
    public static IEnumerable<TestCaseData> BinaryBodies()
    {
        yield return new TestCaseData(new String('x', 1200)).SetArgDisplayNames("a line of 1200 octets");
        yield return new TestCaseData("before\0after").      SetArgDisplayNames("a NUL");
    }

    /// <summary>
    /// The lines of a transaction's message as they arrived - DATA lines, or the BDAT content
    /// cut at its CR LFs - with the dot-stuffing of DATA undone.
    /// </summary>
    internal static IEnumerable<Byte[]> ArrivedLines(ScriptedTransaction Transaction)
    {

        if (Transaction.UsedBdat)
        {

            var content = Transaction.BdatContent.ToArray();
            var start   = 0;

            for (var i = 0; i + 1 < content.Length; i++)
                if (content[i] == '\r' && content[i + 1] == '\n')
                {
                    yield return content[start..i];
                    start = i + 2;
                    i++;
                }

            if (start < content.Length)
                yield return content[start..];

        }

        else
            foreach (var line in Transaction.DataLines)
                yield return line.Bytes is [ (Byte) '.', .. ] ? line.Bytes[1..] : line.Bytes;

    }

    /// <summary>
    /// Whether binary data arrived in this transaction: a line of more than 998 octets, or a NUL.
    /// </summary>
    internal static Boolean BinaryArrived(ScriptedTransaction Transaction)
        => ArrivedLines(Transaction).Any(line => line.Length > 998 || line.Contains((Byte) 0));

    /// <summary>
    /// What a test says of a transaction: how it went, with what MAIL, and its longest line.
    /// </summary>
    internal static String Describe(ScriptedTransaction Transaction)
        => $"{(Transaction.UsedBdat ? "BDAT" : "DATA")}, {Transaction.MailFromLine}, longest line {ArrivedLines(Transaction).Select(line => line.Length).DefaultIfEmpty(0).Max()} octets, NUL {ArrivedLines(Transaction).Any(line => line.Contains((Byte) 0))}";


    public static IEnumerable<TestCaseData> ServersWithoutBinaryMime()
    {

        foreach (var body in BinaryBodies())
        {

            var what = body.Arguments[0] is String text && text.Contains('\0') ? "a NUL" : "a line of 1200 octets";

            yield return new TestCaseData(new[] { "PIPELINING", "SIZE 10485760", "8BITMIME", "ENHANCEDSTATUSCODES" }, body.Arguments[0])
                             .SetName($"Binary data, {what}, is not sent to a server with 8BITMIME and without BINARYMIME")
                             .SetCategory(TestCategories.KnownIssue)
                             .SetProperty("Finding", "C-26");

            yield return new TestCaseData(new[] { "PIPELINING", "SIZE 10485760", "8BITMIME", "ENHANCEDSTATUSCODES", "CHUNKING" }, body.Arguments[0])
                             .SetName($"Binary data, {what}, is not sent to a server with CHUNKING and without BINARYMIME")
                             .SetCategory(TestCategories.KnownIssue)
                             .SetProperty("Finding", "C-26");

        }

    }

    [TestCaseSource(nameof(ServersWithoutBinaryMime))]
    [Description("RFC 3030 §3: \"the sender-SMTP MUST NOT, under any circumstances, send binary data\" to a server that does not offer BINARYMIME; RFC 6152 §3: 8BITMIME \"DOES NOT provide a means of transferring an object with the BINARY content-transfer-encoding\" - the client converts the message or does not send it, and no line of more than 998 octets, no NUL arrives")]
    public async Task Binary_data_is_not_sent_to_a_server_without_BINARYMIME(String[] Extensions, String BodyLine)
    {

        var script = new SmtpServerScript { Extensions = Extensions };
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        await client.Send(BinaryMessage(BodyLine), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        Assert.That(script.Transactions.Where(BinaryArrived).Select(Describe), Is.Empty, Explain(server));

    }


    [TestCaseSource(nameof(BinaryBodies))]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "C-25")]
    [Description("RFC 3030 §3: binary data goes as BODY=BINARYMIME - \"The BINARYMIME service extension can only be used with the \"CHUNKING\" service extension\" -, not as BODY=8BITMIME, which \"DOES NOT provide a means of transferring an object with the BINARY content-transfer-encoding\" (RFC 6152 §3) - to a server that offers both, the message goes as BDAT with BODY=BINARYMIME")]
    public async Task Binary_data_goes_as_BODY_BINARYMIME(String BodyLine)
    {

        var script = new SmtpServerScript { Extensions = [ "PIPELINING", "SIZE 10485760", "8BITMIME", "ENHANCEDSTATUSCODES", "CHUNKING", "BINARYMIME" ] };
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        var result      = await client.Send(BinaryMessage(BodyLine), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        var transaction = script.Transactions.SingleOrDefault();

        Assert.Multiple(() => {
            Assert.That(result,                     Is.EqualTo(MailSentStatus.ok),          Explain(server));
            Assert.That(transaction?.UsedBdat,      Is.True,                                "as BDAT" + Explain(server));
            Assert.That(transaction?.MailFromLine,  Does.Contain(" BODY=BINARYMIME"),       Explain(server));
            Assert.That(transaction is not null && ArrivedLines(transaction).Any(line => line.SequenceEqual(Encoding.UTF8.GetBytes(BodyLine))),
                        Is.True, "the binary data arrived as it is" + Explain(server));
        });

    }


    [Test(Description = "RFC 2045 §2.7, §2.8: a line of 998 octets is no binary data - \"998 octets or less\" -, and goes as before (a guard)")]
    [Property("Finding", "C-26")]
    public async Task A_line_of_998_octets_is_no_binary_data()
    {

        var script = new SmtpServerScript { Extensions = [ "PIPELINING", "SIZE 10485760", "8BITMIME", "ENHANCEDSTATUSCODES" ] };
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        var line   = new String('y', 998);
        var result = await client.Send(Message(line), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        Assert.Multiple(() => {
            Assert.That(result, Is.EqualTo(MailSentStatus.ok), Explain(server));
            Assert.That(script.Transactions.SelectMany(ArrivedLines).Any(arrived => arrived.SequenceEqual(Encoding.ASCII.GetBytes(line))),
                        Is.True, "the line arrived as it is" + Explain(server));
        });

    }


    [Test(Description = "RFC 6152 §3: 8-bit text is no binary data - to a server that offers BINARYMIME too, it arrives as it is (a guard)")]
    [Property("Finding", "C-25")]
    public async Task Eight_bit_text_goes_to_a_server_with_BINARYMIME()
    {

        var script = new SmtpServerScript { Extensions = [ "PIPELINING", "SIZE 10485760", "8BITMIME", "ENHANCEDSTATUSCODES", "CHUNKING", "BINARYMIME" ] };
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        var result = await client.Send(Message("Grüße aus Köln"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        var transaction = script.Transactions.Single();

        Assert.Multiple(() => {
            Assert.That(result,                   Is.EqualTo(MailSentStatus.ok),                         Explain(server));
            Assert.That(transaction.MailFromLine, Does.Contain(" BODY=8BITMIME").Or.Contain(" BODY=BINARYMIME"), Explain(server));
            Assert.That(ArrivedLines(transaction).Any(line => line.SequenceEqual(Encoding.UTF8.GetBytes("Grüße aus Köln"))),
                        Is.True, "the text arrived as it is" + Explain(server));
        });

    }

    #endregion

}
