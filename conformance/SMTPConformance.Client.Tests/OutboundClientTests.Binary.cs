using NUnit.Framework;

using SMTPConformance.Core;

using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// Binary data from the relay: a line of more than 998 octets, a NUL, in a message an
/// application gave it (MailSender). RFC 3030 §3: binary data goes as BODY=BINARYMIME, over
/// BDAT, and to a next hop that does not offer it "the sender-SMTP MUST NOT, under any
/// circumstances, send binary data" - it converts the message, or treats it "as a permanent
/// error"; RFC 6152 §3: 8BITMIME "DOES NOT provide a means of transferring an object with the
/// BINARY content-transfer-encoding".
/// </summary>
public sealed partial class OutboundClientTests
{

    #region Binary data

    private static EMailEnvelop BinaryEnvelope(String BodyLine)

        => new (EMail.Parse([
                    "From: app@client.example",
                    "To: you@outbound.test",
                    "Subject: binary data",
                    "MIME-Version: 1.0",
                    "Content-Type: application/octet-stream",
                    "Content-Transfer-Encoding: binary",
                    "",
                    BodyLine
                ])) { Dsn = DsnParameters.None };


    public static IEnumerable<TestCaseData> NextHopsWithoutBinaryMime()
    {

        foreach (var (body, what) in new[] { (new String('x', 1200), "a line of 1200 octets"), ("before\0after", "a NUL") })
        {

            yield return new TestCaseData(new[] { "PIPELINING", "SIZE 10485760", "8BITMIME", "ENHANCEDSTATUSCODES" }, body)
                             .SetName($"Binary data, {what}, is not relayed to a next hop with 8BITMIME and without BINARYMIME")
                             .SetProperty("Finding", "O-32");

            yield return new TestCaseData(new[] { "PIPELINING", "SIZE 10485760", "8BITMIME", "ENHANCEDSTATUSCODES", "CHUNKING" }, body)
                             .SetName($"Binary data, {what}, is not relayed to a next hop with CHUNKING and without BINARYMIME")
                             .SetProperty("Finding", "O-32");

        }

    }

    [TestCaseSource(nameof(NextHopsWithoutBinaryMime))]
    [Description("RFC 3030 §3: \"the sender-SMTP MUST NOT, under any circumstances, send binary data\" to a server that does not offer BINARYMIME - \"it may treat this as a permanent error\"; RFC 6152 §3 - the relay converts the message or gives up on it, and no line of more than 998 octets, no NUL arrives")]
    public async Task Binary_data_is_not_relayed_to_a_next_hop_without_BINARYMIME(String[] Extensions, String BodyLine)
    {

        var script = new SmtpServerScript { Extensions = Extensions };
        await using var server = ScriptedSmtpServer.Start(script);

        var result = await SendDirect(server, BinaryEnvelope(BodyLine));

        Assert.Multiple(() => {
            Assert.That(script.Transactions.Where(SubmissionClientTests.BinaryArrived).Select(SubmissionClientTests.Describe), Is.Empty, Explain(server));
            Assert.That(result.Status, Is.Not.EqualTo(SendStatus.TempFail), "no next hop takes it later: a permanent failure, or a conversion" + Explain(server));
        });

    }


    [Test]
    [Property("Finding", "O-33")]
    [Description("RFC 3030 §3: binary data goes as BODY=BINARYMIME, and \"BINARYMIME cannot be used with the DATA command\"; RFC 6152 §3: not as BODY=8BITMIME - to a next hop that offers CHUNKING and BINARYMIME, binary data goes as BDAT with BODY=BINARYMIME, or not at all")]
    public async Task Binary_data_goes_to_a_next_hop_with_BINARYMIME_as_BODY_BINARYMIME_only()
    {

        var script = new SmtpServerScript { Extensions = [ "PIPELINING", "SIZE 10485760", "8BITMIME", "ENHANCEDSTATUSCODES", "CHUNKING", "BINARYMIME" ] };
        await using var server = ScriptedSmtpServer.Start(script);

        await SendDirect(server, BinaryEnvelope(new String('x', 1200)));

        Assert.That(script.Transactions.Where(SubmissionClientTests.BinaryArrived).
                                        Where(transaction => !transaction.UsedBdat || transaction.MailFromLine?.Contains(" BODY=BINARYMIME") != true).
                                        Select(SubmissionClientTests.Describe),
                    Is.Empty, Explain(server));

    }


    [Test(Description = "RFC 2045 §2.7, §2.8: a line of 998 octets is no binary data - \"998 octets or less\" -, and is relayed as before (a guard)")]
    [Property("Finding", "O-32")]
    public async Task A_line_of_998_octets_is_relayed()
    {

        var script = new SmtpServerScript { Extensions = [ "PIPELINING", "SIZE 10485760", "8BITMIME", "ENHANCEDSTATUSCODES" ] };
        await using var server = ScriptedSmtpServer.Start(script);

        var line   = new String('y', 998);
        var result = await SendDirect(server, Envelope([ "you@outbound.test" ], line));

        Assert.Multiple(() => {
            Assert.That(result.Status, Is.EqualTo(SendStatus.Success), Explain(server));
            Assert.That(script.Transactions.SelectMany(SubmissionClientTests.ArrivedLines).Any(arrived => arrived.SequenceEqual(System.Text.Encoding.ASCII.GetBytes(line))),
                        Is.True, "the line arrived as it is" + Explain(server));
        });

    }

    #endregion

}
