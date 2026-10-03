using System.Globalization;
using System.Text;

namespace SMTPConformance.Core.RawSmtp;

/// <summary>
/// The everyday dialogue steps, so a test spells out only the part it is about.
/// </summary>
public static class RawSmtpClientExtensions
{

    /// <summary>
    /// A minimal RFC 5322 message: headers, an empty line, the body lines. CRLF throughout,
    /// including after the last body line.
    /// </summary>
    public static String Message(String From, String To, String Subject, params String[] BodyLines)

        => String.Concat(
               $"From: <{From}>\r\n",
               $"To: <{To}>\r\n",
               $"Subject: {Subject}\r\n",
               $"Message-ID: <{Guid.NewGuid():N}@client.example>\r\n",
               $"Date: {DateTimeOffset.UtcNow.ToString("ddd, dd MMM yyyy HH:mm:ss", CultureInfo.InvariantCulture)} +0000\r\n",
               "\r\n",
               String.Concat(BodyLines.Select(line => line + "\r\n"))
           );


    /// <summary>
    /// Dot-stuff a CRLF-terminated message for DATA (RFC 5321 §4.5.2).
    /// </summary>
    public static String DotStuff(String Message)
        => (Message.StartsWith('.') ? "." : "") + Message.Replace("\r\n.", "\r\n..");


    /// <summary>
    /// MAIL, one RCPT per recipient; asserts nothing, returns the replies.
    /// </summary>
    public static async Task<(SmtpReply Mail, SmtpReply[] Rcpts)> EnvelopeAsync(this RawSmtpClient     Client,
                                                                                String                 From,
                                                                                params String[]        To)
    {

        var mail  = await Client.CommandAsync($"MAIL FROM:<{From}>");
        var rcpts = new List<SmtpReply>();

        foreach (var to in To)
            rcpts.Add(await Client.CommandAsync($"RCPT TO:<{to}>"));

        return (mail, [.. rcpts]);

    }


    /// <summary>
    /// DATA, the dot-stuffed message, the terminating dot. Returns the DATA reply and the
    /// final reply (null when DATA was not answered with 354).
    /// </summary>
    public static async Task<(SmtpReply Data, SmtpReply? Final)> DataAsync(this RawSmtpClient Client,
                                                                          String             Message)
    {

        var data = await Client.CommandAsync("DATA");

        if (data.Code != 354)
            return (data, null);

        await Client.WriteRawAsync(Encoding.UTF8.GetBytes(DotStuff(Message) + ".\r\n"));

        return (data, await Client.ReadReplyAsync());

    }


    /// <summary>
    /// A complete transaction: envelope, DATA, end of data. Returns the final reply,
    /// or the first one that was not positive.
    /// </summary>
    public static async Task<SmtpReply> SendMailAsync(this RawSmtpClient Client,
                                                      String             From,
                                                      String             To,
                                                      String?            Message = null)
    {

        var (mail, rcpts) = await Client.EnvelopeAsync(From, To);

        if (mail.Code != 250)
            return mail;

        if (rcpts[0].Code is not 250 and not 251)
            return rcpts[0];

        var (data, final) = await Client.DataAsync(Message ?? RawSmtpClientExtensions.Message(From, To, "conformance", "Hello."));

        return final ?? data;

    }


    /// <summary>
    /// Count the replies that arrive within <paramref name="Window"/> — for asserting that
    /// a server did <i>not</i> answer something it should have treated as data.
    /// </summary>
    public static async Task<List<SmtpReply>> DrainRepliesAsync(this RawSmtpClient Client,
                                                                TimeSpan           Window)
    {

        var replies  = new List<SmtpReply>();
        var deadline = DateTime.UtcNow + Window;

        while (DateTime.UtcNow < deadline)
        {

            var reply = await Client.TryReadReplyAsync(deadline - DateTime.UtcNow);

            if (reply is null)
                break;

            replies.Add(reply);

        }

        return replies;

    }

}
