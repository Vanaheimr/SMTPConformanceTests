using System.Security.Cryptography.X509Certificates;
using System.Text;

using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Core.Scripted;

/// <summary>
/// One mail transaction as a scripted server saw it.
/// </summary>
public sealed class ScriptedTransaction
{

    public String?          MailFromLine   { get; set; }
    public List<String>     RcptToLines    { get; } = [];

    /// <summary>
    /// The DATA lines exactly as received — still dot-stuffed, terminator kept apart.
    /// </summary>
    public List<WireLine>   DataLines      { get; } = [];

    /// <summary>
    /// The concatenated BDAT chunks.
    /// </summary>
    public MemoryStream     BdatContent    { get; } = new();

    public Boolean          UsedBdat       { get; set; }

    public Boolean          Tls            { get; set; }

}


/// <summary>
/// A configurable, well-behaved SMTP server dialogue — the default peer for
/// client tests. Each property bends one part of it.
/// </summary>
/// <remarks>
/// <para>
/// End of DATA is recognised strictly: a line consisting of a single "." that
/// ends in CR LF, after a line that also ended in CR LF. A client that sends
/// bare LFs therefore never finishes its DATA here and times out — which is the
/// visible symptom the tests look for, rather than a reinterpretation.
/// </para>
/// </remarks>
public sealed class SmtpServerScript
{

    public String                   Greeting           { get; init; } = "220 scripted.test ESMTP ready";

    /// <summary>
    /// The extension lines advertised after the EHLO greeting line.
    /// </summary>
    public IReadOnlyList<String>    Extensions         { get; init; } = [ "PIPELINING", "SIZE 10485760", "8BITMIME", "ENHANCEDSTATUSCODES", "SMTPUTF8", "DSN" ];

    /// <summary>
    /// When set, the complete reply to EHLO (lines with codes), instead of the extension list.
    /// </summary>
    public String[]?                EhloReply          { get; init; }

    /// <summary>
    /// Offer STARTTLS with this certificate. Null: STARTTLS is neither advertised nor accepted.
    /// </summary>
    public X509Certificate2?        Certificate        { get; init; }

    /// <summary>
    /// The issuers of <see cref="Certificate"/>, sent along with it in the TLS handshake.
    /// </summary>
    public IReadOnlyList<X509Certificate2> CertificateChain { get; init; } = [];

    /// <summary>
    /// The reply to STARTTLS. The handshake follows only when it starts with "220".
    /// </summary>
    public String                   StartTlsReply      { get; init; } = "220 2.0.0 Ready to start TLS";

    /// <summary>
    /// Mechanisms advertised in the AUTH extension. Empty: no AUTH.
    /// </summary>
    public IReadOnlyList<String>    AuthMechanisms     { get; init; } = [];

    /// <summary>
    /// Advertise AUTH before TLS as well.
    /// </summary>
    public Boolean                  AuthBeforeTls      { get; init; } = false;

    public String                   MailReply          { get; init; } = "250 2.1.0 Ok";

    /// <summary>
    /// The reply to each RCPT, by the address inside the angle brackets.
    /// </summary>
    public Func<String, String>     RcptReply          { get; init; } = _ => "250 2.1.5 Ok";

    public String                   DataReply          { get; init; } = "354 End data with <CR><LF>.<CR><LF>";

    public String                   EndOfDataReply     { get; init; } = "250 2.0.0 Ok: queued";

    /// <summary>
    /// The reply to QUIT. The script closes the connection after it.
    /// </summary>
    public String                   QuitReply          { get; init; } = "221 2.0.0 Bye";


    /// <summary>
    /// Every transaction across all sessions, in order of MAIL.
    /// </summary>
    public List<ScriptedTransaction> Transactions      { get; } = [];

    /// <summary>
    /// Every command line across all sessions, with TLS state when it arrived.
    /// </summary>
    public List<(String Line, Boolean Tls)> Commands   { get; } = [];


    private void Record(String line, Boolean tls)
    {
        lock (Commands)
            Commands.Add((line, tls));
    }


    public async Task RunAsync(ScriptedSmtpSession s)
    {

        // An empty greeting means the caller has already sent its own.
        if (Greeting.Length > 0)
            await s.ReplyAsync(Greeting);

        ScriptedTransaction? transaction = null;

        while (true)
        {

            var line = await s.ReadCommandAsync();

            if (line is null || line.Terminator == LineTerminator.EndOfStream)
                return;

            var text  = line.Utf8;
            Record(text, s.IsTls);

            var space = text.IndexOf(' ');
            var verb  = (space < 0 ? text : text[..space]).ToUpperInvariant();

            switch (verb)
            {

                case "EHLO":
                    if (EhloReply is not null)
                    {
                        await s.ReplyAsync(EhloReply);
                        break;
                    }
                    var lines = new List<String> { "scripted.test Hello" };
                    lines.AddRange(Extensions);
                    if (Certificate is not null && !s.IsTls)
                        lines.Add("STARTTLS");
                    if (AuthMechanisms.Count > 0 && (s.IsTls || AuthBeforeTls))
                        lines.Add("AUTH " + String.Join(' ', AuthMechanisms));
                    await s.ReplyAsync([.. lines.Select((l, i) => (i == lines.Count - 1 ? "250 " : "250-") + l)]);
                    break;

                case "HELO":
                    await s.ReplyAsync("250 scripted.test");
                    break;

                case "STARTTLS":
                    if (Certificate is null)
                    {
                        await s.ReplyAsync("502 5.5.1 STARTTLS not offered");
                        break;
                    }
                    await s.ReplyAsync(StartTlsReply);
                    if (StartTlsReply.StartsWith("220"))
                    {
                        await s.UpgradeToTlsAsServerAsync(Certificate, CertificateChain);
                        transaction = null;
                    }
                    break;

                case "AUTH":
                    await HandleAuthAsync(s, text);
                    break;

                case "MAIL":
                    transaction = new ScriptedTransaction { MailFromLine = text, Tls = s.IsTls };
                    lock (Transactions)
                        Transactions.Add(transaction);
                    await s.ReplyAsync(MailReply);
                    break;

                case "RCPT":
                    transaction?.RcptToLines.Add(text);
                    var open  = text.IndexOf('<');
                    var close = text.IndexOf('>');
                    await s.ReplyAsync(RcptReply(open >= 0 && close > open ? text[(open + 1)..close] : text));
                    break;

                case "DATA":
                    await s.ReplyAsync(DataReply);
                    if (!DataReply.StartsWith('3'))
                        break;
                    var previousEndedInCrLf = true;
                    while (true)
                    {
                        var dataLine = await s.ReadLineAsync(TimeSpan.FromSeconds(30));
                        if (dataLine is null || dataLine.Terminator == LineTerminator.EndOfStream)
                            return;
                        if (previousEndedInCrLf &&
                            dataLine.Terminator == LineTerminator.CRLF &&
                            dataLine.Bytes is [ (Byte) '.' ])
                            break;
                        transaction?.DataLines.Add(dataLine);
                        previousEndedInCrLf = dataLine.Terminator == LineTerminator.CRLF;
                    }
                    await s.ReplyAsync(EndOfDataReply);
                    break;

                case "BDAT":
                    var parts = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    var size  = parts.Length > 1 && Int32.TryParse(parts[1], out var n) ? n : -1;
                    if (size < 0)
                    {
                        await s.ReplyAsync("501 5.5.4 Syntax: BDAT size [LAST]");
                        break;
                    }
                    var chunk = await s.ReadExactlyAsync(size, TimeSpan.FromSeconds(30));
                    if (chunk is null)
                        return;
                    if (transaction is not null)
                    {
                        transaction.UsedBdat = true;
                        transaction.BdatContent.Write(chunk);
                    }
                    await s.ReplyAsync(parts.Length > 2 && parts[2].Equals("LAST", StringComparison.OrdinalIgnoreCase)
                                           ? EndOfDataReply
                                           : $"250 2.0.0 {size} octets received");
                    break;

                case "RSET":
                    transaction = null;
                    await s.ReplyAsync("250 2.0.0 Ok");
                    break;

                case "NOOP":
                    await s.ReplyAsync("250 2.0.0 Ok");
                    break;

                case "QUIT":
                    await s.ReplyAsync(QuitReply);
                    return;

                default:
                    await s.ReplyAsync("500 5.5.2 Command unrecognized");
                    break;

            }

        }

    }


    private async Task HandleAuthAsync(ScriptedSmtpSession s, String text)
    {

        var parts     = text.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        var mechanism = parts.Length > 1 ? parts[1].ToUpperInvariant() : "";

        if (!AuthMechanisms.Contains(mechanism, StringComparer.OrdinalIgnoreCase))
        {
            await s.ReplyAsync("504 5.5.4 Unrecognized authentication type");
            return;
        }

        switch (mechanism)
        {

            case "PLAIN":
                if (parts.Length < 3)
                {
                    await s.ReplyAsync("334 ");
                    var response = await s.ReadCommandAsync();
                    if (response is not null)
                        Record(response.Utf8, s.IsTls);
                }
                await s.ReplyAsync("235 2.7.0 Authentication successful");
                break;

            case "LOGIN":
                await s.ReplyAsync("334 " + Convert.ToBase64String(Encoding.ASCII.GetBytes("Username:")));
                var user = await s.ReadCommandAsync();
                if (user is not null)
                    Record(user.Utf8, s.IsTls);
                await s.ReplyAsync("334 " + Convert.ToBase64String(Encoding.ASCII.GetBytes("Password:")));
                var password = await s.ReadCommandAsync();
                if (password is not null)
                    Record(password.Utf8, s.IsTls);
                await s.ReplyAsync("235 2.7.0 Authentication successful");
                break;

            default:
                await s.ReplyAsync("504 5.5.4 Mechanism not scripted");
                break;

        }

    }

}
