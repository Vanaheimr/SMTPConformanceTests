using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;

namespace SMTPConformance.Core.RawSmtp;

/// <summary>
/// An SMTP client that sends exactly the bytes a test asks for and parses the
/// replies without any help from Hermod — the independent half of every
/// server-side conformance check.
/// </summary>
public sealed class RawSmtpClient : SmtpWire
{

    private readonly TcpClient tcp;

    /// <summary>
    /// The default wait for a reply.
    /// </summary>
    public TimeSpan ReplyTimeout { get; init; } = TimeSpan.FromSeconds(10);


    private RawSmtpClient(TcpClient Tcp, Stream Stream)
        : base(Stream)
    {
        this.tcp = Tcp;
    }


    /// <summary>
    /// Open a connection. Nothing is read: the caller reads the greeting.
    /// </summary>
    /// <param name="ImplicitTls">Start TLS before the first SMTP byte (RFC 8314 §3.3).</param>
    public static async Task<RawSmtpClient> ConnectAsync(String   Host,
                                                         UInt16   Port,
                                                         Boolean  ImplicitTls  = false,
                                                         TimeSpan? Timeout     = null)
    {

        var tcp = new TcpClient { NoDelay = true };

        using (var cts = new CancellationTokenSource(Timeout ?? TimeSpan.FromSeconds(10)))
            await tcp.ConnectAsync(Host, Port, cts.Token);

        Stream stream = tcp.GetStream();

        if (ImplicitTls)
        {

            var tls = new SslStream(stream, leaveInnerStreamOpen: false, (_, _, _, _) => true);

            await tls.AuthenticateAsClientAsync(
                      new SslClientAuthenticationOptions {
                          TargetHost           = Host,
                          EnabledSslProtocols  = SslProtocols.Tls12 | SslProtocols.Tls13
                      }
                  );

            stream = tls;

        }

        return new RawSmtpClient(tcp, stream);

    }


    /// <summary>
    /// Connect and read the greeting.
    /// </summary>
    public static async Task<(RawSmtpClient Client, SmtpReply Greeting)> ConnectAndGreetAsync(String   Host,
                                                                                               UInt16   Port,
                                                                                               Boolean  ImplicitTls = false)
    {
        var client   = await ConnectAsync(Host, Port, ImplicitTls);
        var greeting = await client.ReadReplyAsync();
        return (client, greeting);
    }


    /// <summary>
    /// Read one complete reply, however many lines it has.
    /// </summary>
    /// <exception cref="TimeoutException">No complete reply arrived in time.</exception>
    /// <exception cref="IOException">The connection closed mid-reply or before it.</exception>
    public async Task<SmtpReply> ReadReplyAsync(TimeSpan? Timeout = null)
    {

        var lines       = new List<String>();
        var violations  = new List<String>();

        while (true)
        {

            var line = await ReadLineAsync(Timeout ?? ReplyTimeout)
                           ?? throw new IOException(lines.Count == 0
                                                        ? $"The connection closed instead of a reply.\n{Transcript}"
                                                        : $"The connection closed in the middle of a reply.\n{Transcript}");

            if (line.Terminator == LineTerminator.BareLF)
                violations.Add($"reply line {lines.Count + 1} ends in a bare LF (RFC 5321 §2.3.8)");

            if (line.Terminator == LineTerminator.EndOfStream)
                violations.Add($"reply line {lines.Count + 1} was cut off by the connection closing");

            var text = line.Latin1;
            lines.Add(text);

            // The final line has a space (or nothing) after the code; anything else
            // means more lines follow. A line too short to tell is taken as final, so
            // a broken reply cannot make the reader wait forever.
            if (text.Length <= 3 || text[3] != '-' || line.Terminator == LineTerminator.EndOfStream)
                return SmtpReply.Parse(lines, violations);

        }

    }


    /// <summary>
    /// Read a reply, or null if the connection closed (or nothing came) first.
    /// </summary>
    public async Task<SmtpReply?> TryReadReplyAsync(TimeSpan? Timeout = null)
    {
        try
        {
            return await ReadReplyAsync(Timeout);
        }
        catch (Exception e) when (e is IOException or TimeoutException)
        {
            return null;
        }
    }


    /// <summary>
    /// Send one command line (CRLF appended) and read its reply.
    /// </summary>
    public async Task<SmtpReply> CommandAsync(String Line, TimeSpan? Timeout = null)
    {
        await WriteLineAsync(Line);
        return await ReadReplyAsync(Timeout);
    }


    /// <summary>
    /// EHLO, returning the reply and the advertised extension keywords (upper-cased,
    /// parameters split off) — RFC 5321 §4.1.1.1: the first line is the greeting,
    /// every further line one ehlo-line.
    /// </summary>
    public async Task<(SmtpReply Reply, IReadOnlyDictionary<String, String> Extensions)> EhloAsync(String Domain = "client.example")
    {

        var reply       = await CommandAsync("EHLO " + Domain);
        var extensions  = new Dictionary<String, String>(StringComparer.OrdinalIgnoreCase);

        foreach (var line in reply.Lines.Skip(1))
        {
            var space = line.IndexOf(' ');
            var key   = (space < 0 ? line : line[..space]).ToUpperInvariant();
            extensions[key] = space < 0 ? "" : line[(space + 1)..];
        }

        return (reply, extensions);

    }


    /// <summary>
    /// STARTTLS and the TLS handshake. Returns the STARTTLS reply; the stream is TLS
    /// only if that reply was 220.
    /// </summary>
    public async Task<SmtpReply> StartTlsAsync(String TargetHost = "localhost")
    {

        var reply = await CommandAsync("STARTTLS");

        if (reply.Code == 220)
            await UpgradeToTlsAsClientAsync(TargetHost);

        return reply;

    }


    /// <summary>
    /// Close the sending direction (TCP FIN) while still reading.
    /// </summary>
    public void ShutdownSend()
    {
        try
        {
            tcp.Client.Shutdown(SocketShutdown.Send);
        }
        catch
        {
            // already gone
        }
    }


    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        tcp.Dispose();
    }

}
