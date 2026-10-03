using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SMTPConformance.Core.RawSmtp;

/// <summary>
/// How a line read from the wire was terminated.
/// </summary>
public enum LineTerminator
{

    /// <summary>
    /// CR LF — the only terminator RFC 5321 §2.3.8 permits.
    /// </summary>
    CRLF,

    /// <summary>
    /// A LF with no CR before it.
    /// </summary>
    BareLF,

    /// <summary>
    /// The connection closed before any terminator arrived.
    /// </summary>
    EndOfStream

}

/// <summary>
/// One line as it arrived, with the bytes and the terminator kept apart.
/// </summary>
/// <param name="Bytes">The line's octets without the terminator. A bare CR inside the line stays here.</param>
/// <param name="Terminator">How the line ended.</param>
public sealed record WireLine(Byte[] Bytes, LineTerminator Terminator)
{

    /// <summary>
    /// The line as Latin-1: one char per octet, so nothing is lost or guessed.
    /// </summary>
    public String Latin1
        => Encoding.Latin1.GetString(Bytes);

    /// <summary>
    /// The line decoded as UTF-8 (RFC 6531 content).
    /// </summary>
    public String Utf8
        => Encoding.UTF8.GetString(Bytes);

    public Boolean ContainsBareCR
        => Bytes.Contains((Byte) '\r');

    public override String ToString()
        => Latin1 + Terminator switch {
                        LineTerminator.CRLF    => "<CRLF>",
                        LineTerminator.BareLF  => "<LF>",
                        _                      => "<EOF>"
                    };

}


/// <summary>
/// A byte-exact SMTP stream, shared by the raw client and the scripted server.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately <i>not</i> a <see cref="StreamReader"/>. <c>StreamReader.ReadLine</c>
/// accepts CR, LF and CRLF alike as a line end, which is precisely the
/// ambiguity SMTP smuggling lives in; a test peer built on it could neither
/// produce nor notice the difference. This reader splits on LF only and reports
/// whether a CR came before it.
/// </para>
/// <para>
/// It also never reads ahead past what the caller asked for in a way that
/// matters: <see cref="UpgradeToTlsAsServerAsync"/> and
/// <see cref="UpgradeToTlsAsClientAsync"/> refuse to run while plaintext is
/// still buffered, so a test that pipelines across STARTTLS sees exactly what
/// the other side did with those bytes.
/// </para>
/// </remarks>
public class SmtpWire : IAsyncDisposable
{

    private Stream         stream;
    private readonly Byte[] buffer = new Byte[64 * 1024];
    private Int32          start;
    private Int32          end;

    /// <summary>
    /// Everything written and read, for failure messages. "C:" is this side, "S:" the peer.
    /// </summary>
    public StringBuilder   Transcript      { get; } = new();

    /// <summary>
    /// Whether the stream is currently TLS.
    /// </summary>
    public Boolean         IsTls           => stream is SslStream;

    /// <summary>
    /// The TLS stream, once there is one.
    /// </summary>
    public SslStream?      Tls             => stream as SslStream;

    /// <summary>
    /// Plaintext bytes received but not yet consumed.
    /// </summary>
    public Int32           BufferedBytes   => end - start;

    /// <summary>
    /// The longest line <see cref="ReadLineAsync"/> will accumulate before giving up.
    /// </summary>
    public Int32           MaxLineLength   { get; init; } = 1024 * 1024;

    protected String       ReadPrefix      { get; init; } = "S: ";
    protected String       WritePrefix     { get; init; } = "C: ";


    public SmtpWire(Stream Stream)
    {
        this.stream = Stream;
    }


    #region Reading

    /// <summary>
    /// Fill the buffer with at least one more byte. Returns false at end of stream.
    /// </summary>
    private async Task<Boolean> FillAsync(CancellationToken CancellationToken)
    {

        if (start == end)
        {
            start = 0;
            end   = 0;
        }
        else if (end == buffer.Length)
        {
            Buffer.BlockCopy(buffer, start, buffer, 0, end - start);
            end   -= start;
            start  = 0;
        }

        Int32 read;

        try
        {
            read = await stream.ReadAsync(buffer.AsMemory(end), CancellationToken);
        }
        catch (IOException)
        {
            return false;
        }
        catch (ObjectDisposedException)
        {
            return false;
        }

        end += read;
        return read > 0;

    }


    /// <summary>
    /// Read one line, splitting on LF only.
    /// </summary>
    /// <returns>The line, or null when the connection closed before any byte of it arrived.</returns>
    public async Task<WireLine?> ReadLineAsync(TimeSpan? Timeout = null, CancellationToken CancellationToken = default)
    {

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken);
        cts.CancelAfter(Timeout ?? TimeSpan.FromSeconds(10));

        var line = new MemoryStream();

        while (true)
        {

            for (var i = start; i < end; i++)
            {
                if (buffer[i] == (Byte) '\n')
                {

                    line.Write(buffer, start, i - start);
                    start = i + 1;

                    var bytes = line.ToArray();
                    var crlf  = bytes.Length > 0 && bytes[^1] == (Byte) '\r';

                    var result = new WireLine(crlf ? bytes[..^1] : bytes,
                                              crlf ? LineTerminator.CRLF : LineTerminator.BareLF);

                    Transcript.Append(ReadPrefix).AppendLine(result.ToString());
                    return result;

                }
            }

            line.Write(buffer, start, end - start);
            start = end;

            if (line.Length > MaxLineLength)
                throw new InvalidDataException($"The peer sent more than {MaxLineLength} bytes without a line feed.");

            Boolean more;

            try
            {
                more = await FillAsync(cts.Token);
            }
            catch (OperationCanceledException) when (!CancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException($"No complete line within {Timeout ?? TimeSpan.FromSeconds(10)}.\n{Transcript}");
            }

            if (!more)
            {

                if (line.Length == 0)
                    return null;

                var partial = new WireLine(line.ToArray(), LineTerminator.EndOfStream);
                Transcript.Append(ReadPrefix).AppendLine(partial.ToString());
                return partial;

            }

        }

    }


    /// <summary>
    /// Read exactly <paramref name="Count"/> bytes (a BDAT chunk).
    /// </summary>
    /// <returns>The bytes, or null if the stream ended first.</returns>
    public async Task<Byte[]?> ReadExactlyAsync(Int32 Count, TimeSpan? Timeout = null, CancellationToken CancellationToken = default)
    {

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken);
        cts.CancelAfter(Timeout ?? TimeSpan.FromSeconds(10));

        var result = new Byte[Count];
        var have   = 0;

        while (have < Count)
        {

            if (start == end && !await FillAsync(cts.Token))
                return null;

            var take = Math.Min(Count - have, end - start);
            Buffer.BlockCopy(buffer, start, result, have, take);
            start += take;
            have  += take;

        }

        Transcript.Append(ReadPrefix).AppendLine($"<{Count} octets>");
        return result;

    }


    /// <summary>
    /// Whether the peer closes the connection within <paramref name="Within"/>
    /// without sending anything more.
    /// </summary>
    /// <returns>True on a clean close (or a reset); false if data arrived or the time ran out.</returns>
    public async Task<Boolean> ClosesWithinAsync(TimeSpan Within)
    {

        if (start < end)
            return false;

        using var cts = new CancellationTokenSource(Within);

        try
        {
            return !await FillAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            return false;
        }

    }

    #endregion

    #region Writing

    /// <summary>
    /// Write raw bytes, exactly as given. No terminator is added.
    /// </summary>
    public async Task WriteRawAsync(Byte[] Bytes, CancellationToken CancellationToken = default)
    {
        Transcript.Append(WritePrefix).AppendLine(Escape(Bytes));
        await stream.WriteAsync(Bytes, CancellationToken);
        await stream.FlushAsync(CancellationToken);
    }

    /// <summary>
    /// Write a string as Latin-1 (one octet per char), exactly as given. No terminator is added.
    /// </summary>
    public Task WriteRawAsync(String Text, CancellationToken CancellationToken = default)
        => WriteRawAsync(Encoding.Latin1.GetBytes(Text), CancellationToken);

    /// <summary>
    /// Write one line as UTF-8 followed by CRLF.
    /// </summary>
    public Task WriteLineAsync(String Line, CancellationToken CancellationToken = default)
        => WriteRawAsync(Encoding.UTF8.GetBytes(Line + "\r\n"), CancellationToken);

    private static String Escape(Byte[] bytes)
        => bytes.Length > 512
               ? $"<{bytes.Length} octets>"
               : Encoding.Latin1.GetString(bytes).Replace("\r", "<CR>").Replace("\n", "<LF>");

    #endregion

    #region TLS

    /// <summary>
    /// Switch to TLS as the client. Any certificate is accepted: these tests are
    /// about SMTP, and the fixtures use self-signed ones.
    /// </summary>
    public async Task UpgradeToTlsAsClientAsync(String TargetHost, CancellationToken CancellationToken = default)
    {

        if (BufferedBytes > 0)
            throw new InvalidOperationException($"{BufferedBytes} plaintext bytes are still buffered — the peer sent data after its STARTTLS reply.");

        var tls = new SslStream(stream, leaveInnerStreamOpen: false, (_, _, _, _) => true);

        await tls.AuthenticateAsClientAsync(
                  new SslClientAuthenticationOptions {
                      TargetHost           = TargetHost,
                      EnabledSslProtocols  = SslProtocols.Tls12 | SslProtocols.Tls13
                  },
                  CancellationToken
              );

        stream = tls;
        Transcript.AppendLine($"-- TLS {tls.SslProtocol} --");

    }

    /// <summary>
    /// Switch to TLS as the server.
    /// </summary>
    public async Task UpgradeToTlsAsServerAsync(X509Certificate2 Certificate, CancellationToken CancellationToken = default)
    {

        // Unlike the client side this does not refuse buffered bytes: a server that
        // receives commands pipelined after STARTTLS is supposed to discard them,
        // and that is what happens to whatever is in the buffer here.
        start = end = 0;

        var tls = new SslStream(stream, leaveInnerStreamOpen: false);

        await tls.AuthenticateAsServerAsync(
                  new SslServerAuthenticationOptions {
                      ServerCertificate    = Certificate,
                      EnabledSslProtocols  = SslProtocols.Tls12 | SslProtocols.Tls13
                  },
                  CancellationToken
              );

        stream = tls;
        Transcript.AppendLine($"-- TLS {tls.SslProtocol} --");

    }

    #endregion


    public virtual async ValueTask DisposeAsync()
    {
        try
        {
            await stream.DisposeAsync();
        }
        catch
        {
            // already gone
        }
        GC.SuppressFinalize(this);
    }

}
