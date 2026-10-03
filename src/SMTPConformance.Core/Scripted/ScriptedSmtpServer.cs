using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Core.Scripted;

/// <summary>
/// The server side of one scripted connection: a byte-exact wire, plus a record
/// of every line the client sent.
/// </summary>
public sealed class ScriptedSmtpSession : SmtpWire
{

    private readonly TcpClient tcp;

    /// <summary>
    /// Every line read from the client, in order, with TLS state at the time.
    /// </summary>
    public List<(WireLine Line, Boolean Tls)>  Received   { get; } = [];

    public ScriptedSmtpSession(TcpClient Tcp)
        : base(Tcp.GetStream())
    {
        this.tcp          = Tcp;
        this.ReadPrefix   = "C: ";
        this.WritePrefix  = "S: ";
    }

    /// <summary>
    /// Read one line from the client and record it.
    /// </summary>
    public async Task<WireLine?> ReadCommandAsync(TimeSpan? Timeout = null)
    {

        var line = await ReadLineAsync(Timeout ?? TimeSpan.FromSeconds(30));

        if (line is not null)
            lock (Received)
                Received.Add((line, IsTls));

        return line;

    }

    /// <summary>
    /// Write reply lines exactly as given, each followed by CRLF.
    /// </summary>
    public async Task ReplyAsync(params String[] Lines)
    {
        foreach (var line in Lines)
            await WriteLineAsync(line);
    }

    /// <summary>
    /// Drop the connection without a word.
    /// </summary>
    public void Abort()
    {
        try
        {
            tcp.Client.LingerState = new LingerOption(true, 0);
            tcp.Close();
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


/// <summary>
/// A loopback TCP server that runs a test-supplied script for every connection —
/// the stand-in peer for testing Hermod's SMTP <i>clients</i>.
/// </summary>
public sealed class ScriptedSmtpServer : IAsyncDisposable
{

    private readonly TcpListener                          listener;
    private readonly Func<ScriptedSmtpSession, Task>      script;
    private readonly ConcurrentQueue<ScriptedSmtpSession> sessions  = new();
    private readonly ConcurrentQueue<Task>                running   = new();
    private readonly ConcurrentQueue<Exception>           failures  = new();
    private readonly CancellationTokenSource              cts       = new();
    private readonly Task                                 acceptLoop;

    public UInt16 Port
        => (UInt16) ((IPEndPoint) listener.LocalEndpoint).Port;

    /// <summary>
    /// Every connection accepted so far, in order.
    /// </summary>
    public IReadOnlyList<ScriptedSmtpSession> Sessions
        => [.. sessions];

    /// <summary>
    /// Exceptions the script threw. A script that fails is reported, not swallowed.
    /// </summary>
    public IReadOnlyCollection<Exception> ScriptFailures
        => failures;


    private ScriptedSmtpServer(Func<ScriptedSmtpSession, Task> Script)
    {

        script    = Script;
        listener  = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        acceptLoop = Task.Run(AcceptLoopAsync);

    }

    public static ScriptedSmtpServer Start(Func<ScriptedSmtpSession, Task> Script)
        => new (Script);

    /// <summary>
    /// Start a server that runs a <see cref="SmtpServerScript"/>.
    /// </summary>
    public static ScriptedSmtpServer Start(SmtpServerScript Script)
        => new (Script.RunAsync);


    private async Task AcceptLoopAsync()
    {
        try
        {
            while (!cts.IsCancellationRequested)
            {

                var tcp      = await listener.AcceptTcpClientAsync(cts.Token);
                var session  = new ScriptedSmtpSession(tcp);

                sessions.Enqueue(session);

                running.Enqueue(Task.Run(async () => {
                    try
                    {
                        await script(session);
                    }
                    catch (Exception e) when (e is not IOException and not ObjectDisposedException)
                    {
                        failures.Enqueue(e);
                    }
                    catch
                    {
                        // The client hung up — often the very thing under test.
                    }
                    finally
                    {
                        await session.DisposeAsync();
                    }
                }));

            }
        }
        catch
        {
            // listener stopped
        }
    }


    /// <summary>
    /// Wait until every session that has started has finished its script.
    /// </summary>
    public async Task WhenIdleAsync(TimeSpan? Timeout = null)
    {
        try
        {
            await Task.WhenAll(running).WaitAsync(Timeout ?? TimeSpan.FromSeconds(3));
        }
        catch (TimeoutException)
        {
            // A session still waiting for a client that left is not an error here.
        }
    }


    /// <summary>
    /// A readable dump of every session, for assertion messages.
    /// </summary>
    public String Transcript
        => String.Join("\n---\n", sessions.Select(session => session.Transcript.ToString()));


    public async ValueTask DisposeAsync()
    {

        await cts.CancelAsync();
        listener.Stop();

        foreach (var session in sessions)
            session.Abort();

        try { await acceptLoop.WaitAsync(TimeSpan.FromSeconds(5)); } catch { }
        try { await Task.WhenAll(running).WaitAsync(TimeSpan.FromSeconds(5)); } catch { }

        cts.Dispose();

    }

}
