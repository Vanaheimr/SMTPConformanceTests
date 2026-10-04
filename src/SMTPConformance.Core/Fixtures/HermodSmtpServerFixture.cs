using System.Security.Cryptography.X509Certificates;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;
using org.GraphDefined.Vanaheimr.Hermod.SMTP.Server;

using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Core.Fixtures;

public sealed class HermodSmtpServerFixtureOptions
{

    /// <summary>
    /// The server's own name: the greeting, the EHLO reply and the <c>by</c> clause of <c>Received:</c>.
    /// </summary>
    public String                                     Hostname                 { get; init; } = "mx.hermod.test";

    /// <summary>
    /// Mail to these domains is delivered locally; anything else is a relay request.
    /// </summary>
    public IEnumerable<String>                        LocalDomains             { get; init; } = [ "hermod.test", "localhost" ];

    /// <summary>
    /// Configure a certificate: STARTTLS on the MTA and submission ports, and the implicit-TLS port.
    /// </summary>
    public Boolean                                    EnableTls                { get; init; } = false;

    public Boolean                                    RequireStartTls          { get; init; } = false;

    /// <summary>
    /// Where the server listens, every port chosen by the system. Default: every IPv4 address -
    /// the interop tests reach the server from WSL, through the host's address, not loopback.
    /// </summary>
    public IReadOnlyList<System.Net.IPAddress>        ListenAddresses          { get; init; } = [ System.Net.IPAddress.Any ];

    public Int32                                      MaxMessageSize           { get; init; } = 1024 * 1024;

    public Int32                                      MaxRecipients            { get; init; } = 100;

    public Int32                                      MaxCommandLineLength     { get; init; } = 1024;

    public Int32                                      MaxTextLineLength        { get; init; } = 2048;

    public Boolean                                    RequireAuthForRelay      { get; init; } = true;

    public Boolean                                    RequireAuthOnSubmission  { get; init; } = true;

    public TimeSpan                                   SessionTimeout           { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// User name → clear-text password.
    /// </summary>
    public IEnumerable<KeyValuePair<String, String>>  Users                    { get; init; } = [ new("alice", "correct horse battery staple") ];

    /// <summary>
    /// Rate limits. The default keeps the server's per-session limits but drops the
    /// three-second penalty after a failed AUTH, which would otherwise dominate the
    /// runtime of every negative authentication test.
    /// </summary>
    public RateLimitConfig                            RateLimits               { get; init; } = new() {
                                                                                                    AuthFailDelayMs              = 0,
                                                                                                    MaxAuthAttemptsPerIpPerHour  = 10000,
                                                                                                    MaxConnectionsPerIpPerMinute = 10000,
                                                                                                    MaxMessagesPerIpPerHour      = 10000
                                                                                                };

    public StubDnsClient                              Dns                      { get; init; } = new();

}


/// <summary>
/// Starts a real Hermod <see cref="SMTPServer"/> on three free ports — MTA,
/// submission and implicit-TLS submission — with in-memory storage, queue and
/// users, and a canned DNS.
/// </summary>
/// <remarks>
/// <para>
/// <c>SMTPServer.Start()</c> does not return once it listens: it awaits the
/// accept loops for the life of the server. The fixture therefore starts it
/// without awaiting, and decides "up" by connecting.
/// </para>
/// <para>
/// The server binds <c>IPAddress.Any</c> — it has no option for loopback — so
/// the fixture's listeners are reachable from the LAN for the few seconds a
/// test runs. Nothing about that is configurable here; it is noted in
/// FINDINGS.md.
/// </para>
/// </remarks>
public sealed class HermodSmtpServerFixture : IAsyncDisposable
{

    public SMTPServer             Server            { get; }
    public SMTPServerConfig       Config            { get; }
    public CapturingMailStorage   Storage           { get; }
    public CapturingMailQueue     Queue             { get; }
    public InMemoryUserStore      Users             { get; }
    public CapturingLogger        Log               { get; }
    public StubDnsClient          Dns               { get; }
    public X509Certificate2?      Certificate       { get; }

    // The ports the system chose: the configuration asks for port 0, the server says where it landed.
    public UInt16                 MtaPort           => (UInt16) Server.MtaEndPoints[0].Port;
    public UInt16                 SubmissionPort    => (UInt16) Server.SubmissionEndPoints[0].Port;
    public UInt16                 ImplicitTlsPort   => (UInt16) Server.ImplicitTlsEndPoints[0].Port;

    public String                 Host              => "127.0.0.1";

    private readonly Task         runTask;
    private readonly String       directory;


    private HermodSmtpServerFixture(SMTPServer            Server,
                                    SMTPServerConfig      Config,
                                    CapturingMailStorage  Storage,
                                    CapturingMailQueue    Queue,
                                    InMemoryUserStore     Users,
                                    CapturingLogger       Log,
                                    StubDnsClient         Dns,
                                    X509Certificate2?     Certificate,
                                    Task                  RunTask,
                                    String                Directory)
    {
        this.Server       = Server;
        this.Config       = Config;
        this.Storage      = Storage;
        this.Queue        = Queue;
        this.Users        = Users;
        this.Log          = Log;
        this.Dns          = Dns;
        this.Certificate  = Certificate;
        this.runTask      = RunTask;
        this.directory    = Directory;
    }


    public static async Task<HermodSmtpServerFixture> StartAsync(HermodSmtpServerFixtureOptions? Options = null)
    {

        Options ??= new HermodSmtpServerFixtureOptions();

        var directory = Directory.CreateTempSubdirectory("smtp-conformance-").FullName;

        String?            certificatePath  = null;
        X509Certificate2?  certificate      = null;

        if (Options.EnableTls)
            (certificatePath, certificate) = TestCertificate.WritePfx(directory, Options.Hostname);

        // Port 0 everywhere: the system picks free ports while binding, so no other process can
        // take one between choosing and binding, and the server reports where it landed.
        var config  = new SMTPServerConfig {
                          Hostname                 = Options.Hostname,
                          ListenAddresses          = Options.ListenAddresses,
                          Port                     = 0,
                          SubmissionPort           = 0,
                          ImplicitTlsPort          = 0,
                          EnableImplicitTls        = Options.EnableTls,
                          MailStoragePath          = directory,
                          CertificatePath          = certificatePath,
                          CertificatePassword      = certificatePath is not null ? TestCertificate.PfxPassword : null,
                          SessionTimeout           = Options.SessionTimeout,
                          MaxMessageSize           = Options.MaxMessageSize,
                          MaxRecipients            = Options.MaxRecipients,
                          MaxCommandLineLength     = Options.MaxCommandLineLength,
                          MaxTextLineLength        = Options.MaxTextLineLength,
                          RequireStartTls          = Options.RequireStartTls,
                          LocalDomains             = [.. Options.LocalDomains],
                          RequireAuthForRelay      = Options.RequireAuthForRelay,
                          RequireAuthOnSubmission  = Options.RequireAuthOnSubmission
                      };

        var storage = new CapturingMailStorage();
        var queue   = new CapturingMailQueue();
        var users   = new InMemoryUserStore(Options.Users);
        var log     = new CapturingLogger();

        var server  = new SMTPServer(config,
                                     Options.Dns,
                                     log,
                                     users,
                                     queue,
                                     Options.RateLimits,
                                     storage);

        // Start() binds its listeners before its first await: a bind that failed shows up as an
        // already-faulted task, and the end points are known once it has returned.
        var runTask = server.Start();

        if (runTask.IsFaulted || server.MtaEndPoints.Count == 0)
        {
            try { await server.DisposeAsync(); } catch { }
            TryDelete(directory);
            throw new InvalidOperationException($"Hermod's SMTP server did not come up.\n{runTask.Exception?.ToString() ?? log.ToString()}");
        }

        return new HermodSmtpServerFixture(server, config, storage, queue, users, log, Options.Dns, certificate, runTask, directory);

    }


    /// <summary>
    /// Connect to the MTA port (25 in production) and read the greeting.
    /// </summary>
    public Task<(RawSmtpClient Client, SmtpReply Greeting)> ConnectMtaAsync()
        => RawSmtpClient.ConnectAndGreetAsync(Host, MtaPort);

    /// <summary>
    /// Connect to the submission port (587 in production) and read the greeting.
    /// </summary>
    public Task<(RawSmtpClient Client, SmtpReply Greeting)> ConnectSubmissionAsync()
        => RawSmtpClient.ConnectAndGreetAsync(Host, SubmissionPort);

    /// <summary>
    /// Connect to the implicit-TLS port (465 in production), handshake, and read the greeting.
    /// </summary>
    public Task<(RawSmtpClient Client, SmtpReply Greeting)> ConnectImplicitTlsAsync()
        => RawSmtpClient.ConnectAndGreetAsync(Host, ImplicitTlsPort, ImplicitTls: true);


    /// <summary>
    /// Connect to the MTA port, EHLO, and return the client ready for MAIL.
    /// </summary>
    public async Task<RawSmtpClient> ConnectAndEhloAsync(String Domain = "client.example")
    {
        var (client, _) = await ConnectMtaAsync();
        await client.EhloAsync(Domain);
        return client;
    }


    private static void TryDelete(String directory)
    {
        try
        {
            Directory.Delete(directory, recursive: true);
        }
        catch
        {
            // a file still open; the temp directory will be cleaned eventually
        }
    }


    public async ValueTask DisposeAsync()
    {

        try
        {
            await Server.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        }
        catch
        {
            // A session that hangs on shutdown is not what the test was about.
        }

        try
        {
            await runTask.WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch
        {
            // Accept loops end in OperationCanceledException or ObjectDisposedException.
        }

        TryDelete(directory);

    }

}
