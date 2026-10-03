using NUnit.Framework;

using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Core.Fixtures;

/// <summary>
/// One Hermod SMTP server per test fixture; every test opens its own connections.
/// </summary>
public abstract class HermodServerTestBase
{

    protected HermodSmtpServerFixture Server { get; private set; } = null!;

    /// <summary>
    /// The server configuration this fixture runs against.
    /// </summary>
    protected virtual HermodSmtpServerFixtureOptions Options
        => new();


    [OneTimeSetUp]
    public async Task StartServer()
        => Server = await HermodSmtpServerFixture.StartAsync(Options);

    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (Server is not null)
            await Server.DisposeAsync();
    }


    /// <summary>
    /// What to print when an assertion fails: the wire transcript, then the server's log.
    /// </summary>
    protected String Explain(RawSmtpClient Client)
        => $"\n--- wire ---\n{Client.Transcript}\n--- server log ---\n{Server.Log}";

    /// <summary>
    /// A marker unique to the calling test, for finding its message in shared storage.
    /// </summary>
    protected static String Marker()
        => $"marker-{Guid.NewGuid():N}";

}
