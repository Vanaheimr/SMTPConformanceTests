using System.Net.Sockets;

using NUnit.Framework;

namespace SMTPConformance.Core;

/// <summary>
/// One-time capability probing (network / WSL / docker) with
/// Assert.Ignore-based gating so prerequisite-less environments skip
/// instead of fail.
/// </summary>
public static class TestEnvironment
{

    /// <summary>
    /// The Debian packages that provide every tool the interop lane drives.
    /// One list, so a skip message and the CI install step cannot drift apart.
    /// </summary>
    public const String LinuxPackages = "swaks libnet-ssleay-perl libio-socket-ssl-perl libauthen-sasl-perl openssl python3 postfix";

    #region Network

    private static readonly Lazy<Boolean> hasNetwork = new(() => {

        foreach (var (host, port) in new[] { ("1.1.1.1", 443), ("8.8.8.8", 443) })
        {
            try
            {

                using var tcp = new TcpClient();

                if (tcp.ConnectAsync(host, port).Wait(TimeSpan.FromSeconds(3)) && tcp.Connected)
                    return true;

            }
            catch
            {
                // try the next one
            }
        }

        return false;

    });

    /// <summary>
    /// True when an outbound TCP connection to the internet succeeds.
    /// </summary>
    /// <remarks>
    /// Deliberately not a probe of port 25: most residential and many cloud
    /// networks block outbound 25, and a test that needs it has to say so on its
    /// own rather than inherit a "no network" verdict that is only half true.
    /// </remarks>
    public static Boolean HasNetwork
        => hasNetwork.Value;

    public static void RequireNetwork()
    {
        if (!HasNetwork)
            Assert.Ignore("No outbound connectivity (probed 1.1.1.1 and 8.8.8.8 on TCP/443) — skipping Online test.");
    }

    #endregion

    #region WSL

    /// <summary>
    /// Require the GNU/Linux mail tools these interop tests drive.
    /// </summary>
    /// <param name="tools">The executables the calling test needs on the PATH.</param>
    /// <remarks>
    /// The category is still called <c>WSL</c> because that is where these tools
    /// live on a developer machine. On a Linux host — a CI runner, say — the
    /// same tests run against the tools directly, with no bridge and no
    /// firewall between them and the server under test.
    /// </remarks>
    public static void RequireWsl(params String[] tools)
    {

        if (!Wsl.IsAvailable)
            Assert.Ignore(Wsl.UsesWslBridge
                              ? $"WSL is not available — skipping. Install WSL, then: wsl -u root apt-get install -y {LinuxPackages}"
                              :  "No POSIX shell available — skipping.");

        foreach (var tool in tools)
            if (!Wsl.HasTool(tool))
                Assert.Ignore(Wsl.UsesWslBridge
                                  ? $"'{tool}' not found inside WSL — skipping. Install it, e.g.: wsl -u root apt-get install -y {LinuxPackages}"
                                  : $"'{tool}' not found on the PATH — skipping. Install it, e.g.: apt-get install -y {LinuxPackages}");

    }

    #endregion

    #region Docker

    private static readonly Lazy<Boolean> hasDocker = new(() => {
        try
        {

            var psi = new System.Diagnostics.ProcessStartInfo {
                          FileName                = "docker",
                          Arguments               = "info --format {{.ServerVersion}}",
                          RedirectStandardOutput  = true,
                          RedirectStandardError   = true,
                          UseShellExecute         = false,
                          CreateNoWindow          = true
                      };

            using var process = System.Diagnostics.Process.Start(psi);

            if (process is null)
                return false;

            if (!process.WaitForExit(5000))
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                return false;
            }

            return process.ExitCode == 0;

        }
        catch
        {
            return false;
        }
    });

    public static Boolean HasDockerDaemon
        => hasDocker.Value;

    public static void RequireDocker()
    {
        if (!HasDockerDaemon)
            Assert.Ignore("No reachable Docker daemon — skipping Docker-based interop test.");
    }

    #endregion

}
