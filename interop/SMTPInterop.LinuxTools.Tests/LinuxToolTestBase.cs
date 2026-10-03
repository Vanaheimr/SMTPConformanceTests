using System.Text;

using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;

namespace SMTPInterop.LinuxTools.Tests;

/// <summary>
/// A Hermod SMTP server reachable from the Linux side — WSL on a developer
/// machine, the host itself on a CI runner — and the plumbing to drive a tool
/// against it.
/// </summary>
/// <remarks>
/// Hermod's <c>SMTPServer</c> binds the wildcard address on its own, so no
/// widening is needed here. What can still stand in the way under WSL's NAT
/// networking is the Windows firewall, which by default drops inbound
/// connections from the WSL subnet to a freshly started test host. That is
/// probed once per fixture and reported as a skip, not as a protocol failure.
/// </remarks>
[Category(TestCategories.Wsl)]
public abstract class LinuxToolTestBase : HermodServerTestBase
{

    protected override HermodSmtpServerFixtureOptions Options
        => new() { EnableTls = true };

    /// <summary>
    /// The address the Linux side uses to reach the server.
    /// </summary>
    protected String LinuxSideHost { get; private set; } = "127.0.0.1";


    /// <summary>
    /// Skip unless the tools exist and the server is reachable from where they run.
    /// </summary>
    protected void Require(params String[] Tools)
    {

        TestEnvironment.RequireWsl([ "python3", .. Tools ]);

        LinuxSideHost = Wsl.WindowsHostAddress
                            ?? throw new InconclusiveException("Could not determine the host address as seen from WSL.");

        var probe = Wsl.Run($"python3 -c \"import socket; socket.create_connection(('{LinuxSideHost}', {Server.MtaPort}), 3).close()\"",
                            TimeSpan.FromSeconds(15));

        if (!probe.Success)
            Assert.Ignore($"The SMTP server on {LinuxSideHost}:{Server.MtaPort} is not reachable from the Linux side " +
                          "(under WSL NAT that is usually the Windows firewall) — skipping.\n" + probe);

    }


    /// <summary>
    /// Run a Python 3 script on the Linux side. The script is written to a file
    /// rather than passed with -c, so no quoting survives two shells.
    /// </summary>
    protected Wsl.Result RunPython(String Script, TimeSpan? Timeout = null)
    {

        var path = Path.Combine(Path.GetTempPath(), $"smtp-interop-{Guid.NewGuid():N}.py");

        File.WriteAllText(path, Script.Replace("\r\n", "\n"), new UTF8Encoding(false));

        try
        {
            return Wsl.Run($"python3 '{Wsl.ToWslPath(path)}'", Timeout ?? TimeSpan.FromSeconds(60));
        }
        finally
        {
            File.Delete(path);
        }

    }

}
