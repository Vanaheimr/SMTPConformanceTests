using System.Diagnostics;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// Runs one call into Hermod in a process of its own - for input that may end the process
/// it runs in: a stack overflow cannot be caught, and in the test run's own process it would
/// end the run. The test assembly's entry point (the project sets GenerateProgramFile to
/// false); started without arguments it does nothing.
/// </summary>
public static class IsolatedProcess
{

    /// <summary>
    /// The stack the call runs on: 1.5 MiB, what CoreCLR gives a new thread on Linux - a
    /// server's worker threads have no more.
    /// </summary>
    public const Int32 StackSize = 1536 * 1024;


    public static Int32 Main(String[] Args)

        => Args switch {
               [ "dmarc-parse", var path ] => OnThread(() => {
                                                  var report = DmarcReportReader.Parse(File.ReadAllText(path));
                                                  Console.WriteLine(report is null ? "parsed: none" : $"parsed: {report.Domain.Length}");
                                              }),
               _                           => 0
           };

    private static Int32 OnThread(Action Call)
    {
        var thread = new Thread(() => Call(), StackSize);
        thread.Start();
        thread.Join();
        return 0;
    }


    /// <summary>
    /// Run this assembly with these arguments; its exit code and what it wrote, or -1 when it
    /// had not ended after <paramref name="Timeout"/> (it is killed then).
    /// </summary>
    public static async Task<(Int32 ExitCode, String Output)> RunAsync(TimeSpan Timeout, params String[] Args)
    {

        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") is { Length: > 0 } host ? host : "dotnet") {
                        RedirectStandardOutput = true,
                        RedirectStandardError  = true,
                        UseShellExecute        = false
                    };

        start.ArgumentList.Add(typeof(IsolatedProcess).Assembly.Location);
        foreach (var arg in Args)
            start.ArgumentList.Add(arg);

        using var process = Process.Start(start) ?? throw new InvalidOperationException("dotnet did not start");

        var output = process.StandardOutput.ReadToEndAsync();
        var error  = process.StandardError. ReadToEndAsync();

        try
        {
            await process.WaitForExitAsync().WaitAsync(Timeout);
        }
        catch (TimeoutException)
        {
            process.Kill(entireProcessTree: true);
            return (-1, "timed out");
        }

        var errors = await error;

        // A stack overflow prints the frame that repeats, thousands of times: the start is enough.
        return (process.ExitCode, (await output) + (errors.Length > 2000 ? errors[..2000] + " ..." : errors));

    }

}
