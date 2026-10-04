using System.Net.Sockets;
using System.Text;

using NUnit.Framework;

using SMTPConformance.Core;

namespace SMTPInterop.LinuxTools.Tests;

/// <summary>
/// A private Postfix on the Linux side: its own configuration, queue and log under one
/// directory in /tmp, its own smtpd port, started with <c>postfix -c</c> and stopped and
/// removed again on dispose. Nothing of the system's Postfix configuration is touched.
/// </summary>
internal sealed class PostfixInstance : IDisposable
{

    /// <summary>The instance's directory: etc/ (main.cf, master.cf), spool/, lib/, maillog.</summary>
    public String  Directory  { get; }

    /// <summary>The address Hermod uses to reach this Postfix: the WSL VM, or this host.</summary>
    public String  Host       { get; }

    /// <summary>The smtpd port.</summary>
    public UInt16  Port       { get; }

    private PostfixInstance(String Directory, String Host, UInt16 Port)
    {
        this.Directory  = Directory;
        this.Host       = Host;
        this.Port       = Port;
    }


    /// <summary>
    /// Run a POSIX shell script on the Linux side, as root - written to a file first, so that no
    /// quoting has to survive wsl.exe and sh.
    /// </summary>
    public static Wsl.Result RunScript(String Script, TimeSpan? Timeout = null)
    {

        var path = Path.Combine(Path.GetTempPath(), $"postfix-interop-{Guid.NewGuid():N}.sh");
        File.WriteAllText(path, Script.Replace("\r\n", "\n"), new UTF8Encoding(false));

        try
        {
            return Wsl.Run($"sh '{Wsl.ToWslPath(path)}'", Timeout ?? TimeSpan.FromSeconds(60), asRoot: true);
        }
        finally
        {
            File.Delete(path);
        }

    }


    /// <param name="RelayHost">Where this Postfix sends everything: "[host]:port".</param>
    /// <param name="MainCf">More main.cf lines; a later setting wins over an earlier one.</param>
    /// <param name="WithCertificate">Give smtpd a self-signed certificate and offer STARTTLS.</param>
    public static async Task<PostfixInstance> StartAsync(String               RelayHost,
                                                         IEnumerable<String>? MainCf           = null,
                                                         Boolean              WithCertificate  = false)
    {

        TestEnvironment.RequireWsl("postfix", "sendmail", "openssl");

        var host = Wsl.VmAddress ?? throw new InconclusiveException("Could not determine the WSL address as seen from the host.");

        for (var attempt = 0; attempt < 5; attempt++)
        {

            var port = (UInt16) Random.Shared.Next(20000, 60000);
            var dir  = $"/tmp/postfix-interop-{Guid.NewGuid():N}";

            String[] mainCf = [
                "compatibility_level = 3.6",
               $"queue_directory = {dir}/spool",
               $"data_directory = {dir}/lib",
                "myhostname = postfix.interop.test",
                "mydomain = interop.test",
                "myorigin = $myhostname",
                "inet_interfaces = all",
                "inet_protocols = ipv4",
                "mydestination =",
                "mynetworks = 0.0.0.0/0",
                "smtpd_relay_restrictions = permit_mynetworks, reject",
               $"relayhost = {RelayHost}",
               $"maillog_file = {dir}/maillog",
                "maillog_file_prefixes = /tmp",
                "alias_maps =",
                "alias_database =",
                "local_recipient_maps =",
                // A strict receiver: what Postfix 3.9+ does by default about bare LFs, and the
                // usual HELO and envelope checks of a public MX.
                "smtpd_forbid_bare_newline = yes",
                "smtpd_helo_required = yes",
                "smtpd_helo_restrictions = reject_invalid_helo_hostname, reject_non_fqdn_helo_hostname",
                "strict_rfc821_envelopes = yes",
                "smtputf8_enable = yes",
                "smtp_tls_security_level = none",
                "smtpd_tls_security_level = none",
                // Deliver at once, retry quickly: a test waits seconds, not minutes.
                "queue_run_delay = 1s",
                "minimal_backoff_time = 1s",
                "maximal_backoff_time = 2s",
                .. WithCertificate
                       ? new[] {
                             "smtpd_tls_security_level = may",
                            $"smtpd_tls_cert_file = {dir}/etc/cert.pem",
                            $"smtpd_tls_key_file = {dir}/etc/key.pem",
                             "smtpd_tls_loglevel = 1"
                         }
                       : [],
                .. MainCf ?? []
            ];

            // master.cf: the system's, with smtpd on our port and nothing chrooted (the chroot
            // would be the private queue directory, without the files a chroot needs).
            var script = $$"""
                set -e
                D={{dir}}
                mkdir -p $D/etc $D/spool $D/lib
                cat > $D/etc/main.cf <<'MAINCF'
                {{String.Join("\n", mainCf)}}
                MAINCF
                awk -v port={{port}} '/^#/ || NF<8 || /^[ \t]/ {print; next} { if ($1=="smtp" && $2=="inet") $1=port; $5="n"; print }' /etc/postfix/master.cf > $D/etc/master.cf
                {{(WithCertificate ? "openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=postfix.interop.test -keyout $D/etc/key.pem -out $D/etc/cert.pem -days 2 2>/dev/null" : "")}}
                chown postfix:postfix $D/lib
                postfix -c $D/etc check >/dev/null 2>&1
                postfix -c $D/etc start >/dev/null 2>&1 || { cat $D/maillog; exit 1; }
                """;

            var started = RunScript(script, TimeSpan.FromSeconds(90));

            if (started.Success)
            {

                var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(15);

                while (DateTime.UtcNow < deadline)
                {
                    try
                    {
                        using var tcp = new TcpClient();
                        await tcp.ConnectAsync(host, port).WaitAsync(TimeSpan.FromSeconds(1));
                        return new PostfixInstance(dir, host, port);
                    }
                    catch
                    {
                        await Task.Delay(200);
                    }
                }

            }

            RunScript($"postfix -c {dir}/etc stop >/dev/null 2>&1; rm -rf {dir}");

            if (attempt == 4)
                Assert.Ignore($"A private Postfix did not come up on {host} - skipping.\n{started}");

        }

        throw new InvalidOperationException();

    }


    /// <summary>
    /// Hand a message to this Postfix with its sendmail(1), as a local program would.
    /// </summary>
    public Wsl.Result Inject(String From, IEnumerable<String> To, String Message, String Options = "")
    {

        var path = Path.Combine(Path.GetTempPath(), $"postfix-message-{Guid.NewGuid():N}.eml");
        File.WriteAllText(path, Message.Replace("\r\n", "\n"), new UTF8Encoding(false));

        try
        {
            return RunScript($"sendmail -C {Directory}/etc {Options} -f '{From}' {String.Join(" ", To.Select(to => $"'{to}'"))} < '{Wsl.ToWslPath(path)}'");
        }
        finally
        {
            File.Delete(path);
        }

    }


    /// <summary>Postfix's own log of this instance.</summary>
    public String Log
        => RunScript($"cat {Directory}/maillog 2>/dev/null").StdOut;


    /// <summary>
    /// Wait until the log contains the given text.
    /// </summary>
    public async Task<Boolean> LogContainsAsync(String Text, TimeSpan Within)
    {
        var deadline = DateTime.UtcNow + Within;
        while (DateTime.UtcNow < deadline)
        {
            if (Log.Contains(Text, StringComparison.Ordinal))
                return true;
            await Task.Delay(500);
        }
        return false;
    }


    public void Dispose()
        => RunScript($"postfix -c {Directory}/etc stop >/dev/null 2>&1; rm -rf {Directory}");

}
