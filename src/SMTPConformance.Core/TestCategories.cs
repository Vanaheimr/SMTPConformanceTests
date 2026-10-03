namespace SMTPConformance.Core;

/// <summary>
/// NUnit category names used to gate tests on external prerequisites.
/// Default CI filter: TestCategory!=Online&amp;TestCategory!=WSL&amp;TestCategory!=Docker&amp;TestCategory!=KnownIssue.
/// </summary>
public static class TestCategories
{

    /// <summary>
    /// Needs outbound internet (public MX hosts, live DNS).
    /// </summary>
    public const String Online      = "Online";

    /// <summary>
    /// Needs WSL (or, on Linux, the host itself) with the GNU/Linux mail tools
    /// installed: swaks, openssl, postfix's smtp-sink/smtp-source, …
    /// </summary>
    public const String Wsl         = "WSL";

    /// <summary>
    /// Needs a reachable Docker daemon.
    /// </summary>
    public const String Docker      = "Docker";

    /// <summary>
    /// Longer-running tests (&gt; ~5 s).
    /// </summary>
    public const String Slow        = "Slow";

    /// <summary>
    /// Encodes an RFC requirement Hermod is currently known to violate — see FINDINGS.md.
    /// The test asserts what the RFC says, so it is red until the finding is fixed;
    /// the category is what keeps it out of the merge gate meanwhile.
    /// </summary>
    public const String KnownIssue  = "KnownIssue";

}
