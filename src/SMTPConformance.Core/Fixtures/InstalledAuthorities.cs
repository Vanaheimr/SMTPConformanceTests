using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SMTPConformance.Core.Fixtures;

/// <summary>
/// Takes the certificate authorities a test server sent along out of the
/// intermediate CA stores again, where Windows' TLS has put them.
/// </summary>
/// <remarks>
/// On Windows, <see cref="System.Net.Security.SslStreamCertificateContext"/>
/// checks whether the operating system can build the chain of a certificate it
/// is given issuers for. When it cannot - and a test PKI's root is trusted
/// nowhere - it adds them to "Intermediate Certification Authorities", of the
/// local machine if it may write there, else of the current user, and nothing
/// ever takes them out again. Every DANE-TA test left its "Conformance test
/// authority" there, under a name of its own: 302 of them between 2026-11-19
/// and 2026-11-24, and every load of that store costs every TLS handshake on
/// the machine about 0.14 ms of CPU per certificate in it.
/// </remarks>
public static class InstalledAuthorities
{

    /// <summary>
    /// Remove the given certificates from the intermediate CA stores of the
    /// local machine and of the current user, wherever they are found, by
    /// thumbprint. Does nothing on other operating systems than Windows.
    /// </summary>
    /// <remarks>
    /// The local machine's store first: a process that may write to it, as the
    /// elevated one on a CI runner does, is where .NET puts them, and the
    /// current user's store lists the machine's certificates as well but cannot
    /// take them out. A removal that is refused is skipped: what it leaves
    /// behind costs time, not correctness.
    /// </remarks>
    /// <param name="Authorities">The CA certificates. Nulls are skipped.</param>
    /// <returns>How many certificates were removed.</returns>
    public static Int32 Remove(IEnumerable<X509Certificate2?> Authorities)
    {

        if (!OperatingSystem.IsWindows())
            return 0;

        var thumbprints = Authorities.
                              OfType<X509Certificate2>().
                              Select(authority => authority.Thumbprint).
                              Distinct(StringComparer.OrdinalIgnoreCase).
                              ToArray();

        if (thumbprints.Length == 0)
            return 0;

        return RemoveFrom(StoreLocation.LocalMachine, thumbprints) +
               RemoveFrom(StoreLocation.CurrentUser,  thumbprints);

    }

    private static Int32 RemoveFrom(StoreLocation Location, String[] Thumbprints)
    {

        using var store = new X509Store(StoreName.CertificateAuthority, Location);

        try
        {
            store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
        }
        catch (CryptographicException)
        {
            // The machine's store, unelevated: nothing can have been added there either.
            return 0;
        }

        var removed = 0;

        foreach (var thumbprint in Thumbprints)
            foreach (var installed in store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false))
            {
                try
                {
                    store.Remove(installed);
                    removed++;
                }
                catch (CryptographicException)
                {
                    // "Access is denied": the machine's copy, seen through the user's store.
                }
                finally
                {
                    installed.Dispose();
                }
            }

        return removed;

    }

}
