using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace SMTPConformance.Core.Fixtures;

/// <summary>
/// An <see cref="IDNSClient"/> that answers from a canned table instead of a socket.
/// </summary>
/// <remarks>
/// <para>
/// Hermod's SMTP server resolves on every accepted message: SPF, DKIM, DMARC,
/// ARC and MX for the envelope sender, PTR for the <c>Received:</c> trace. A
/// conformance run that let those out would depend on whoever answers for
/// <c>example.com</c> today, and would be slow when nobody does.
/// </para>
/// <para>
/// Whatever a test does not register is answered as an empty NOERROR — no SPF
/// record, no DMARC policy, no PTR — which is the hermetic baseline: the
/// verifier finds nothing to enforce and the message is accepted.
/// </para>
/// </remarks>
public sealed class StubDnsClient : IDNSClient
{

    private readonly Dictionary<(String Name, DNSResourceRecordTypes Type), List<IDNSResourceRecord>> table = [];
    private readonly Lock tableLock = new();

    private static readonly DNSServerConfig origin = new(IPv4Address.Localhost, IPPort.DNS);

    /// <summary>
    /// Every query this client received, in order.
    /// </summary>
    public List<(String Name, DNSResourceRecordTypes Type)> Queries { get; } = [];


    /// <summary>
    /// Register the answer for one owner name and type. Returns this, for chaining.
    /// </summary>
    public StubDnsClient Answer(String                       Name,
                                DNSResourceRecordTypes       Type,
                                params IDNSResourceRecord[]  Records)
    {
        lock (tableLock)
            table[(Key(Name), Type)] = [.. Records];
        return this;
    }

    private static String Key(String name)
        => name.TrimEnd('.').ToLowerInvariant();

    private DNSInfo Build(String                               Name,
                          IEnumerable<DNSResourceRecordTypes>  Types)
    {

        var answers = new List<IDNSResourceRecord>();

        lock (tableLock)
        {
            foreach (var type in Types)
            {

                Queries.Add((Key(Name), type));

                if (table.TryGetValue((Key(Name), type), out var records))
                    answers.AddRange(records);

            }
        }

        return new DNSInfo(
                   origin,
                   0,
                   true,                       // authoritative
                   false,                      // not truncated
                   true,                       // recursion desired
                   false,                      // recursion available
                   DNSResponseCodes.NoError,
                   answers,
                   [],
                   [],
                   true,                       // IsValid
                   false,                      // IsTimeout
                   TimeSpan.FromSeconds(5),
                   TimeSpan.Zero
               );

    }

    public Task<DNSInfo> Query(DomainName                           DomainName,
                               IEnumerable<DNSResourceRecordTypes>  ResourceRecordTypes,
                               TimeSpan?                            Timeout            = null,
                               Boolean?                             RecursionDesired   = true,
                               Boolean?                             ForceUpdate        = false,
                               CancellationToken                    CancellationToken  = default)

        => Task.FromResult(Build(DomainName.FullName, ResourceRecordTypes));

    public Task<DNSInfo> Query(DNSServiceName                       DNSServiceName,
                               IEnumerable<DNSResourceRecordTypes>  ResourceRecordTypes,
                               TimeSpan?                            Timeout            = null,
                               Boolean?                             RecursionDesired   = true,
                               Boolean?                             ForceUpdate        = false,
                               CancellationToken                    CancellationToken  = default)

        => Task.FromResult(Build(DNSServiceName.FullName, ResourceRecordTypes));

    public void Dispose()
    { }

    public ValueTask DisposeAsync()
        => ValueTask.CompletedTask;

    public override String ToString()
        => $"stub DNS client ({table.Count} canned RRsets)";

}
