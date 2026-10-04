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
/// <para>
/// It speaks DNSSEC as far as a stub can: it carries the DO bit DANE switches on,
/// and returns RRSIGs where a test registered them with the records they sign. A
/// lookup can also be made to fail - an error code, or an exception as a timeout
/// or an unreachable server would raise.
/// </para>
/// </remarks>
public sealed class StubDnsClient : IDNSClientWithDNSSEC
{

    private readonly Dictionary<(String Name, DNSResourceRecordTypes Type), List<IDNSResourceRecord>> table = [];
    private readonly Dictionary<(String Name, DNSResourceRecordTypes Type), DNSResponseCodes>          failures = [];
    private readonly Dictionary<(String Name, DNSResourceRecordTypes Type), Exception>                 exceptions = [];
    private readonly Dictionary<(String Name, DNSResourceRecordTypes Type), List<IDNSResourceRecord>> proofs = [];
    private readonly Lock tableLock = new();

    private static readonly DNSServerConfig origin = new(IPv4Address.Localhost, IPPort.DNS);

    /// <summary>
    /// Every query this client received, in order.
    /// </summary>
    public List<(String Name, DNSResourceRecordTypes Type)> Queries { get; } = [];

    /// <summary>
    /// The DNSSEC OK bit (RFC 3225), which a DANE resolver sets.
    /// </summary>
    public Boolean DnssecOK { get; set; }


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

    /// <summary>
    /// Answer one owner name and type with an error code and no records. Returns this, for chaining.
    /// </summary>
    public StubDnsClient Fail(String                  Name,
                              DNSResourceRecordTypes  Type,
                              DNSResponseCodes        ResponseCode   = DNSResponseCodes.ServerFailure)
    {
        lock (tableLock)
            failures[(Key(Name), Type)] = ResponseCode;
        return this;
    }

    /// <summary>
    /// Put records in the authority section of the answer to one owner name and type - the NSEC
    /// records, and their signatures, that prove a name or type does not exist. Returns this, for
    /// chaining.
    /// </summary>
    public StubDnsClient Proof(String                       Name,
                               DNSResourceRecordTypes       Type,
                               params IDNSResourceRecord[]  Authorities)
    {
        lock (tableLock)
            proofs[(Key(Name), Type)] = [.. Authorities];
        return this;
    }

    /// <summary>
    /// Let the lookup of one owner name and type throw, as a timeout would. Returns this, for chaining.
    /// </summary>
    public StubDnsClient Throw(String                  Name,
                               DNSResourceRecordTypes  Type,
                               Exception?              Exception   = null)
    {
        lock (tableLock)
            exceptions[(Key(Name), Type)] = Exception ?? new TimeoutException($"DNS query for {Name} {Type} timed out");
        return this;
    }

    private static String Key(String name)
        => name.TrimEnd('.').ToLowerInvariant();

    private DNSInfo Build(String                               Name,
                          IEnumerable<DNSResourceRecordTypes>  Types)
    {

        var answers      = new List<IDNSResourceRecord>();
        var authorities  = new List<IDNSResourceRecord>();
        var responseCode = DNSResponseCodes.NoError;

        lock (tableLock)
        {
            foreach (var type in Types)
            {

                Queries.Add((Key(Name), type));

                if (exceptions.TryGetValue((Key(Name), type), out var exception))
                    throw exception;

                if (failures.TryGetValue((Key(Name), type), out var failure))
                    responseCode = failure;

                else if (table.TryGetValue((Key(Name), type), out var records))
                    answers.AddRange(records);

                if (proofs.TryGetValue((Key(Name), type), out var proof))
                    authorities.AddRange(proof);

            }
        }

        return new DNSInfo(
                   origin,
                   0,
                   true,                       // authoritative
                   false,                      // not truncated
                   true,                       // recursion desired
                   false,                      // recursion available
                   responseCode,
                   answers,
                   authorities,
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
