using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 7208 §4 to §6: how check_host() comes to its result - which record it takes, what a
/// DNS error makes of it, the syntax of the whole record, the modifiers, the "ptr" and "mx"
/// mechanisms and their limits. Evaluated by <see cref="DNSVerifier.CheckSpfAsync"/>, the
/// same evaluation the server applies to the MAIL FROM and HELO identities, against the
/// test's DNS. The client is 192.0.2.25.
/// </summary>
[TestFixture]
public sealed class SpfEvaluationTests
{

    #region Setup

    private const String ClientAddress = "192.0.2.25";

    private static TXT Txt(String Name, String Text)
        => new (DNSServiceName.Parse(Name), DNSQueryClasses.IN, TimeSpan.FromHours(1), Text);

    private static A Address(String Name, String Address)
        => new (DomainName.Parse(Name), DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse(Address));

    private static MX Mx(String Name, UInt16 Preference, String Host)
        => new (DomainName.Parse(Name), DNSQueryClasses.IN, TimeSpan.FromHours(1), Preference, DomainName.Parse(Host));

    /// <summary>
    /// A DNS that publishes the given SPF records - one TXT record each - at the given names.
    /// </summary>
    private static StubDnsClient Publish(params (String Name, String Spf)[] Records)
    {

        var dns = new StubDnsClient();

        foreach (var group in Records.GroupBy(record => record.Name))
            dns.Answer(group.Key, DNSResourceRecordTypes.TXT, [ .. group.Select(record => Txt(group.Key, record.Spf)) ]);

        return dns;

    }

    /// <summary>
    /// check_host() for the domain and the client address, and the DNS queries it made.
    /// </summary>
    private static async Task<(SPFResult Result, String Queries)> CheckHost(StubDnsClient  Dns,
                                                                           String         Domain,
                                                                           String         Client   = ClientAddress)
    {

        var (result, _) = await new DNSVerifier(Dns, new CapturingLogger()).CheckSpfAsync(Domain, System.Net.IPAddress.Parse(Client));

        return (result, "queries: " + String.Join(", ", Dns.Queries.Select(query => $"{query.Name}/{query.Type}")));

    }

    #endregion


    #region V-5: DNS errors

    public static IEnumerable<TestCaseData> DnsErrors()
    {

        TestCaseData Case(String Name, String Record, Action<StubDnsClient> Error)
            => new TestCaseData(Record, Error).SetName($"temperror: {Name}")
                                              .SetProperty("Finding", "V-5");

        yield return Case("the SPF record lookup fails with SERVFAIL",  "",                                          dns => dns.Fail ("dnserror.test", DNSResourceRecordTypes.TXT));
        yield return Case("the SPF record lookup times out",            "",                                          dns => dns.Throw("dnserror.test", DNSResourceRecordTypes.TXT));
        yield return Case("an a: lookup fails with SERVFAIL",           "v=spf1 a:mail.dnserror.test -all",          dns => dns.Fail ("mail.dnserror.test", DNSResourceRecordTypes.A));
        yield return Case("the mx lookup fails with SERVFAIL",          "v=spf1 mx -all",                            dns => dns.Fail ("dnserror.test", DNSResourceRecordTypes.MX));
        yield return Case("the include: record lookup fails",           "v=spf1 include:other.dnserror.test -all",   dns => dns.Fail ("other.dnserror.test", DNSResourceRecordTypes.TXT));
        yield return Case("an exists: lookup times out",                "v=spf1 exists:x.dnserror.test -all",        dns => dns.Throw("x.dnserror.test", DNSResourceRecordTypes.A));

    }


    [TestCaseSource(nameof(DnsErrors))]
    [Description("RFC 7208 §4.4: \"If the DNS lookup returns a server failure (RCODE 2) or some other error (RCODE other than 0 or 3), or if the lookup times out, then check_host() terminates immediately with the result \"temperror\"\"; §5: for the lookups of a mechanism, \"the mechanism stops and the topmost check_host() returns \"temperror\"\"")]
    public async Task A_DNS_error_is_a_temporary_error(String Record, Action<StubDnsClient> Error)
    {

        var dns = Record.Length > 0 ? Publish(("dnserror.test", Record)) : new StubDnsClient();
        Error(dns);

        var (result, queries) = await CheckHost(dns, "dnserror.test");

        Assert.That(result, Is.EqualTo(SPFResult.TempError), queries);

    }


    [Test(Description = "RFC 7208 §5: \"If the server returns \"Name Error\" (RCODE 3), then evaluation of the mechanism continues as if the server returned no error (RCODE 0) and zero answer records\" - a guard for V-5")]
    [Property("Finding", "V-5")]
    public async Task A_name_that_does_not_exist_is_no_error()
    {

        var dns = Publish(("nxdomain.test", $"v=spf1 a:gone.nxdomain.test ip4:{ClientAddress} -all"));
        dns.Fail("gone.nxdomain.test", DNSResourceRecordTypes.A,    DNSResponseCodes.NameError);
        dns.Fail("gone.nxdomain.test", DNSResourceRecordTypes.AAAA, DNSResponseCodes.NameError);

        var (result, queries) = await CheckHost(dns, "nxdomain.test");

        Assert.That(result, Is.EqualTo(SPFResult.Pass), queries);

    }

    #endregion

    #region V-6: which record

    public static IEnumerable<TestCaseData> RecordSets()
    {

        TestCaseData Case(String Name, SPFResult Expected, params String[] Records)
            => new TestCaseData(Records, Expected).SetName($"Record set: {Name}")
                                                  .SetProperty("Finding", "V-6");

        yield return Case("two SPF records",                         SPFResult.PermError,  $"v=spf1 ip4:{ClientAddress} -all", "v=spf1 -all");
        yield return Case("only v=spf10, which is no SPF record",    SPFResult.None,       $"v=spf10 ip4:{ClientAddress} -all");
        yield return Case("v=spf10 before the SPF record",           SPFResult.Pass,       "v=spf10 -all", $"v=spf1 ip4:{ClientAddress} -all");
        yield return Case("an SPF record among other TXT records",   SPFResult.Pass,       "site-verification=4711", $"v=spf1 ip4:{ClientAddress} -all");

    }


    [TestCaseSource(nameof(RecordSets))]
    [Description("RFC 7208 §4.5: \"discard records that do not begin with a version section of exactly \"v=spf1\". Note that the version section is terminated by either an SP character or the end of the record. As an example, a record with a version section of \"v=spf10\" does not match and is discarded\"; \"If the resultant record set includes more than one record, check_host() produces the \"permerror\" result\"")]
    public async Task Only_one_record_of_exactly_v_spf1_is_evaluated(String[] Records, SPFResult Expected)
    {

        var (result, queries) = await CheckHost(Publish([ .. Records.Select(record => ("records.test", record)) ]), "records.test");

        Assert.That(result, Is.EqualTo(Expected), queries);

    }

    #endregion

    #region V-7: the syntax of the whole record

    [TestCase("v=spf1 +all frobnicate:example.test",                 Description = "an unknown mechanism after the one that matches")]
    [TestCase("v=spf1 ip4:192.0.2.25 ip4:192.0.2.1/33",              Description = "an IPv4 prefix longer than 32 after the one that matches")]
    [TestCase("v=spf1 ip4:192.0.2 ip4:192.0.2.25 -all",              Description = "an IPv4 address of three octets before the one that matches")]
    [Test(Description = "RFC 7208 §4.6: \"The syntax of the record is validated first, and if there are any syntax errors anywhere in the record, check_host() returns immediately with the result \"permerror\", without further interpretation or evaluation\" - not only up to the term that matches")]
    [Property("Finding", "V-7")]
    public async Task A_syntax_error_anywhere_is_a_permanent_error(String Record)
    {

        var (result, queries) = await CheckHost(Publish(("syntax.test", Record)), "syntax.test");

        Assert.That(result, Is.EqualTo(SPFResult.PermError), queries);

    }


    [Test(Description = "RFC 7208 §6: \"Unrecognized modifiers MUST be ignored no matter where, or how often, they appear in a record\" - a guard for V-7")]
    [Property("Finding", "V-7")]
    public async Task An_unknown_modifier_is_no_syntax_error()
    {

        var (result, queries) = await CheckHost(Publish(("syntax.test", $"v=spf1 foo=bar ip4:{ClientAddress} foo=baz -all")), "syntax.test");

        Assert.That(result, Is.EqualTo(SPFResult.Pass), queries);

    }

    #endregion

    #region V-8: redirect= and exp= once each

    [TestCase("v=spf1 redirect=a.modifiers.test redirect=b.modifiers.test",  Description = "redirect= twice")]
    [TestCase("v=spf1 ip4:192.0.2.25 exp=a.modifiers.test exp=b.modifiers.test -all", Description = "exp= twice")]
    [Test(Description = "RFC 7208 §6: \"These two modifiers MUST NOT appear in a record more than once each. If they do, then check_host() exits with a result of \"permerror\"\"")]
    [Property("Finding", "V-8")]
    public async Task A_modifier_given_twice_is_a_permanent_error(String Record)
    {

        var dns = Publish(("modifiers.test",   Record),
                          ("a.modifiers.test", $"v=spf1 ip4:{ClientAddress} -all"),
                          ("b.modifiers.test", "v=spf1 -all"));

        var (result, queries) = await CheckHost(dns, "modifiers.test");

        Assert.That(result, Is.EqualTo(SPFResult.PermError), queries);

    }

    #endregion

    #region V-9: ptr

    /// <summary>
    /// The client's reverse name, mail.ptr.test, and that name's address - the client's, when
    /// the name is to be validated.
    /// </summary>
    private static StubDnsClient Reverse(StubDnsClient Dns, String AddressOfName = ClientAddress)
    {

        Dns.Answer("25.2.0.192.in-addr.arpa", DNSResourceRecordTypes.PTR,
                   new PTR(DNSServiceName.Parse("25.2.0.192.in-addr.arpa"), DNSQueryClasses.IN, TimeSpan.FromHours(1), DNSServiceName.Parse("mail.ptr.test")));
        Dns.Answer("mail.ptr.test", DNSResourceRecordTypes.A, Address("mail.ptr.test", AddressOfName));

        return Dns;

    }


    [TestCase("ptr.test",   "v=spf1 ptr -all",           Description = "ptr: the validated name is within the domain")]
    [TestCase("other.test", "v=spf1 ptr:ptr.test -all",  Description = "ptr:domain")]
    [Test(Description = "RFC 7208 §5.5: \"It is, however, still in use as part of the SPF protocol, so compliant check_host() implementations MUST support it\" - the client's validated reverse name mail.ptr.test is within ptr.test, and the mechanism matches")]
    [Property("Finding", "V-9")]
    public async Task The_ptr_mechanism_matches_a_validated_name(String Domain, String Record)
    {

        var (result, queries) = await CheckHost(Reverse(Publish((Domain, Record))), Domain);

        Assert.That(result, Is.EqualTo(SPFResult.Pass), queries);

    }


    [Test(Description = "RFC 7208 §5.5: \"If <ip> is among the returned IP addresses, then that domain name is validated\" - a reverse name whose addresses are not the client's is not, and ptr does not match: a guard for V-9")]
    [Property("Finding", "V-9")]
    public async Task The_ptr_mechanism_does_not_match_a_name_that_is_not_validated()
    {

        var (result, queries) = await CheckHost(Reverse(Publish(("ptr.test", "v=spf1 ptr -all")), AddressOfName: "192.0.2.99"), "ptr.test");

        Assert.That(result, Is.EqualTo(SPFResult.Fail), queries);

    }

    #endregion

    #region V-10: mx and its ten names

    private static StubDnsClient MxHosts(Int32 Count)
    {

        var dns = Publish(("many.test", "v=spf1 mx -all"));

        dns.Answer("many.test", DNSResourceRecordTypes.MX,
                   [ .. Enumerable.Range(1, Count).Select(i => Mx("many.test", (UInt16) i, $"mx{i:00}.many.test")) ]);

        dns.Answer("mx01.many.test", DNSResourceRecordTypes.A, Address("mx01.many.test", ClientAddress));

        return dns;

    }


    [Test(Description = "RFC 7208 §4.6.4: \"the evaluation of each \"MX\" record MUST NOT result in querying more than 10 address records ... If this limit is exceeded, the \"mx\" mechanism MUST produce a \"permerror\" result\" - eleven MX names, the client the address of the first")]
    [Property("Finding", "V-10")]
    public async Task An_mx_mechanism_with_more_than_ten_names_is_a_permanent_error()
    {

        var (result, queries) = await CheckHost(MxHosts(11), "many.test");

        Assert.That(result, Is.EqualTo(SPFResult.PermError), queries);

    }


    [Test(Description = "RFC 7208 §4.6.4: ten MX names are within the limit - a guard for V-10")]
    [Property("Finding", "V-10")]
    public async Task An_mx_mechanism_with_ten_names_is_evaluated()
    {

        var (result, queries) = await CheckHost(MxHosts(10), "many.test");

        Assert.That(result, Is.EqualTo(SPFResult.Pass), queries);

    }

    #endregion

    #region V-11: void lookups

    [Test(Description = "RFC 7208 §4.6.4: \"SPF implementations SHOULD limit \"void lookups\" to two ... Exceeding the limit produces a \"permerror\" result\" - three a: terms for names without an address")]
    [Property("Finding", "V-11")]
    public async Task A_third_void_lookup_is_a_permanent_error()
    {

        var (result, queries) = await CheckHost(Publish(("void.test", $"v=spf1 a:v1.void.test a:v2.void.test a:v3.void.test ip4:{ClientAddress} -all")), "void.test");

        Assert.That(result, Is.EqualTo(SPFResult.PermError), queries);

    }


    [Test(Description = "RFC 7208 §4.6.4: two void lookups are within the limit - a guard for V-11")]
    [Property("Finding", "V-11")]
    public async Task Two_void_lookups_are_within_the_limit()
    {

        var (result, queries) = await CheckHost(Publish(("void.test", $"v=spf1 a:v1.void.test a:v2.void.test ip4:{ClientAddress} -all")), "void.test");

        Assert.That(result, Is.EqualTo(SPFResult.Pass), queries);

    }

    #endregion

    #region V-12: IPv4-mapped IPv6 clients

    [TestCase("v=spf1 ip4:192.0.2.25 -all",   Description = "ip4")]
    [TestCase("v=spf1 a -all",                Description = "a, the domain's A record the client's address")]
    [Test(Description = "RFC 7208 §5: \"SPF implementations on IPv6 servers need to handle both \"AAAA\" and \"A\" records, for clients on IPv4-mapped IPv6 addresses [RFC4291]\" - ::ffff:192.0.2.25 is 192.0.2.25")]
    [Property("Finding", "V-12")]
    public async Task A_client_on_an_IPv4_mapped_address_is_matched_as_IPv4(String Record)
    {

        var dns = Publish(("mapped.test", Record));
        dns.Answer("mapped.test", DNSResourceRecordTypes.A, Address("mapped.test", ClientAddress));

        var (result, queries) = await CheckHost(dns, "mapped.test", Client: "::ffff:" + ClientAddress);

        Assert.That(result, Is.EqualTo(SPFResult.Pass), queries);

    }


    [Test(Description = "RFC 7208 §5.6: the same record for the client at 192.0.2.25 itself - a guard for V-12")]
    [Property("Finding", "V-12")]
    public async Task A_client_on_its_IPv4_address_is_matched()
    {

        var (result, queries) = await CheckHost(Publish(("mapped.test", $"v=spf1 ip4:{ClientAddress} -all")), "mapped.test");

        Assert.That(result, Is.EqualTo(SPFResult.Pass), queries);

    }

    #endregion

}
