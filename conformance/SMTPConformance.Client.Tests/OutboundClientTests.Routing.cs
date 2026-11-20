using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;

namespace SMTPConformance.Client.Tests;

public sealed partial class OutboundClientTests
{

    #region The way to the next hop (RFC 5321 §5.1)

    // The client connects to its MX hosts on port 25, which no test can listen on; what it
    // does is seen in its DNS queries instead. It asks for the addresses of a host when it is
    // about to connect to it, and only then - so a host whose addresses it asked for is one it
    // meant to deliver to. None of the hosts here has an address: each attempt fails at once.

    private const String OwnName = "relay.hermod.test";

    /// <summary>
    /// Deliver to you@ the domain through the given DNS, as relay.hermod.test.
    /// </summary>
    private static async Task<SendResult> Route(StubDnsClient Dns, String Domain = "route.test")

        => await SendWith(new SMTPOutboundClient(new SmtpOutboundConfig {
                                                     LocalHostname     = OwnName,
                                                     ConnectTimeoutMs  = 3_000,
                                                     ReadTimeoutMs     = 10_000,
                                                     WriteTimeoutMs    = 3_000
                                                 },
                                                 null, Dns, new CapturingLogger()),
                          Envelope([ $"you@{Domain}" ]));

    private static MX MxRecord(String Domain, UInt16 Preference, String Host)
        => new (DomainName.Parse(Domain), DNSQueryClasses.IN, TimeSpan.FromHours(1), Preference, DomainName.Parse(Host));

    /// <summary>
    /// Whether the client asked for the addresses of the host - whether it meant to connect to it.
    /// </summary>
    private static Boolean LookedUpAddressOf(StubDnsClient Dns, String Host)
        => Dns.Queries.Any(query => query.Name == Host && query.Type is DNSResourceRecordTypes.A or DNSResourceRecordTypes.AAAA);

    private static String Queries(StubDnsClient Dns)
        => "queries: " + String.Join(", ", Dns.Queries.Select(query => $"{query.Name}/{query.Type}"));


    #region O-9: a temporary error of the MX lookup

    public static IEnumerable<TestCaseData> MxLookupErrors()
    {

        TestCaseData Case(String Name, Action<StubDnsClient> Error)
            => new TestCaseData(Error).SetName($"Queued, not sent to the domain's address: {Name}")
                                      .SetCategory(TestCategories.KnownIssue)
                                      .SetProperty("Finding", "O-9");

        yield return Case("the MX lookup fails with SERVFAIL",  dns => dns.Fail ("route.test", DNSResourceRecordTypes.MX));
        yield return Case("the MX lookup times out",            dns => dns.Throw("route.test", DNSResourceRecordTypes.MX));

    }


    [TestCaseSource(nameof(MxLookupErrors))]
    [Description("RFC 5321 §5.1: \"If a temporary error is returned, the message MUST be queued and retried later\"; the implicit MX - the domain's own address - is for \"an empty list of MXs\", and \"applies only if there are no MX records present\"")]
    public async Task A_temporary_error_of_the_MX_lookup_queues_the_message(Action<StubDnsClient> Error)
    {

        var dns = new StubDnsClient();
        Error(dns);

        var result = await Route(dns);

        Assert.Multiple(() => {
            Assert.That(result.Status,                         Is.EqualTo(SendStatus.TempFail),  $"{result.ResponseCode} {result.ResponseText}");
            Assert.That(LookedUpAddressOf(dns, "route.test"),  Is.False,                         "the domain's own address is no MX host: " + Queries(dns));
        });

    }


    [Test(Description = "RFC 5321 §5.1: \"If an empty list of MXs is returned, the address is treated as if it was associated with an implicit MX RR, with a preference of 0, pointing to that host\" - a guard for O-9")]
    [Property("Finding", "O-9")]
    public async Task A_domain_without_MX_records_is_its_own_MX()
    {

        var dns = new StubDnsClient();

        await Route(dns);

        Assert.That(LookedUpAddressOf(dns, "route.test"), Is.True, Queries(dns));

    }

    #endregion

    #region O-10: a domain, or MX hosts, that do not exist

    public static IEnumerable<TestCaseData> Nonexistent()
    {

        TestCaseData Case(String Name, Action<StubDnsClient> Zone)
            => new TestCaseData(Zone).SetName($"Reported, not retried: {Name}")
                                     .SetCategory(TestCategories.KnownIssue)
                                     .SetProperty("Finding", "O-10");

        yield return Case("the domain does not exist (NXDOMAIN)", dns => {
                              dns.Fail("route.test", DNSResourceRecordTypes.MX,   DNSResponseCodes.NameError);
                              dns.Fail("route.test", DNSResourceRecordTypes.A,    DNSResponseCodes.NameError);
                              dns.Fail("route.test", DNSResourceRecordTypes.AAAA, DNSResponseCodes.NameError);
                          });

        yield return Case("its only MX host does not exist", dns => {
                              dns.Answer("route.test", DNSResourceRecordTypes.MX, MxRecord("route.test", 10, "mx.nowhere.test"));
                              dns.Fail("mx.nowhere.test", DNSResourceRecordTypes.A,    DNSResponseCodes.NameError);
                              dns.Fail("mx.nowhere.test", DNSResourceRecordTypes.AAAA, DNSResponseCodes.NameError);
                          });

    }


    [TestCaseSource(nameof(Nonexistent))]
    [Description("RFC 5321 §5.1: \"If a non-existent domain error is returned, this situation MUST be reported as an error\"; \"If MX records are present, but none of them are usable, or the implicit MX is unusable, this situation MUST be reported as an error\" - a permanent failure, not a message queued for days")]
    public async Task A_domain_that_cannot_be_reached_is_a_permanent_failure(Action<StubDnsClient> Zone)
    {

        var dns = new StubDnsClient();
        Zone(dns);

        var result = await Route(dns);

        Assert.That(result.Status, Is.EqualTo(SendStatus.PermFail), $"{result.ResponseCode} {result.ResponseText}\n{Queries(dns)}");

    }

    #endregion

    #region O-11: MX hosts of the same preference

    [Test(Description = "RFC 5321 §5.1: \"If there are multiple destinations with the same preference and there is no clear reason to favor one ... then the sender-SMTP MUST randomize them to spread the load across multiple mail exchangers\" - of two MX hosts of preference 10, each is tried first in some of 16 deliveries (both always behind the other: a chance of 1 in 32768)")]
    [Category(TestCategories.KnownIssue), Property("Finding", "O-11")]
    public async Task MX_hosts_of_the_same_preference_are_tried_in_random_order()
    {

        var dns = new StubDnsClient();
        dns.Answer("route.test", DNSResourceRecordTypes.MX,
                   MxRecord("route.test", 10, "a.route.test"),
                   MxRecord("route.test", 10, "b.route.test"));

        var first = new List<String>();

        for (var i = 0; i < 16; i++)
        {

            dns.Queries.Clear();

            await Route(dns);

            first.Add(dns.Queries.FirstOrDefault(query => query.Name is "a.route.test" or "b.route.test").Name ?? "none");

        }

        Assert.That(first.Distinct().Order(), Is.EqualTo(new[] { "a.route.test", "b.route.test" }), "tried first: " + String.Join(", ", first));

    }

    #endregion

    #region O-12: the relay among the MX hosts

    public static IEnumerable<TestCaseData> OwnMx()
    {

        TestCaseData Case(String Name, String[] Tried, String[] NotTried, SendStatus Status, params (UInt16 Preference, String Host)[] Mx)
            => new TestCaseData(Mx, Tried, NotTried, Status).SetName($"The relay's own MX level: {Name}")
                                                            .SetCategory(TestCategories.KnownIssue)
                                                            .SetProperty("Finding", "O-12");

        yield return Case("the only MX",                      [],                  [ OwnName ],                         SendStatus.PermFail,  (10, OwnName));
        yield return Case("the best MX, a backup behind it",  [],                  [ OwnName, "backup.route.test" ],    SendStatus.PermFail,  (10, OwnName), (20, "backup.route.test"));
        // The better MX host has no address either: the one usable MX host there could be is not
        // - a permanent failure (O-10).
        yield return Case("a backup MX behind a better one",  [ "mx.route.test" ], [ OwnName ],                         SendStatus.PermFail,  (10, "mx.route.test"), (20, OwnName));

    }


    [TestCaseSource(nameof(OwnMx))]
    [Description("RFC 5321 §5.1: a relay \"MUST then inspect the list for any of the names or addresses by which it might be known in mail transactions. If a matching record is found, all records at that preference level and higher-numbered ones MUST be discarded from consideration. If there are no records left at that point, it is an error condition, and the message MUST be returned as undeliverable\" - relay.hermod.test does not send to itself, or to MX hosts behind itself")]
    public async Task The_relay_does_not_send_to_itself_or_behind_itself((UInt16 Preference, String Host)[] Mx, String[] Tried, String[] NotTried, SendStatus Status)
    {

        var dns = new StubDnsClient();
        dns.Answer("route.test", DNSResourceRecordTypes.MX, [ .. Mx.Select(mx => MxRecord("route.test", mx.Preference, mx.Host)) ]);

        var result = await Route(dns);

        Assert.Multiple(() => {

            Assert.That(result.Status, Is.EqualTo(Status), $"{result.ResponseCode} {result.ResponseText}");

            foreach (var host in Tried)
                Assert.That(LookedUpAddressOf(dns, host), Is.True,  $"{host} is tried: {Queries(dns)}");

            foreach (var host in NotTried)
                Assert.That(LookedUpAddressOf(dns, host), Is.False, $"{host} is not tried: {Queries(dns)}");

        });

    }

    #endregion

    #endregion

}
