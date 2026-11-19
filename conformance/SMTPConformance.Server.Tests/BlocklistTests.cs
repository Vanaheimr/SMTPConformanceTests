using IPAddress = System.Net.IPAddress;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 5782: DNS blocklists asked about the client - the name of the question, what an
/// answer means, and RFC 5321 §4.5.1's postmaster, who stays reachable for a listed client.
/// </summary>
/// <remarks>
/// The tests' client is 127.0.0.1, which RFC 5782 §5 says no list may name ("IPv4-based
/// DNSxLs MUST NOT contain an entry for 127.0.0.1"); the stub list names it anyway, and the
/// server is told to ask about private addresses, so that a list can be heard at all.
/// </remarks>
[TestFixture]
public sealed class BlocklistTests : HermodServerTestBase
{

    private const String Zone = "bl.test";

    // A container without IPv6 - as the CI's Debian one may be - listens on IPv4 alone.
    private static readonly Boolean ipv6 = IPv6LoopbackUsable();

    private static Boolean IPv6LoopbackUsable()
    {
        try
        {
            using var socket = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetworkV6, System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp);
            socket.Bind(new System.Net.IPEndPoint(IPAddress.IPv6Loopback, 0));
            return true;
        }
        catch (System.Net.Sockets.SocketException)
        {
            return false;
        }
    }

    protected override HermodSmtpServerFixtureOptions Options
        => new() {
               ListenAddresses  = ipv6 ? [ IPAddress.Any, IPAddress.IPv6Any ] : [ IPAddress.Any ],
               DnsBlocklists    = new DnsBlocklistConfig {
                                      Zones                  = [ Zone ],
                                      Action                 = DnsBlocklistAction.Reject,
                                      CheckPrivateAddresses  = true
                                  },
               Dns              = new StubDnsClient().
                                      Answer("1.0.0.127." + Zone, DNSResourceRecordTypes.A,
                                             new A(DomainName.Parse("1.0.0.127." + Zone), DNSQueryClasses.IN, TimeSpan.FromMinutes(5), IPv4Address.Parse("127.0.0.2")))
           };

    /// <summary>
    /// Connect to the MTA port over the IPv6 loopback, EHLO.
    /// </summary>
    private async Task<RawSmtpClient> ConnectOverIPv6Async()
    {

        var endPoint = Server.Server.MtaEndPoints.First(endPoint => endPoint.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);

        var (client, _) = await RawSmtpClient.ConnectAndGreetAsync("::1", (UInt16) endPoint.Port);
        await client.EhloAsync("client.example");

        return client;

    }

    private IReadOnlyList<String> AskedAbout
        => [ .. Server.Dns.Queries.ToArray().
                           Where (query => query.Type == DNSResourceRecordTypes.A && query.Name.EndsWith("." + Zone)).
                           Select(query => query.Name) ];


    [Test(Description = "RFC 5782 §2.1: the question is the client's IPv4 address with its octets reversed, followed by the list's domain")]
    public async Task An_IPv4_client_is_asked_about_by_its_reversed_octets()
    {

        await using var client = await Server.ConnectAndEhloAsync();
        await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");

        Assert.That(AskedAbout, Does.Contain("1.0.0.127." + Zone), Explain(client));

    }


    [Test(Description = "RFC 5782 §2.1: a client the list names (an A record, conventionally 127.0.0.2) is refused - permanently, at RCPT, and saying why (RFC 3463 §3.8, 5.7.1)")]
    public async Task A_listed_client_is_refused_its_recipients()
    {

        await using var client = await Server.ConnectAndEhloAsync();
        var (_, rcpts) = await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");

        Assert.Multiple(() => {
            Assert.That(rcpts[0].Class,         Is.EqualTo(5),                      Explain(client));
            Assert.That(rcpts[0].EnhancedCode,  Is.EqualTo("5.7.1"),                Explain(client));
            Assert.That(rcpts[0].Text,          Does.Contain(Zone),                 "the reply names the list");
        });

    }


    [Test(Description = "RFC 5321 §4.5.1: \"SMTP systems are expected to make every reasonable effort to accept mail directed to Postmaster from any other system\" - also from one a blocklist names")]
    public async Task A_listed_client_still_reaches_the_postmaster()
    {

        await using var client = await Server.ConnectAndEhloAsync();

        var marker = Marker();
        var (_, rcpts) = await client.EnvelopeAsync("sender@client.example", "postmaster@hermod.test", "Postmaster");
        var (_, final) = await client.DataAsync(RawSmtpClientExtensions.Message("sender@client.example", "postmaster@hermod.test", marker, "Why am I listed?"));

        Assert.Multiple(async () => {
            Assert.That(rcpts.Select(rcpt => rcpt.Code),                   Is.EqualTo(new[] { 250, 250 }),  Explain(client));
            Assert.That(final?.Code,                                         Is.EqualTo(250),                 Explain(client));
            Assert.That(await Server.Storage.WaitForMarkerAsync(marker),     Is.Not.Null,                     "stored");
        });

    }


    [Test(Description = "RFC 5782 §2.4: an IPv6 client is asked about by \"a 32-component hex nibble-reversed IPv6 address suffixed by the DNSxL domain\"; one the list does not name is served")]
    public async Task An_IPv6_client_is_asked_about_by_its_reversed_nibbles()
    {

        Assume.That(ipv6, "no IPv6 loopback on this host");

        await using var client = await ConnectOverIPv6Async();
        var (_, rcpts) = await client.EnvelopeAsync("sender@client.example", "alice@hermod.test");

        Assert.Multiple(() => {
            Assert.That(AskedAbout,       Does.Contain(String.Concat(Enumerable.Repeat("0.", 31)).Insert(0, "1.") + Zone), Explain(client));
            Assert.That(rcpts[0].Code,    Is.EqualTo(250),                                                                 Explain(client));
        });

    }

}
