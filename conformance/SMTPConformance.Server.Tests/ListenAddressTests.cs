using System.Net;
using System.Net.Sockets;

using NUnit.Framework;

using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// Where the server listens: RFC 5321 §5.1 and RFC 3974 expect an MX to answer on the addresses
/// its name has - IPv6 among them - and a server for this host only keeps to loopback. Every
/// fixture of this suite runs on port 0 and asks the server where it landed; these tests check
/// the addresses.
/// </summary>
[TestFixture]
public sealed class ListenAddressTests
{

    /// <summary>
    /// Whether ::1 can be bound here. Socket.OSSupportsIPv6 is not enough: a container may have
    /// the IPv6 stack and IPv6 switched off on its interfaces.
    /// </summary>
    private static Boolean IPv6LoopbackUsable()
    {
        try
        {
            using var socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
            socket.Bind(new IPEndPoint(IPAddress.IPv6Loopback, 0));
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }


    private static async Task AssertGreets(IPEndPoint EndPoint)
    {

        var host = EndPoint.Address.Equals(IPAddress.Any)     ? "127.0.0.1"
                 : EndPoint.Address.Equals(IPAddress.IPv6Any) ? "::1"
                 : EndPoint.Address.ToString();

        var (client, greeting) = await RawSmtpClient.ConnectAndGreetAsync(host, (UInt16) EndPoint.Port);
        await using var _ = client;

        Assert.That(greeting.Code, Is.EqualTo(220), $"{EndPoint}\n{client.Transcript}");

    }


    [Test(Description = "RFC 5321 §5.1: the server answers on IPv4 and IPv6 alike")]
    [Property("Finding", "S-18")]
    public async Task The_server_listens_on_IPv4_and_IPv6()
    {

        Assume.That(IPv6LoopbackUsable(), "no IPv6 loopback on this host");

        await using var server = await HermodSmtpServerFixture.StartAsync(new() { ListenAddresses = [ IPAddress.Loopback, IPAddress.IPv6Loopback ] });

        Assert.That(server.Server.MtaEndPoints.Select(endPoint => endPoint.AddressFamily),
                    Is.EquivalentTo(new[] { AddressFamily.InterNetwork, AddressFamily.InterNetworkV6 }));

        foreach (var endPoint in server.Server.MtaEndPoints.Concat(server.Server.SubmissionEndPoints))
            await AssertGreets(endPoint);

    }


    [Test(Description = "A server for this host only: loopback, and the ports the system chose")]
    [Property("Finding", "S-18")]
    public async Task A_loopback_server_reports_the_ports_it_was_given()
    {

        await using var server = await HermodSmtpServerFixture.StartAsync(new() { ListenAddresses = [ IPAddress.Loopback ] });

        var mta        = server.Server.MtaEndPoints.Single();
        var submission = server.Server.SubmissionEndPoints.Single();

        Assert.Multiple(() => {
            Assert.That(mta.Address,        Is.EqualTo(IPAddress.Loopback));
            Assert.That(mta.Port,           Is.Not.Zero);
            Assert.That(submission.Port,    Is.Not.Zero.And.Not.EqualTo(mta.Port));
            Assert.That(server.Server.ImplicitTlsEndPoints, Is.Empty, "no certificate, no implicit TLS");
        });

        await AssertGreets(mta);
        await AssertGreets(submission);

    }

}
