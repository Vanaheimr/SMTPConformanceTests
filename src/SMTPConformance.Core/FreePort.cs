using System.Net;
using System.Net.Sockets;

namespace SMTPConformance.Core;

/// <summary>
/// Ephemeral-port allocation for fixtures.
/// </summary>
/// <remarks>
/// Hermod's <c>SMTPServer</c> takes its three ports from <c>SMTPServerConfig</c>
/// and exposes no "actually bound port" afterwards, so it cannot be handed port 0
/// and asked where it landed. A fixture therefore picks the ports first and
/// passes them in — a time-of-check-to-time-of-use race, which the fixture
/// answers by retrying the whole start with fresh ports.
///
/// The probe binds <see cref="IPAddress.Any"/> because that is what the server
/// binds: a port free on loopback can still be taken on the wildcard address.
/// </remarks>
public static class FreePort
{

    /// <summary>
    /// A TCP port that was free on the wildcard address a moment ago.
    /// </summary>
    public static UInt16 Tcp()
    {

        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

        socket.Bind(new IPEndPoint(IPAddress.Any, 0));

        return (UInt16) ((IPEndPoint) socket.LocalEndPoint!).Port;

    }

    /// <summary>
    /// <paramref name="Count"/> distinct TCP ports that were free a moment ago.
    /// </summary>
    public static UInt16[] Tcp(Int32 Count)
    {

        var ports = new HashSet<UInt16>();

        while (ports.Count < Count)
            ports.Add(Tcp());

        return [.. ports];

    }

}
