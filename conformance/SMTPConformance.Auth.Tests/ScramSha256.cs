using System.Security.Cryptography;
using System.Text;

namespace SMTPConformance.Auth.Tests;

/// <summary>
/// The client half of SCRAM-SHA-256 (RFC 5802, RFC 7677), written from the RFCs
/// alone so it can serve as the oracle for Hermod's server half. Pinned to the
/// RFC 7677 §3 example by <see cref="ScramOracleTests"/>.
/// </summary>
public sealed class ScramSha256
{

    private readonly String  username;
    private readonly String  password;
    private readonly String  clientNonce;

    private String?          clientFirstBare;
    private Byte[]?          saltedPassword;
    private String?          authMessage;

    public ScramSha256(String Username, String Password, String? ClientNonce = null)
    {
        username     = Username;
        password     = Password;
        clientNonce  = ClientNonce ?? Convert.ToBase64String(RandomNumberGenerator.GetBytes(18));
    }


    /// <summary>
    /// RFC 5802 §5.1: saslname escapes "=" and ",".
    /// </summary>
    private static String SaslName(String name)
        => name.Replace("=", "=3D").Replace(",", "=2C");


    /// <summary>
    /// client-first-message = gs2-header client-first-message-bare; no channel binding ("n,,").
    /// </summary>
    public String ClientFirst()
    {
        clientFirstBare = $"n={SaslName(username)},r={clientNonce}";
        return "n,," + clientFirstBare;
    }


    /// <summary>
    /// client-final-message for the given server-first-message.
    /// </summary>
    /// <exception cref="InvalidDataException">The server nonce does not extend the client nonce, or an attribute is missing.</exception>
    public String ClientFinal(String ServerFirst)
    {

        var attributes = ServerFirst.Split(',').
                                     Where (part => part.Length > 1 && part[1] == '=').
                                     ToDictionary(part => part[0], part => part[2..]);

        if (!attributes.TryGetValue('r', out var nonce) || !nonce.StartsWith(clientNonce, StringComparison.Ordinal))
            throw new InvalidDataException($"server nonce does not begin with the client nonce: {ServerFirst}");

        if (!attributes.TryGetValue('s', out var salt) || !attributes.TryGetValue('i', out var iterations))
            throw new InvalidDataException($"server-first-message lacks s= or i=: {ServerFirst}");

        saltedPassword = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password),
                                                   Convert.FromBase64String(salt),
                                                   Int32.Parse(iterations),
                                                   HashAlgorithmName.SHA256,
                                                   32);

        var withoutProof  = $"c={Convert.ToBase64String("n,,"u8.ToArray())},r={nonce}";
        authMessage       = $"{clientFirstBare},{ServerFirst},{withoutProof}";

        var clientKey     = HMACSHA256.HashData(saltedPassword, "Client Key"u8);
        var storedKey     = SHA256.HashData(clientKey);
        var signature     = HMACSHA256.HashData(storedKey, Encoding.UTF8.GetBytes(authMessage));
        var proof         = clientKey.Zip(signature, (a, b) => (Byte) (a ^ b)).ToArray();

        return $"{withoutProof},p={Convert.ToBase64String(proof)}";

    }


    /// <summary>
    /// The server-final-message a server that knows the password must send: "v=" ServerSignature.
    /// </summary>
    public String ExpectedServerFinal()
    {

        if (saltedPassword is null || authMessage is null)
            throw new InvalidOperationException("ClientFinal first.");

        var serverKey = HMACSHA256.HashData(saltedPassword, "Server Key"u8);

        return "v=" + Convert.ToBase64String(HMACSHA256.HashData(serverKey, Encoding.UTF8.GetBytes(authMessage)));

    }

}
