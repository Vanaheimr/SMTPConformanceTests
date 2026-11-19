using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace SMTPConformance.Core.Fixtures;

/// <summary>
/// A DKIM signer of the suite's own (RFC 6376, rsa-sha256, relaxed/relaxed), so that what
/// Hermod verifies was not signed by Hermod. One key, one domain, one selector.
/// </summary>
public sealed partial class TestDkimKey : IDisposable
{

    private readonly RSA rsa = RSA.Create(2048);

    public String  Domain    { get; }
    public String  Selector  { get; }

    /// <summary>
    /// The owner name of the key record: selector._domainkey.domain (RFC 6376 §3.6.2.1).
    /// </summary>
    public String  RecordName
        => $"{Selector}._domainkey.{Domain}";

    public TestDkimKey(String Domain, String Selector = "test")
    {
        this.Domain    = Domain;
        this.Selector  = Selector;
    }


    /// <summary>
    /// The key record as RFC 6376 §3.6.1 writes it - with the version tag, or (it is only
    /// RECOMMENDED) without.
    /// </summary>
    public TXT Record(Boolean WithVersion = true)

        => new (DNSServiceName.Parse(RecordName), DNSQueryClasses.IN, TimeSpan.FromHours(1),
                (WithVersion ? "v=DKIM1; " : "") + $"k=rsa; p={Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo())}");


    /// <summary>
    /// The message with a DKIM-Signature field on top, over the given header fields and the
    /// body. CRLF line ends throughout.
    /// </summary>
    public String Sign(String Message, params String[] SignedHeaders)
    {

        if (SignedHeaders.Length == 0)
            SignedHeaders = [ "from", "to", "subject", "date", "message-id" ];

        var split    = Message.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var header   = Message[..(split + 2)];
        var body     = Message[(split + 4)..];
        var fields   = Fields(header);

        var bodyHash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(RelaxedBody(body))));
        var tags     = $"v=1; a=rsa-sha256; c=relaxed/relaxed; d={Domain}; s={Selector}; " +
                       $"t={DateTimeOffset.UtcNow.ToUnixTimeSeconds()}; h={String.Join(":", SignedHeaders)}; bh={bodyHash}; b=";

        // RFC 6376 §5.4.2: each name picks the last instance not yet used, from the bottom up.
        var used     = new HashSet<Int32>();
        var input    = new StringBuilder();

        foreach (var name in SignedHeaders)
        {
            for (var i = fields.Count - 1; i >= 0; i--)
            {
                if (!used.Contains(i) && fields[i].Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    used.Add(i);
                    input.Append(RelaxedHeader(fields[i].Name, fields[i].Value)).Append("\r\n");
                    break;
                }
            }
        }

        // §3.7: the DKIM-Signature field itself, b= empty, without its final CRLF.
        input.Append(RelaxedHeader("DKIM-Signature", " " + tags));

        var signature = rsa.SignData(Encoding.UTF8.GetBytes(input.ToString()), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return $"DKIM-Signature: {tags}{Convert.ToBase64String(signature)}\r\n" + Message;

    }


    /// <summary>
    /// The header fields, unfolded only as far as splitting them goes: name and raw value.
    /// </summary>
    private static List<(String Name, String Value)> Fields(String Header)
    {

        var fields = new List<(String Name, String Value)>();

        foreach (var line in Header.Split("\r\n"))
        {

            if (line.Length == 0)
                continue;

            if ((line[0] == ' ' || line[0] == '\t') && fields.Count > 0)
            {
                fields[^1] = (fields[^1].Name, fields[^1].Value + "\r\n" + line);
                continue;
            }

            var colon = line.IndexOf(':');
            fields.Add((line[..colon], line[(colon + 1)..]));

        }

        return fields;

    }

    /// <summary>
    /// RFC 6376 §3.4.2: name in lower case, unfolded, whitespace runs to one space, none at
    /// the ends of the value.
    /// </summary>
    private static String RelaxedHeader(String Name, String Value)
        => Name.Trim().ToLowerInvariant() + ":" + Whitespace().Replace(Value.Replace("\r\n", ""), " ").Trim(' ');

    /// <summary>
    /// RFC 6376 §3.4.4: whitespace runs to one space, none at line ends, no empty lines at the
    /// end, and a CRLF after the last line of a body that is not empty.
    /// </summary>
    private static String RelaxedBody(String Body)
    {

        var lines = Body.Split("\r\n").
                         Select(line => Whitespace().Replace(line, " ").TrimEnd(' ')).
                         ToList();

        while (lines.Count > 0 && lines[^1].Length == 0)
            lines.RemoveAt(lines.Count - 1);

        return lines.Count == 0 ? "" : String.Join("\r\n", lines) + "\r\n";

    }

    [GeneratedRegex("[ \t]+")]
    private static partial Regex Whitespace();

    public void Dispose()
        => rsa.Dispose();

}
