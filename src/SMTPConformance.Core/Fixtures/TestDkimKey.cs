using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace SMTPConformance.Core.Fixtures;

/// <summary>
/// A DKIM signer of the suite's own (RFC 6376, rsa-sha256, relaxed/relaxed - or a relaxed
/// header and a simple body), so that what Hermod verifies was not signed by Hermod. One key,
/// one domain, one selector.
/// </summary>
public sealed partial class TestDkimKey : IDisposable
{

    private readonly RSA rsa;

    public String  Domain    { get; }
    public String  Selector  { get; }

    /// <summary>
    /// The owner name of the key record: selector._domainkey.domain (RFC 6376 §3.6.2.1).
    /// </summary>
    public String  RecordName
        => $"{Selector}._domainkey.{Domain}";

    /// <param name="Bits">The size of the RSA key: 2048, or another - 512, which RFC 8301
    /// §3.2 forbids, for a verifier that is to refuse it.</param>
    public TestDkimKey(String Domain, String Selector = "test", Int32 Bits = 2048)
    {
        this.Domain    = Domain;
        this.Selector  = Selector;
        this.rsa       = RSA.Create(Bits);
    }


    /// <summary>
    /// The key record as RFC 6376 §3.6.1 writes it - with the version tag, or (it is only
    /// RECOMMENDED) without.
    /// </summary>
    public TXT Record(Boolean WithVersion = true)
        => Record((WithVersion ? "v=DKIM1; " : "") + "k=rsa; ");

    /// <summary>
    /// A key record of the given tags, the p= tag with the public key after them - "v=DKIM1;
    /// k=rsa; h=sha1; " for one that names its hash algorithms (RFC 6376 §3.6.1).
    /// </summary>
    public TXT Record(String TagsBeforeKey)

        => new (DNSServiceName.Parse(RecordName), DNSQueryClasses.IN, TimeSpan.FromHours(1),
                TagsBeforeKey + $"p={Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo())}");

    /// <summary>
    /// The private key as PKCS#8 PEM - for a signer under test that is to sign with this key.
    /// </summary>
    public String ExportPrivateKeyPem()
        => rsa.ExportPkcs8PrivateKeyPem();

    /// <summary>
    /// The public key, for checking what was signed with this key.
    /// </summary>
    public RSA PublicKey()
    {
        var key = RSA.Create();
        key.ImportSubjectPublicKeyInfo(rsa.ExportSubjectPublicKeyInfo(), out _);
        return key;
    }


    /// <summary>
    /// The message with a DKIM-Signature field on top, over the given header fields and the
    /// body. CRLF line ends throughout.
    /// </summary>
    public String Sign(String Message, params String[] SignedHeaders)
        => Sign(Message, "rsa-sha256", false, SignedHeaders);

    /// <summary>
    /// As above, with the algorithm named - "rsa-sha1", which RFC 8301 retired, hashes and
    /// signs with SHA-1 - and, if asked, the b= tag first: RFC 6376 §3.2 leaves the order of
    /// the tags free.
    /// </summary>
    public String Sign(String Message, String Algorithm, Boolean SignatureFirst, params String[] SignedHeaders)
        => Sign(Message, Algorithm, SignatureFirst, tags => tags, SignedHeaders);

    /// <summary>
    /// As above, the tags before b= changed first - "v=1; a=rsa-sha256; c=relaxed/relaxed;
    /// d=...; s=...; t=...; h=...; bh=..." - and then signed as they are: a signature without
    /// v=, or with an i= of another domain, that is a valid signature over what it says.
    /// </summary>
    public String Sign(String Message, Func<String, String> Tags, params String[] SignedHeaders)
        => Sign(Message, "rsa-sha256", false, Tags, SignedHeaders);

    /// <summary>
    /// As above, with the c= tag written as given - "relaxed", "relaxed/simple" or
    /// "relaxed/relaxed" - and the body canonicalized as it says: RFC 6376 §3.5, "If only one
    /// algorithm is named, that algorithm is used for the header and "simple" is used for the
    /// body". The header is always relaxed.
    /// </summary>
    public String SignCanonicalized(String Message, String Canonicalization, params String[] SignedHeaders)
    {

        var names = Canonicalization.Split('/');

        if (names[0] != "relaxed" || names.Length > 2 || names.Length == 2 && names[1] is not ("relaxed" or "simple"))
            throw new ArgumentException($"The suite's signer canonicalizes a relaxed header only, not c={Canonicalization}.", nameof(Canonicalization));

        return Sign(Message, "rsa-sha256", false, tags => tags, SignedHeaders, Canonicalization, names.Length == 2 ? names[1] : "simple");

    }

    private String Sign(String Message, String Algorithm, Boolean SignatureFirst, Func<String, String> Tags, String[] SignedHeaders,
                        String Canonicalization = "relaxed/relaxed", String BodyCanonicalization = "relaxed")
    {

        if (SignedHeaders.Length == 0)
            SignedHeaders = [ "from", "to", "subject", "date", "message-id" ];

        var (header, body) = Split(Message);
        var sha1     = Algorithm == "rsa-sha1";

        var bodyHash = Convert.ToBase64String(Hash(Encoding.UTF8.GetBytes(BodyCanonicalization == "simple" ? SimpleBody(body) : RelaxedBody(body)), sha1));
        var rest     = Tags($"v=1; a={Algorithm}; c={Canonicalization}; d={Domain}; s={Selector}; " +
                            $"t={DateTimeOffset.UtcNow.ToUnixTimeSeconds()}; h={String.Join(":", SignedHeaders)}; bh={bodyHash}");
        var empty    = SignatureFirst ? "b=; " + rest : rest + "; b=";

        // §3.7: the selected header fields, then the DKIM-Signature field itself, b= empty,
        // without its final CRLF.
        var input    = SelectedHeaders(Fields(header), SignedHeaders) +
                       RelaxedHeader("DKIM-Signature", " " + empty);

        var b        = Convert.ToBase64String(SignData(input, sha1));

        return "DKIM-Signature: " + (SignatureFirst ? $"b={b}; " + rest : rest + "; b=" + b) + "\r\n" + Message;

    }


    /// <summary>
    /// An RSA PKCS#1 v1.5 signature over the UTF-8 octets of the input, with SHA-256 or SHA-1.
    /// </summary>
    internal Byte[] SignData(String Input, Boolean Sha1 = false)
        => rsa.SignData(Encoding.UTF8.GetBytes(Input), Sha1 ? HashAlgorithmName.SHA1 : HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    internal static Byte[] Hash(Byte[] Data, Boolean Sha1 = false)
        => Sha1 ? SHA1.HashData(Data) : SHA256.HashData(Data);

    /// <summary>
    /// A message split at its first empty line: the header with its last CRLF, and the body.
    /// </summary>
    internal static (String Header, String Body) Split(String Message)
    {
        var split = Message.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        return (Message[..(split + 2)], Message[(split + 4)..]);
    }

    /// <summary>
    /// The relaxed - or, if asked, the simple - CRLF-terminated header fields a signature's h=
    /// list names (RFC 6376 §5.4.2): each name picks the last instance not yet used, from the
    /// bottom up; a name with no instance left adds nothing.
    /// </summary>
    internal static String SelectedHeaders(List<(String Name, String Value)> Fields, IEnumerable<String> Names, Boolean Relaxed = true)
    {

        var used  = new HashSet<Int32>();
        var input = new StringBuilder();

        foreach (var name in Names)
        {
            for (var i = Fields.Count - 1; i >= 0; i--)
            {
                if (!used.Contains(i) && Fields[i].Name.Trim().Equals(name.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    used.Add(i);
                    input.Append(Relaxed ? RelaxedHeader(Fields[i].Name, Fields[i].Value) : SimpleHeader(Fields[i].Name, Fields[i].Value)).Append("\r\n");
                    break;
                }
            }
        }

        return input.ToString();

    }


    /// <summary>
    /// The header fields, unfolded only as far as splitting them goes: name and raw value.
    /// </summary>
    internal static List<(String Name, String Value)> Fields(String Header)
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
    internal static String RelaxedHeader(String Name, String Value)
        => Name.Trim().ToLowerInvariant() + ":" + Whitespace().Replace(Value.Replace("\r\n", ""), " ").Trim(' ');

    /// <summary>
    /// RFC 6376 §3.4.1: "The "simple" header canonicalization algorithm does not change header
    /// fields in any way" - name, colon and value as they are, folding and all.
    /// </summary>
    internal static String SimpleHeader(String Name, String Value)
        => Name + ":" + Value;

    /// <summary>
    /// RFC 6376 §3.4.4: whitespace runs to one space, none at line ends, no empty lines at the
    /// end, and a CRLF after the last line of a body that is not empty.
    /// </summary>
    internal static String RelaxedBody(String Body)
    {

        var lines = Body.Split("\r\n").
                         Select(line => Whitespace().Replace(line, " ").TrimEnd(' ')).
                         ToList();

        while (lines.Count > 0 && lines[^1].Length == 0)
            lines.RemoveAt(lines.Count - 1);

        return lines.Count == 0 ? "" : String.Join("\r\n", lines) + "\r\n";

    }

    /// <summary>
    /// RFC 6376 §3.4.3: the body as it is, but for the empty lines at its end - "If there is no
    /// body or no trailing CRLF on the message body, a CRLF is added".
    /// </summary>
    internal static String SimpleBody(String Body)
    {

        while (Body.EndsWith("\r\n\r\n", StringComparison.Ordinal))
            Body = Body[..^2];

        return Body.EndsWith("\r\n", StringComparison.Ordinal) ? Body : Body + "\r\n";

    }

    [GeneratedRegex("[ \t]+")]
    private static partial Regex Whitespace();

    public void Dispose()
        => rsa.Dispose();

}
