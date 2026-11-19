using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace SMTPConformance.Core.Fixtures;

/// <summary>
/// One DKIM-Signature of a message, and whether it verified.
/// </summary>
public sealed record DkimVerification(String   Domain,
                                     String   Selector,
                                     String   Algorithm,
                                     Boolean  Valid,
                                     String   Detail);

/// <summary>
/// A DKIM verifier of the suite's own (RFC 6376 §6, RFC 8463), so that what Hermod signs is
/// checked by something other than Hermod: rsa-sha256 and ed25519-sha256, simple and relaxed
/// canonicalization, over the message's octets as Latin-1 text (one char per octet).
/// </summary>
public static partial class TestDkimVerifier
{

    /// <summary>
    /// Verify every DKIM-Signature of the message against the given key records - by their
    /// owner name, selector._domainkey.domain - as RFC 6376 §3.6.1 writes them.
    /// </summary>
    public static IReadOnlyList<DkimVerification> Verify(String Message, IReadOnlyDictionary<String, String> KeyRecords)
    {

        var split   = Message.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var fields  = Fields(Message[..(split + 2)]);
        var body    = Message[(split + 4)..];
        var results = new List<DkimVerification>();

        foreach (var signature in fields.Where(field => field.Name.Equals("DKIM-Signature", StringComparison.OrdinalIgnoreCase)))
        {

            var tags      = Tags(signature.Value);
            var domain    = tags.GetValueOrDefault("d", "");
            var selector  = tags.GetValueOrDefault("s", "");
            var algorithm = tags.GetValueOrDefault("a", "");

            DkimVerification Result(Boolean Valid, String Detail)
                => new (domain, selector, algorithm, Valid, Detail);

            var canonicalization = tags.GetValueOrDefault("c", "simple/simple").Split('/');
            var headerCanon      = canonicalization[0];
            var bodyCanon        = canonicalization.Length > 1 ? canonicalization[1] : "simple";

            // §3.7: the body hash.
            var bodyHash = Convert.ToBase64String(SHA256.HashData(Encoding.Latin1.GetBytes(bodyCanon == "relaxed" ? RelaxedBody(body) : SimpleBody(body))));
            if (bodyHash != tags.GetValueOrDefault("bh"))
            {
                results.Add(Result(false, $"body hash {bodyHash}, signed {tags.GetValueOrDefault("bh")}"));
                continue;
            }

            // §5.4.2: each name in h= picks the last instance not yet used, from the bottom up.
            var used  = new HashSet<Int32>();
            var input = new StringBuilder();

            foreach (var name in tags.GetValueOrDefault("h", "").Split(':').Select(name => name.Trim()))
            {
                for (var i = fields.Count - 1; i >= 0; i--)
                {
                    if (!used.Contains(i) && fields[i].Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                    {
                        used.Add(i);
                        input.Append(Header(headerCanon, fields[i].Name, fields[i].Value)).Append("\r\n");
                        break;
                    }
                }
            }

            // §3.7: the signature field itself, the value of b= deleted, without its final CRLF.
            input.Append(Header(headerCanon, signature.Name, SignatureValue().Replace(signature.Value, "${pre}")));

            var data = Encoding.Latin1.GetBytes(input.ToString());

            if (!KeyRecords.TryGetValue($"{selector}._domainkey.{domain}", out var record))
            {
                results.Add(Result(false, "no key record"));
                continue;
            }

            var key       = Tags(record);
            var publicKey = Convert.FromBase64String(key.GetValueOrDefault("p", ""));
            var signed    = Convert.FromBase64String(Regex.Replace(tags.GetValueOrDefault("b", ""), @"\s", ""));

            switch (algorithm)
            {

                case "rsa-sha256":
                    using (var rsa = RSA.Create())
                    {
                        rsa.ImportSubjectPublicKeyInfo(publicKey, out _);
                        results.Add(Result(rsa.VerifyData(data, signed, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), "rsa-sha256"));
                    }
                    break;

                // RFC 8463 §3: Ed25519 (PureEdDSA) over the SHA-256 hash of the data; §4.2: p= is
                // the raw 32-octet public key.
                case "ed25519-sha256":
                    if (publicKey.Length != 32)
                    {
                        results.Add(Result(false, $"p= is {publicKey.Length} octets, not the 32 of a raw Ed25519 key"));
                        break;
                    }
                    var verifier = new Ed25519Signer();
                    verifier.Init(false, new Ed25519PublicKeyParameters(publicKey, 0));
                    var hash = SHA256.HashData(data);
                    verifier.BlockUpdate(hash, 0, hash.Length);
                    results.Add(Result(verifier.VerifySignature(signed), "ed25519-sha256"));
                    break;

                default:
                    results.Add(Result(false, "unknown algorithm"));
                    break;

            }

        }

        return results;

    }


    // "b=" and its value - not "bh=" - with the whitespace around the value.
    [GeneratedRegex(@"(?<pre>(?:^|;)\s*b\s*=)[^;]*")]
    private static partial Regex SignatureValue();

    [GeneratedRegex("[ \t]+")]
    private static partial Regex Whitespace();

    /// <summary>
    /// The tag=value pairs of a DKIM-Signature or a key record, folding whitespace removed
    /// around them.
    /// </summary>
    private static Dictionary<String, String> Tags(String Value)

        => Value.Replace("\r\n", "").
                 Split(';', StringSplitOptions.RemoveEmptyEntries).
                 Select(tag => tag.Split('=', 2)).
                 Where (pair => pair.Length == 2).
                 GroupBy(pair => pair[0].Trim()).
                 ToDictionary(group => group.Key, group => group.First()[1].Trim());

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

    private static String Header(String Canonicalization, String Name, String Value)

        => Canonicalization == "relaxed"
               ? Name.Trim().ToLowerInvariant() + ":" + Whitespace().Replace(Value.Replace("\r\n", ""), " ").Trim(' ')
               : Name + ":" + Value;

    private static String RelaxedBody(String Body)
    {

        var lines = Body.Split("\r\n").Select(line => Whitespace().Replace(line, " ").TrimEnd(' ')).ToList();

        while (lines.Count > 0 && lines[^1].Length == 0)
            lines.RemoveAt(lines.Count - 1);

        return lines.Count == 0 ? "" : String.Join("\r\n", lines) + "\r\n";

    }

    private static String SimpleBody(String Body)
    {

        var lines = Body.Split("\r\n").ToList();

        while (lines.Count > 0 && lines[^1].Length == 0)
            lines.RemoveAt(lines.Count - 1);

        return String.Join("\r\n", lines) + "\r\n";

    }

}
