using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SMTPConformance.Core.Fixtures;

/// <summary>
/// How the suite's ARC sealer seals - by default as RFC 8617 says; the other settings build
/// the sets a validator has to refuse.
/// </summary>
public sealed record TestArcSealOptions
{

    /// <summary>
    /// The instance; by default one above the highest the message carries.
    /// </summary>
    public Int32?    Instance        { get; init; }

    /// <summary>
    /// The cv= value as written - by default "none" for instance 1 and "pass" above it. Written
    /// as it is: "fail; cv=pass" writes the tag twice.
    /// </summary>
    public String?   Cv              { get; init; }

    public String    Algorithm       { get; init; } = "rsa-sha256";

    public String    AuthServId      { get; init; } = "forwarder.example";

    public String    AuthResults     { get; init; } = "spf=pass smtp.mailfrom=forwarder.example";

    /// <summary>
    /// Tags added to the ARC-Seal before its b= - "h=from" gives it the tag it must not have.
    /// </summary>
    public String?   ExtraSealTags   { get; init; }

    /// <summary>
    /// b= as the first tag of the ARC-Message-Signature and the ARC-Seal.
    /// </summary>
    public Boolean   SignatureFirst  { get; init; }

    public String[]  SignedHeaders   { get; init; } = [ "from", "to", "subject", "date", "message-id" ];

}


/// <summary>
/// ARC (RFC 8617) of the suite's own: a sealer, so that what Hermod validates was not sealed
/// by Hermod, and a validator after §5.2, so that what Hermod seals is not judged by Hermod.
/// rsa-sha256 (and rsa-sha1, to be refused), relaxed/relaxed.
/// </summary>
public static partial class TestArc
{

    public  const  String    AAR  = "ARC-Authentication-Results";
    public  const  String    AMS  = "ARC-Message-Signature";
    public  const  String    AS   = "ARC-Seal";

    private static readonly String[] setOrder = [ AAR, AMS, AS ];


    #region Seal(Message, Key, Options = null)

    /// <summary>
    /// The message with one more ARC set on top: ARC-Seal, ARC-Message-Signature,
    /// ARC-Authentication-Results.
    /// </summary>
    public static String Seal(String Message, TestDkimKey Key, TestArcSealOptions? Options = null)
    {

        var o          = Options ?? new TestArcSealOptions();
        var (head, body) = TestDkimKey.Split(Message);
        var fields     = TestDkimKey.Fields(head);
        var instance   = o.Instance ?? fields.Where(IsArc).Select(field => InstanceOf(field.Value)).DefaultIfEmpty(0).Max() + 1;
        var cv         = o.Cv ?? (instance == 1 ? "none" : "pass");
        var sha1       = o.Algorithm == "rsa-sha1";
        var t          = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // §4.1.1: the AAR is the authres-payload of this hop, with its instance.
        var aar        = $" i={instance}; {o.AuthServId}; {o.AuthResults}";

        // §4.1.2: the AMS is a DKIM signature without v=, over no ARC header field.
        var bh         = Convert.ToBase64String(TestDkimKey.Hash(Encoding.UTF8.GetBytes(TestDkimKey.RelaxedBody(body)), sha1));
        var amsTags    = $"i={instance}; a={o.Algorithm}; c=relaxed/relaxed; d={Key.Domain}; s={Key.Selector}; t={t}; h={String.Join(":", o.SignedHeaders)}; bh={bh}";
        var amsInput   = TestDkimKey.SelectedHeaders(fields, o.SignedHeaders) +
                         TestDkimKey.RelaxedHeader(AMS, Place(amsTags, "", o.SignatureFirst));
        var ams        = Place(amsTags, Convert.ToBase64String(Key.SignData(amsInput, sha1)), o.SignatureFirst);

        // §4.1.3: the AS signs the ARC sets 1..i in increasing order, each as AAR, AMS, AS,
        // the AS being made with b= empty and without its final CRLF.
        var asTags     = $"i={instance}; a={o.Algorithm}; cv={cv}; d={Key.Domain}; s={Key.Selector}; t={t}" +
                         (o.ExtraSealTags is not null ? "; " + o.ExtraSealTags : "");
        var asInput    = new StringBuilder();

        for (var i = 1; i < instance; i++)
            foreach (var name in setOrder)
                foreach (var field in fields.Where(field => Is(field, name) && InstanceOf(field.Value) == i).Take(1))
                    asInput.Append(TestDkimKey.RelaxedHeader(field.Name, field.Value)).Append("\r\n");

        asInput.Append(TestDkimKey.RelaxedHeader(AAR, aar)).Append("\r\n");
        asInput.Append(TestDkimKey.RelaxedHeader(AMS, ams)).Append("\r\n");
        asInput.Append(TestDkimKey.RelaxedHeader(AS,  Place(asTags, "", o.SignatureFirst)));

        var seal       = Place(asTags, Convert.ToBase64String(Key.SignData(asInput.ToString(), sha1)), o.SignatureFirst);

        return $"{AS}:{seal}\r\n{AMS}:{ams}\r\n{AAR}:{aar}\r\n" + Message;

    }

    private static String Place(String Tags, String Signature, Boolean First)
        => First ? $" b={Signature}; {Tags}" : $" {Tags}; b={Signature}";

    #endregion

    #region Validate(Message, PublicKey)

    /// <summary>
    /// The chain validation status of RFC 8617 §5.2 - "none", "pass" or "fail" - with what
    /// decided it. One key for every signature: the test knows whose it is.
    /// </summary>
    public static (String Status, String Detail) Validate(String Message, RSA PublicKey)
    {
        try
        {
            return ValidateChain(Message, PublicKey);
        }
        catch (FormatException e)
        {
            return ("fail", e.Message);
        }
    }

    private static (String Status, String Detail) ValidateChain(String Message, RSA PublicKey)
    {

        var (head, body) = TestDkimKey.Split(Message);
        var fields       = TestDkimKey.Fields(head);
        var arc          = fields.Where(IsArc).ToList();

        // Step 1: none, or at most 50 sets.
        if (arc.Count == 0)
            return ("none", "no ARC header fields");

        var instances    = arc.Select(field => InstanceOf(field.Value)).ToList();
        var n            = instances.Max();

        if (n > 50)
            return ("fail", $"instance {n}: more than 50 ARC sets");

        // Step 3: one of each per instance, 1..N without gaps; cv none at 1, pass above.
        for (var i = 1; i <= n; i++)
            foreach (var name in setOrder)
                if (fields.Count(field => Is(field, name) && InstanceOf(field.Value) == i) != 1)
                    return ("fail", $"instance {i} has not exactly one {name}");

        if (instances.Any(i => i < 1))
            return ("fail", "an ARC header field without a valid instance");

        for (var i = 1; i <= n; i++)
        {
            var cv = Tags(Field(fields, AS, i).Value).GetValueOrDefault("cv");
            if (cv != (i == 1 ? "none" : "pass"))
                return ("fail", $"instance {i}: cv={cv}");
        }

        // Step 4: the newest AMS.
        var ams          = Field(fields, AMS, n);
        var amsTags      = Tags(ams.Value);

        if (amsTags.GetValueOrDefault("a") != "rsa-sha256")
            return ("fail", $"AMS {n}: a={amsTags.GetValueOrDefault("a")}");

        if (amsTags.GetValueOrDefault("c") != "relaxed/relaxed")
            return ("fail", $"AMS {n}: c={amsTags.GetValueOrDefault("c")} - the suite validates relaxed/relaxed only");

        var bh           = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(TestDkimKey.RelaxedBody(body))));
        if (bh != Unspace(amsTags.GetValueOrDefault("bh") ?? ""))
            return ("fail", $"AMS {n}: body hash");

        var amsInput     = TestDkimKey.SelectedHeaders(fields, (amsTags.GetValueOrDefault("h") ?? "").Split(':')) +
                           TestDkimKey.RelaxedHeader(ams.Name, WithoutSignature(ams.Value));

        if (!Verifies(PublicKey, amsInput, amsTags.GetValueOrDefault("b")))
            return ("fail", $"AMS {n}: signature");

        // Step 6: every AS.
        for (var i = n; i >= 1; i--)
        {

            var seal     = Field(fields, AS, i);
            var sealTags = Tags(seal.Value);

            if (sealTags.ContainsKey("h"))
                return ("fail", $"AS {i}: has an h= tag");

            if (sealTags.GetValueOrDefault("a") != "rsa-sha256")
                return ("fail", $"AS {i}: a={sealTags.GetValueOrDefault("a")}");

            var input    = new StringBuilder();
            for (var j = 1; j <= i; j++)
            {
                input.Append(TestDkimKey.RelaxedHeader(AAR, Field(fields, AAR, j).Value)).Append("\r\n");
                input.Append(TestDkimKey.RelaxedHeader(AMS, Field(fields, AMS, j).Value)).Append("\r\n");
                if (j < i)
                    input.Append(TestDkimKey.RelaxedHeader(AS, Field(fields, AS, j).Value)).Append("\r\n");
            }
            input.Append(TestDkimKey.RelaxedHeader(AS, WithoutSignature(seal.Value)));

            if (!Verifies(PublicKey, input.ToString(), sealTags.GetValueOrDefault("b")))
                return ("fail", $"AS {i}: signature");

        }

        return ("pass", $"{n} ARC set(s)");

    }

    private static Boolean Verifies(RSA PublicKey, String Input, String? Signature)
    {
        try
        {
            return Signature is not null &&
                   PublicKey.VerifyData(Encoding.UTF8.GetBytes(Input), Convert.FromBase64String(Unspace(Signature)), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    #endregion

    #region Tags, fields

    /// <summary>
    /// A tag-list (RFC 6376 §3.2): names are case-sensitive, and one that occurs twice makes
    /// the whole list invalid.
    /// </summary>
    public static Dictionary<String, String> Tags(String Value)
    {

        var tags = new Dictionary<String, String>(StringComparer.Ordinal);

        foreach (var part in Value.Replace("\r\n", "").Split(';'))
        {

            var equals = part.IndexOf('=');
            if (equals <= 0)
                continue;

            var name = part[..equals].Trim();
            if (!tags.TryAdd(name, part[(equals + 1)..].Trim()))
                throw new FormatException($"the tag {name} twice: an invalid tag-list");

        }

        return tags;

    }

    /// <summary>
    /// The value of each header field of that name, unfolded, top to bottom.
    /// </summary>
    public static IReadOnlyList<String> Header(String Message, String Name)
        => [ .. TestDkimKey.Fields(TestDkimKey.Split(Message).Header).
                            Where (field => field.Name.Trim().Equals(Name, StringComparison.OrdinalIgnoreCase)).
                            Select(field => field.Value.Replace("\r\n", "").Trim()) ];

    public static Int32 InstanceOf(String Value)
    {
        var match = Instance().Match(Value.Replace("\r\n", ""));
        return match.Success && Int32.TryParse(match.Groups["i"].Value, out var i) ? i : 0;
    }

    private static Boolean IsArc((String Name, String Value) Field)
        => setOrder.Any(name => Is(Field, name));

    private static Boolean Is((String Name, String Value) Field, String Name)
        => Field.Name.Trim().Equals(Name, StringComparison.OrdinalIgnoreCase);

    private static (String Name, String Value) Field(List<(String Name, String Value)> Fields, String Name, Int32 Instance)
        => Fields.Single(field => Is(field, Name) && InstanceOf(field.Value) == Instance);

    /// <summary>
    /// The value with the value of its b= tag removed - b= at a tag boundary, wherever it stands.
    /// </summary>
    private static String WithoutSignature(String Value)
        => SignatureValue().Replace(Value, "${pre}");

    private static String Unspace(String Base64)
        => Regex.Replace(Base64, @"\s+", "");

    [GeneratedRegex(@"(?:^|;)\s*i\s*=\s*(?<i>\d+)\s*(?:;|$)")]
    private static partial Regex Instance();

    [GeneratedRegex(@"(?<pre>(?:^|;)\s*b\s*=)[^;]*")]
    private static partial Regex SignatureValue();

    #endregion

}
