using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace SMTPConformance.Core.Fixtures;

/// <summary>
/// One MIME part of a report mail: its header fields and its decoded content.
/// </summary>
public sealed record ReportPart(IReadOnlyDictionary<String, String> Headers, Byte[] Content)
{

    public String ContentType
        => Headers.GetValueOrDefault("Content-Type") ?? "text/plain";

    public String Text
        => Encoding.UTF8.GetString(Content);

    /// <summary>
    /// The content, gunzipped.
    /// </summary>
    public String Gunzipped()
    {
        using var gzip   = new GZipStream(new MemoryStream(Content), CompressionMode.Decompress);
        using var reader = new StreamReader(gzip, Encoding.UTF8);
        return reader.ReadToEnd();
    }

}


/// <summary>
/// Just enough MIME (RFC 2045, RFC 2046) to read the report mails a reporter queues - DMARC
/// aggregate and failure reports, TLS-RPT reports: header fields, one level of multipart,
/// base64 and 7bit content.
/// </summary>
public static partial class ReportMail
{

    /// <summary>
    /// The header fields of a message or part, unfolded; a name that occurs twice keeps its first value.
    /// </summary>
    public static IReadOnlyDictionary<String, String> Headers(String Message)
    {

        var end     = Message.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var header  = end >= 0 ? Message[..end] : Message;
        var fields  = new Dictionary<String, String>(StringComparer.OrdinalIgnoreCase);

        foreach (Match field in Field().Matches(header))
            fields.TryAdd(field.Groups["name"].Value, Regex.Replace(field.Groups["value"].Value, @"\r\n[ \t]+", " ").Trim());

        return fields;

    }

    /// <summary>
    /// The parts of a multipart message, one level deep.
    /// </summary>
    public static IReadOnlyList<ReportPart> Parts(String Message)
    {

        var contentType = Headers(Message).GetValueOrDefault("Content-Type") ?? "";
        var boundary    = Boundary().Match(contentType);

        if (!boundary.Success)
            throw new FormatException("not multipart: " + contentType);

        var delimiter   = "--" + boundary.Groups["b"].Value;
        var body        = Message[(Message.IndexOf("\r\n\r\n", StringComparison.Ordinal) + 4)..];
        var parts       = new List<ReportPart>();

        foreach (var chunk in body.Split(delimiter).Skip(1))
        {

            if (chunk.StartsWith("--", StringComparison.Ordinal))
                break;

            var part     = chunk.TrimStart('\r', '\n');
            var headers  = Headers(part);
            var split    = part.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            var content  = split >= 0 ? part[(split + 4)..] : "";

            if (content.EndsWith("\r\n", StringComparison.Ordinal))
                content = content[..^2];

            var bytes    = (headers.GetValueOrDefault("Content-Transfer-Encoding") ?? "").Equals("base64", StringComparison.OrdinalIgnoreCase)
                               ? Convert.FromBase64String(Regex.Replace(content, @"\s+", ""))
                               : Encoding.UTF8.GetBytes(content);

            parts.Add(new ReportPart(headers, bytes));

        }

        return parts;

    }

    /// <summary>
    /// The first part whose media type is this one (parameters ignored).
    /// </summary>
    public static ReportPart Part(String Message, String MediaType)
        => Parts(Message).First(part => part.ContentType.Split(';')[0].Trim().Equals(MediaType, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// A parameter of a header field value - Content-Type's boundary, Content-Disposition's filename.
    /// </summary>
    public static String? Parameter(String HeaderValue, String Name)
    {
        var match = Regex.Match(HeaderValue, $@";\s*{Regex.Escape(Name)}\s*=\s*(?:""(?<v>[^""]*)""|(?<v>[^;\s]+))", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups["v"].Value : null;
    }

    [GeneratedRegex(@"^(?<name>[!-9;-~]+):(?<value>[^\r\n]*(?:\r\n[ \t][^\r\n]*)*)", RegexOptions.Multiline)]
    private static partial Regex Field();

    [GeneratedRegex(@"boundary\s*=\s*""?(?<b>[^"";\s]+)""?", RegexOptions.IgnoreCase)]
    private static partial Regex Boundary();

}
