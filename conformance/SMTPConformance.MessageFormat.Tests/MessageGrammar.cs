using System.Text;
using System.Text.RegularExpressions;

namespace SMTPConformance.MessageFormat.Tests;

/// <summary>
/// The suite's own reading of a message Hermod wrote - RFC 5322 header fields, RFC 2045
/// quoted-printable, RFC 2046 boundaries, RFC 2047 encoded words - strict where the RFCs
/// are, and sharing no code with Hermod.
/// </summary>
internal static partial class MessageGrammar
{

    /// <summary>
    /// Octets as text, one character per octet: an 8-bit octet stays visible as what it was.
    /// </summary>
    public static String Text(Byte[] Octets)
        => Encoding.Latin1.GetString(Octets);

    /// <summary>
    /// The lines of a message: split at CRLF, the last one left out when the message ends with one.
    /// </summary>
    public static IReadOnlyList<String> Lines(String Message)
    {
        var lines = Message.Split("\r\n");
        return Message.EndsWith("\r\n", StringComparison.Ordinal) ? lines[..^1] : lines;
    }

    /// <summary>
    /// Whether the text holds a CR or an LF that is not part of a CRLF.
    /// </summary>
    public static Boolean HasBareLineBreak(String Message)
        => Message.Replace("\r\n", "").AsSpan().IndexOfAny('\r', '\n') >= 0;

    /// <summary>
    /// The longest line, without its CRLF.
    /// </summary>
    public static String LongestLine(String Message)
        => Lines(Message).MaxBy(line => line.Length) ?? "";

    /// <summary>
    /// The header section of a message or part (up to the first empty line).
    /// </summary>
    public static String HeaderSection(String Message)
    {
        var end = Message.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        return end >= 0 ? Message[..(end + 2)] : Message;
    }

    /// <summary>
    /// The header fields of a message or part in their order: their names and their raw
    /// (still folded) values, as RFC 5322 §2.2 has them - field-name ":" field-body.
    /// </summary>
    public static IReadOnlyList<(String Name, String Raw)> Fields(String Message)
        => [ .. Field().Matches(HeaderSection(Message)).Select(match => (match.Groups["name"].Value, match.Groups["value"].Value)) ];

    /// <summary>
    /// The value of the first header field of that name, unfolded (RFC 5322 §2.2.3) and trimmed.
    /// </summary>
    public static String? Value(String Message, String Name)
        => Fields(Message).Where(field => field.Name.Equals(Name, StringComparison.OrdinalIgnoreCase)).
                           Select(field => Unfold(field.Raw).Trim()).
                           FirstOrDefault();

    /// <summary>
    /// Unfolding (RFC 5322 §2.2.3): every CRLF that is followed by WSP is removed.
    /// </summary>
    public static String Unfold(String Raw)
        => Regex.Replace(Raw, "\r\n(?=[ \t])", "");

    /// <summary>
    /// The lines of the header section that are not a field and not a continuation of one -
    /// what RFC 5322 §2.2 does not allow there.
    /// </summary>
    public static IEnumerable<String> MalformedHeaderLines(String Message)
        => Lines(HeaderSection(Message)).Where(line => line.Length > 0 && !FieldStart().IsMatch(line) && line[0] is not (' ' or '\t'));

    /// <summary>
    /// The body of a message or part: what follows the first empty line.
    /// </summary>
    public static String Body(String Message)
    {
        var end = Message.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        return end >= 0 ? Message[(end + 4)..] : "";
    }

    /// <summary>
    /// A parameter of a header field value, its quotes taken away.
    /// </summary>
    public static String? Parameter(String Value, String Name)
    {
        var match = Regex.Match(Value, $@";\s*{Regex.Escape(Name)}\s*=\s*(?:""(?<v>(?:[^""\\]|\\.)*)""|(?<v>[^;\s]+))", RegexOptions.IgnoreCase);
        return match.Success ? Regex.Replace(match.Groups["v"].Value, @"\\(.)", "$1") : null;
    }

    /// <summary>
    /// The body parts of a multipart body, split at its boundary delimiter lines (RFC 2046
    /// §5.1.1): the CRLF before a delimiter belongs to the delimiter; preamble and epilogue go.
    /// </summary>
    public static IReadOnlyList<String> Parts(String Body, String Boundary)
    {

        var parts    = new List<String>();
        var text     = "\r\n" + Body;
        var position = text.IndexOf("\r\n--" + Boundary + "\r\n", StringComparison.Ordinal);

        if (position < 0)
            return parts;

        position += Boundary.Length + 6;

        while (true)
        {

            var next  = text.IndexOf("\r\n--" + Boundary, position, StringComparison.Ordinal);
            if (next < 0)
                break;

            parts.Add(text[position..next]);

            var after = next + Boundary.Length + 4;
            if (text.AsSpan(after).StartsWith("--"))
                break;

            position = after + 2;

        }

        return parts;

    }


    #region Grammars

    /// <summary>
    /// RFC 5322 §3.3 date-time, as it is to be generated (no obsolete forms).
    /// </summary>
    [GeneratedRegex(@"^(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), )?\d{1,2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}(?::\d{2})? [+-]\d{4}$", RegexOptions.CultureInvariant)]
    public static partial Regex DateTime();

    /// <summary>
    /// RFC 5322 §3.6.4 msg-id: "&lt;" id-left "@" id-right "&gt;", id-left a dot-atom-text,
    /// id-right a dot-atom-text or a no-fold-literal.
    /// </summary>
    [GeneratedRegex(@"^<[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\[[!-Z^-~]*\])>$", RegexOptions.CultureInvariant)]
    public static partial Regex MsgId();

    /// <summary>
    /// RFC 2046 §5.1.1: boundary := 0*69&lt;bchars&gt; bcharsnospace.
    /// </summary>
    [GeneratedRegex(@"^[0-9A-Za-z'()+_,\-./:=? ]{0,69}[0-9A-Za-z'()+_,\-./:=?]$", RegexOptions.CultureInvariant)]
    public static partial Regex Boundary();

    /// <summary>
    /// RFC 2047 §2 encoded-word: "=?" charset "?" encoding "?" encoded-text "?=".
    /// </summary>
    [GeneratedRegex(@"=\?(?<charset>[^()<>@,;:""/\[\]?.= \t]+)\?(?<encoding>[QqBb])\?(?<text>[!->@-~]*)\?=", RegexOptions.CultureInvariant)]
    public static partial Regex EncodedWord();

    /// <summary>
    /// RFC 2047 §5 (3): the characters a "Q" encoded-word in a phrase may hold.
    /// </summary>
    [GeneratedRegex(@"^(?:[A-Za-z0-9!*+\-/_]|=[0-9A-F]{2})*$", RegexOptions.CultureInvariant)]
    public static partial Regex PhraseQText();

    /// <summary>
    /// RFC 2231 §7 extended-initial-value: [charset] "'" [language] "'" extended-other-values.
    /// </summary>
    [GeneratedRegex(@"^[A-Za-z0-9!#$&+\-^_`{}~]*'[A-Za-z0-9-]*'(?:[A-Za-z0-9!#$&+\-.^_`|~]|%[0-9A-Fa-f]{2})*$", RegexOptions.CultureInvariant)]
    public static partial Regex ExtendedInitialValue();

    [GeneratedRegex(@"^(?<name>[!-9;-~]+):(?<value>[^\r\n]*(?:\r\n[ \t][^\r\n]*)*)\r\n", RegexOptions.Multiline)]
    private static partial Regex Field();

    [GeneratedRegex(@"^[!-9;-~]+:")]
    private static partial Regex FieldStart();

    #endregion


    #region Decoders

    /// <summary>
    /// Quoted-printable (RFC 2045 §6.7), strictly: soft line breaks go, "=XX" in upper case is
    /// the octet, nothing else may follow an "=".
    /// </summary>
    public static Byte[] DecodeQuotedPrintable(String Encoded)
    {

        var octets = new List<Byte>();

        for (var i = 0; i < Encoded.Length; i++)
        {

            if (Encoded[i] != '=')
            {
                octets.Add((Byte) Encoded[i]);
                continue;
            }

            if (Encoded.AsSpan(i + 1).StartsWith("\r\n"))
            {
                i += 2;
                continue;
            }

            if (i + 2 < Encoded.Length && Uri.IsHexDigit(Encoded[i + 1]) && Uri.IsHexDigit(Encoded[i + 2]) && !Char.IsLower(Encoded[i + 1]) && !Char.IsLower(Encoded[i + 2]))
            {
                octets.Add(Convert.ToByte(Encoded.Substring(i + 1, 2), 16));
                i += 2;
                continue;
            }

            throw new FormatException($"'=' at {i} starts neither an escape nor a soft line break");

        }

        return [ .. octets ];

    }

    /// <summary>
    /// The octets of a "Q" encoded-text (RFC 2047 §4.2): "_" is a space, "=XX" an octet.
    /// </summary>
    public static Byte[] DecodeQ(String EncodedText)
    {

        var octets = new List<Byte>();

        for (var i = 0; i < EncodedText.Length; i++)
        {
            if (EncodedText[i] == '_')
                octets.Add(0x20);
            else if (EncodedText[i] == '=')
            {
                octets.Add(Convert.ToByte(EncodedText.Substring(i + 1, 2), 16));
                i += 2;
            }
            else
                octets.Add((Byte) EncodedText[i]);
        }

        return [ .. octets ];

    }

    #endregion

}
