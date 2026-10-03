using System.Text.RegularExpressions;

namespace SMTPConformance.Core.RawSmtp;

/// <summary>
/// One SMTP reply as it arrived on the wire, parsed independently of Hermod.
/// </summary>
/// <remarks>
/// <para>
/// RFC 5321 §4.2: <c>Reply-line = *( Reply-code "-" [ textstring ] CRLF ) Reply-code [ SP textstring ] CRLF</c>.
/// Every line of a multiline reply carries the same three-digit code; all but the
/// last have a hyphen after it, the last a space (or nothing at all).
/// </para>
/// <para>
/// The parser never throws on a malformed reply. It records what was wrong in
/// <see cref="Violations"/> and parses what it can, because a conformance test
/// wants to assert on the defect, not die on it.
/// </para>
/// </remarks>
public sealed partial class SmtpReply
{

    /// <summary>
    /// The three-digit reply code of the final line, or -1 when it was not three digits.
    /// </summary>
    public Int32                  Code         { get; }

    /// <summary>
    /// The text after the code and separator, one entry per line.
    /// </summary>
    public IReadOnlyList<String>  Lines        { get; }

    /// <summary>
    /// The lines exactly as received, without their line terminator.
    /// </summary>
    public IReadOnlyList<String>  RawLines     { get; }

    /// <summary>
    /// Everything the parser found wrong with the reply's syntax. Empty for a well-formed reply.
    /// </summary>
    public IReadOnlyList<String>  Violations   { get; }

    public Boolean                IsMultiline  => RawLines.Count > 1;

    /// <summary>
    /// The text of the first line.
    /// </summary>
    public String                 Text         => Lines.Count > 0 ? Lines[0] : "";

    /// <summary>
    /// The RFC 3463 enhanced status code that prefaces the first line's text, if any.
    /// </summary>
    public String?                EnhancedCode { get; }

    public Int32                  Class        => Code / 100;

    public Boolean                IsPositiveCompletion    => Class == 2;
    public Boolean                IsPositiveIntermediate  => Class == 3;
    public Boolean                IsTransientNegative     => Class == 4;
    public Boolean                IsPermanentNegative     => Class == 5;


    // RFC 3463 §2 / RFC 2034 §4: class "." subject "." detail, with 1*3digit each.
    [GeneratedRegex(@"^([245])\.(\d{1,3})\.(\d{1,3})(?=\s|$)")]
    private static partial Regex EnhancedCodePattern();


    private SmtpReply(Int32 Code, List<String> Lines, List<String> RawLines, List<String> Violations)
    {

        this.Code        = Code;
        this.Lines       = Lines;
        this.RawLines    = RawLines;
        this.Violations  = Violations;

        var match        = EnhancedCodePattern().Match(Text);
        EnhancedCode     = match.Success ? match.Value : null;

    }


    /// <summary>
    /// Whether every line's text is prefaced with an enhanced status code whose class
    /// matches the reply code's class (RFC 2034 §4, RFC 3463 §2).
    /// </summary>
    public Boolean EveryLineHasEnhancedCode
        => Lines.All(line => {
               var match = EnhancedCodePattern().Match(line);
               return match.Success && match.Groups[1].Value == Class.ToString();
           });


    /// <summary>
    /// Parse a reply from the lines that made it up.
    /// </summary>
    /// <param name="Lines">The reply's lines, without their terminators.</param>
    /// <param name="TerminatorViolations">Line-terminator defects the reader already noticed (bare LF).</param>
    public static SmtpReply Parse(IReadOnlyList<String> Lines, IEnumerable<String>? TerminatorViolations = null)
    {

        var violations  = new List<String>(TerminatorViolations ?? []);
        var texts       = new List<String>();
        var code        = -1;
        String? first   = null;

        for (var i = 0; i < Lines.Count; i++)
        {

            var line    = Lines[i];
            var isLast  = i == Lines.Count - 1;

            if (line.Length < 3 || !line[..3].All(Char.IsAsciiDigit))
            {
                violations.Add($"line {i + 1} does not start with a three-digit code: \"{line}\"");
                texts.Add(line);
                continue;
            }

            var lineCode = line[..3];
            first ??= lineCode;

            if (lineCode != first)
                violations.Add($"line {i + 1} carries code {lineCode}, the reply began with {first} (RFC 5321 §4.2.1)");

            if (line.Length == 3)
            {
                if (!isLast)
                    violations.Add($"line {i + 1} has no separator but is not the last line");
                texts.Add("");
            }
            else
            {

                var separator = line[3];

                if (isLast && separator != ' ')
                    violations.Add($"last line has separator '{separator}', expected SP (RFC 5321 §4.2)");

                if (!isLast && separator != '-')
                    violations.Add($"line {i + 1} has separator '{separator}', expected '-' (RFC 5321 §4.2)");

                texts.Add(line[4..]);

            }

            if (isLast)
                code = Int32.Parse(lineCode);

        }

        // RFC 5321 §4.2: the first digit is 2-5, the second 0-5.
        if (code >= 0 && (code / 100 is < 2 or > 5 || code / 10 % 10 > 5))
            violations.Add($"reply code {code} is outside the RFC 5321 §4.2 grammar");

        return new SmtpReply(code, texts, [.. Lines], violations);

    }


    public override String ToString()
        => String.Join(" | ", RawLines);

}
