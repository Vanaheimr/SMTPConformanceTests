using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;

namespace SMTPConformance.MessageFormat.Tests;

/// <summary>
/// RFC 6376 §3.4: DKIM canonicalization, checked against the worked example of §3.4.5.
/// </summary>
[TestFixture]
public sealed class DkimCanonicalizationTests
{

    // RFC 6376 §3.4.5, with <SP>, <HTAB> and <CRLF> written out.
    private const String Headers = "A: X\r\n" +
                                   "B : Y\t\r\n" +
                                   "\tZ  \r\n";

    private const String Body    = " C \r\n" +
                                   "D \t E\r\n" +
                                   "\r\n" +
                                   "\r\n";


    [Test(Description = "RFC 6376 §3.4.5: relaxed header canonicalization yields \"a:X\" and \"b:Y Z\"")]
    public void Relaxed_headers_match_the_rfc_example()
    {

        var fields = DkimCanonicalization.ParseFields(Headers.TrimEnd('\r', '\n'));

        Assert.That(fields.Select(f => DkimCanonicalization.CanonicalizeHeader(f, "relaxed")),
                    Is.EqualTo(new[] { "a:X", "b:Y Z" }));

    }


    [Test(Description = "RFC 6376 §3.4.5: simple header canonicalization leaves the fields exactly as they were")]
    public void Simple_headers_match_the_rfc_example()
    {

        var fields = DkimCanonicalization.ParseFields(Headers.TrimEnd('\r', '\n'));

        Assert.That(String.Concat(fields.Select(f => DkimCanonicalization.CanonicalizeHeader(f, "simple") + "\r\n")),
                    Is.EqualTo(Headers));

    }


    [Test(Description = "RFC 6376 §3.4.5: relaxed body canonicalization yields \" C<CRLF>D E<CRLF>\"")]
    public void Relaxed_body_matches_the_rfc_example()
    {
        Assert.That(DkimCanonicalization.CanonicalizeBody(Body, "relaxed"), Is.EqualTo(" C\r\nD E\r\n"));
    }


    [Test(Description = "RFC 6376 §3.4.5: simple body canonicalization only drops the trailing empty lines")]
    public void Simple_body_matches_the_rfc_example()
    {
        Assert.That(DkimCanonicalization.CanonicalizeBody(Body, "simple"), Is.EqualTo(" C \r\nD \t E\r\n"));
    }


    [Test(Description = "RFC 6376 §3.4.3: an empty body canonicalizes to a single CRLF under \"simple\"")]
    public void Simple_empty_body_is_one_crlf()
    {
        Assert.That(DkimCanonicalization.CanonicalizeBody("", "simple"), Is.EqualTo("\r\n"));
    }


    [Test(Description = "RFC 6376 §3.4.4: an empty body canonicalizes to the empty string under \"relaxed\"")]
    public void Relaxed_empty_body_is_empty()
    {
        Assert.That(DkimCanonicalization.CanonicalizeBody("", "relaxed"), Is.Empty);
    }

}
