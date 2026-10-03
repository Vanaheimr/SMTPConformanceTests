using System.Net;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;

namespace SMTPConformance.MessageFormat.Tests;

/// <summary>
/// RFC 7208 §7.4: the macro expansion examples, for sender strong-bad@email.example.com
/// connecting from 192.0.2.3 or 2001:db8::cb01.
/// </summary>
[TestFixture]
public sealed class SpfMacroTests
{

    private static readonly SpfMacroContext context = new(Sender:       "strong-bad@email.example.com",
                                                          LocalPart:    "strong-bad",
                                                          SenderDomain: "email.example.com",
                                                          HeloDomain:   "mx.example.org");

    public static IEnumerable<TestCaseData> Ipv4Examples()
    {

        TestCaseData Case(String macro, String expected)
            => new TestCaseData(macro, expected).SetName($"RFC 7208 §7.4 (IPv4): {macro}");

        yield return Case("%{s}",                               "strong-bad@email.example.com");
        yield return Case("%{o}",                               "email.example.com");
        yield return Case("%{d}",                               "email.example.com");
        yield return Case("%{d4}",                              "email.example.com");
        yield return Case("%{d3}",                              "email.example.com");
        yield return Case("%{d2}",                              "example.com");
        yield return Case("%{d1}",                              "com");
        yield return Case("%{dr}",                              "com.example.email");
        yield return Case("%{d2r}",                             "example.email");
        yield return Case("%{l}",                               "strong-bad");
        yield return Case("%{l-}",                              "strong.bad");
        yield return Case("%{lr}",                              "strong-bad");
        yield return Case("%{lr-}",                             "bad.strong");
        yield return Case("%{l1r-}",                            "strong");
        yield return Case("%{ir}.%{v}._spf.%{d2}",              "3.2.0.192.in-addr._spf.example.com");
        yield return Case("%{lr-}.lp._spf.%{d2}",               "bad.strong.lp._spf.example.com");
        yield return Case("%{lr-}.lp.%{ir}.%{v}._spf.%{d2}",    "bad.strong.lp.3.2.0.192.in-addr._spf.example.com");
        yield return Case("%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}",   "3.2.0.192.in-addr.strong.lp._spf.example.com");
        yield return Case("%{d2}.trusted-domains.example.net",  "example.com.trusted-domains.example.net");

    }


    [TestCaseSource(nameof(Ipv4Examples))]
    public void Ipv4_examples_expand_as_in_the_rfc(String Macro, String Expected)
    {
        Assert.That(SpfMacros.Expand(Macro, "email.example.com", IPAddress.Parse("192.0.2.3"), context), Is.EqualTo(Expected));
    }


    [Test(Description = "RFC 7208 §7.4 (IPv6): %{ir}.%{v}._spf.%{d2} expands the address nibble by nibble under ip6")]
    public void Ipv6_example_expands_as_in_the_rfc()
    {
        Assert.That(SpfMacros.Expand("%{ir}.%{v}._spf.%{d2}", "email.example.com", IPAddress.Parse("2001:db8::cb01"), context),
                    Is.EqualTo("1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com"));
    }

}
