using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;

namespace SMTPConformance.MessageFormat.Tests;

/// <summary>
/// RFC 5322 §3.4 address syntax, checked with the examples of RFC 5322 Appendix A.
/// The server uses <see cref="MailAddressParser"/> to find the RFC5322.From domain
/// for DMARC alignment, so a mis-parse here is a mis-aligned policy decision there.
/// </summary>
[TestFixture]
public sealed class AddressParsingTests
{

    public static IEnumerable<TestCaseData> Appendix_A()
    {

        TestCaseData Case(String section, String header, params String[] expected)
            => new TestCaseData(header, expected).SetName($"RFC 5322 {section}: {header.Replace("\r\n", " ")}");

        yield return Case("A.1.1", "John Doe <jdoe@machine.example>",                                         "jdoe@machine.example");
        yield return Case("A.1.2", "\"Joe Q. Public\" <john.q.public@example.com>",                           "john.q.public@example.com");
        yield return Case("A.1.2", "Mary Smith <mary@x.test>, jdoe@example.org, Who? <one@y.test>",            "mary@x.test", "jdoe@example.org", "one@y.test");
        yield return Case("A.1.2", "<boss@nil.test>, \"Giant; \\\"Big\\\" Box\" <sysservices@example.net>",   "boss@nil.test", "sysservices@example.net");
        yield return Case("A.1.3", "A Group:Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>;",         "c@a.test", "joe@where.test", "jdoe@one.test");
        yield return Case("A.1.3", "Undisclosed recipients:;");
        yield return Case("A.5",   "Pete(A nice \\) chap) <pete(his account)@silly.test(his host)>",          "pete@silly.test");
        yield return Case("A.5",   "A Group(Some people)\r\n     :Chris Jones <c@(Chris's host.)public.example>,\r\n         joe@example.org,\r\n  John <jdoe@one.test> (my dear friend); (the end of the group)",
                                                                                                               "c@public.example", "joe@example.org", "jdoe@one.test");
        yield return Case("§3.4.1", "jdoe@[192.168.0.1]",                                                      "jdoe@[192.168.0.1]");

    }


    [TestCaseSource(nameof(Appendix_A))]
    public void Addr_specs_are_extracted(String Header, String[] Expected)
    {
        Assert.That(MailAddressParser.ParseAddressList(Header), Is.EqualTo(Expected));
    }

}
