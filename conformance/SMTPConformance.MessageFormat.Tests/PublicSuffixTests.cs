using System.Globalization;
using System.Net;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core.Fixtures;

namespace SMTPConformance.MessageFormat.Tests;

/// <summary>
/// The Public Suffix List algorithm (https://github.com/publicsuffix/list/wiki/Format, "Formal
/// algorithm": rules, wildcards, exceptions, the default rule "*", both divisions) as
/// <see cref="PublicSuffixList"/> runs it over its embedded copy of the list, checked with the
/// list's own test vectors; and RFC 7489 §3.2, the Organizational Domain DMARC builds on it, as
/// <see cref="DNSVerifier"/> uses it for relaxed alignment (§3.1) and for the record of the
/// Organizational Domain (§6.6.3) - with messages signed by the suite's own DKIM signer.
/// </summary>
[TestFixture]
public sealed class PublicSuffixTests
{

    #region The list's own test vectors

    /// <summary>
    /// checkPublicSuffix(input, registrable domain) from
    /// https://raw.githubusercontent.com/publicsuffix/list/master/tests/test_psl.txt
    /// ("Any copyright is dedicated to the Public Domain",
    /// https://creativecommons.org/publicdomain/zero/1.0/), fetched 2026-11-20 - all of them but
    /// the "local" cases the file itself comments out. The vectors give the registrable domain
    /// of a U-label input in U-labels; Hermod gives A-labels throughout ("Both the list entries
    /// and the queried names are normalised to A-labels"), and the algorithm compares
    /// "canonicalized in the normal way for hostnames - lower-case, Punycode (RFC 3492)", so the
    /// test compares A-labels.
    /// </summary>
    public static IEnumerable<TestCaseData> TestPsl()
    {

        TestCaseData Check(String? Domain, String? Registrable, String Group)
            => new TestCaseData(Domain, Registrable).SetArgDisplayNames(Group, Domain ?? "null");

        // null input.
        yield return Check(null, null, "null input");
        // Mixed case.
        yield return Check("COM", null, "mixed case");
        yield return Check("example.COM", "example.com", "mixed case");
        yield return Check("WwW.example.COM", "example.com", "mixed case");
        // Leading dot.
        yield return Check(".com", null, "leading dot");
        yield return Check(".example", null, "leading dot");
        yield return Check(".example.com", null, "leading dot");
        yield return Check(".example.example", null, "leading dot");
        // Unlisted TLD.
        yield return Check("example", null, "unlisted TLD");
        yield return Check("example.example", "example.example", "unlisted TLD");
        yield return Check("b.example.example", "example.example", "unlisted TLD");
        yield return Check("a.b.example.example", "example.example", "unlisted TLD");
        // TLD with only 1 rule.
        yield return Check("biz", null, "TLD with one rule");
        yield return Check("domain.biz", "domain.biz", "TLD with one rule");
        yield return Check("b.domain.biz", "domain.biz", "TLD with one rule");
        yield return Check("a.b.domain.biz", "domain.biz", "TLD with one rule");
        // TLD with some 2-level rules.
        yield return Check("com", null, "2-level rules");
        yield return Check("example.com", "example.com", "2-level rules");
        yield return Check("b.example.com", "example.com", "2-level rules");
        yield return Check("a.b.example.com", "example.com", "2-level rules");
        yield return Check("uk.com", null, "2-level rules");
        yield return Check("example.uk.com", "example.uk.com", "2-level rules");
        yield return Check("b.example.uk.com", "example.uk.com", "2-level rules");
        yield return Check("a.b.example.uk.com", "example.uk.com", "2-level rules");
        yield return Check("test.ac", "test.ac", "2-level rules");
        // TLD with only 1 (wildcard) rule.
        yield return Check("mm", null, "wildcard only");
        yield return Check("c.mm", null, "wildcard only");
        yield return Check("b.c.mm", "b.c.mm", "wildcard only");
        yield return Check("a.b.c.mm", "b.c.mm", "wildcard only");
        // More complex TLD.
        yield return Check("jp", null, "complex TLD");
        yield return Check("test.jp", "test.jp", "complex TLD");
        yield return Check("www.test.jp", "test.jp", "complex TLD");
        yield return Check("ac.jp", null, "complex TLD");
        yield return Check("test.ac.jp", "test.ac.jp", "complex TLD");
        yield return Check("www.test.ac.jp", "test.ac.jp", "complex TLD");
        yield return Check("kyoto.jp", null, "complex TLD");
        yield return Check("test.kyoto.jp", "test.kyoto.jp", "complex TLD");
        yield return Check("ide.kyoto.jp", null, "complex TLD");
        yield return Check("b.ide.kyoto.jp", "b.ide.kyoto.jp", "complex TLD");
        yield return Check("a.b.ide.kyoto.jp", "b.ide.kyoto.jp", "complex TLD");
        yield return Check("c.kobe.jp", null, "complex TLD");
        yield return Check("b.c.kobe.jp", "b.c.kobe.jp", "complex TLD");
        yield return Check("a.b.c.kobe.jp", "b.c.kobe.jp", "complex TLD");
        yield return Check("city.kobe.jp", "city.kobe.jp", "complex TLD");
        yield return Check("www.city.kobe.jp", "city.kobe.jp", "complex TLD");
        // TLD with a wildcard rule and exceptions.
        yield return Check("ck", null, "wildcard and exception");
        yield return Check("test.ck", null, "wildcard and exception");
        yield return Check("b.test.ck", "b.test.ck", "wildcard and exception");
        yield return Check("a.b.test.ck", "b.test.ck", "wildcard and exception");
        yield return Check("www.ck", "www.ck", "wildcard and exception");
        yield return Check("www.www.ck", "www.ck", "wildcard and exception");
        // US K12.
        yield return Check("us", null, "US K12");
        yield return Check("test.us", "test.us", "US K12");
        yield return Check("www.test.us", "test.us", "US K12");
        yield return Check("ak.us", null, "US K12");
        yield return Check("test.ak.us", "test.ak.us", "US K12");
        yield return Check("www.test.ak.us", "test.ak.us", "US K12");
        yield return Check("k12.ak.us", null, "US K12");
        yield return Check("test.k12.ak.us", "test.k12.ak.us", "US K12");
        yield return Check("www.test.k12.ak.us", "test.k12.ak.us", "US K12");
        // IDN labels.
        yield return Check("食狮.com.cn", "食狮.com.cn", "IDN");
        yield return Check("食狮.公司.cn", "食狮.公司.cn", "IDN");
        yield return Check("www.食狮.公司.cn", "食狮.公司.cn", "IDN");
        yield return Check("shishi.公司.cn", "shishi.公司.cn", "IDN");
        yield return Check("公司.cn", null, "IDN");
        yield return Check("食狮.中国", "食狮.中国", "IDN");
        yield return Check("www.食狮.中国", "食狮.中国", "IDN");
        yield return Check("shishi.中国", "shishi.中国", "IDN");
        yield return Check("中国", null, "IDN");
        // Same as above, but punycoded.
        yield return Check("xn--85x722f.com.cn", "xn--85x722f.com.cn", "punycode");
        yield return Check("xn--85x722f.xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn", "punycode");
        yield return Check("www.xn--85x722f.xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn", "punycode");
        yield return Check("shishi.xn--55qx5d.cn", "shishi.xn--55qx5d.cn", "punycode");
        yield return Check("xn--55qx5d.cn", null, "punycode");
        yield return Check("xn--85x722f.xn--fiqs8s", "xn--85x722f.xn--fiqs8s", "punycode");
        yield return Check("www.xn--85x722f.xn--fiqs8s", "xn--85x722f.xn--fiqs8s", "punycode");
        yield return Check("shishi.xn--fiqs8s", "shishi.xn--fiqs8s", "punycode");
        yield return Check("xn--fiqs8s", null, "punycode");

    }

    private static readonly IdnMapping idn = new ();

    private static String? ALabels(String? Domain)
        => Domain is null ? null : idn.GetAscii(Domain);


    [TestCaseSource(nameof(TestPsl))]
    [Test(Description = "Public Suffix List, Formal algorithm: \"If no rules match, the prevailing rule is \"*\"\" ... \"If more than one rule matches, the prevailing rule is the one which is an exception rule\" ... \"the one with the most labels\" ... \"The registered or registrable domain is the public suffix plus one additional label\" - the list's own test vectors")]
    public void The_registrable_domain_is_the_one_the_list_test_vectors_give(String? Domain, String? Registrable)
    {
        Assert.That(PublicSuffixList.GetRegistrableDomain(Domain), Is.EqualTo(ALabels(Registrable)));
    }

    #endregion

    #region The embedded list

    [TestCase("pref.hokkaido.jp",          "pref.hokkaido.jp",    Description = "an exception to *.hokkaido.jp is a registrable domain itself")]
    [TestCase("www.city.kawasaki.jp",      "city.kawasaki.jp",    Description = "!city.kawasaki.jp")]
    [TestCase("a.b.kawasaki.jp",           "a.b.kawasaki.jp",     Description = "*.kawasaki.jp: b.kawasaki.jp is a public suffix")]
    [TestCase("news.example.co.uk",        "example.co.uk",       Description = "a two-label suffix under a ccTLD")]
    [TestCase("a.b.c.d.example.com",       "example.com",         Description = "RFC 7489 §3.2's own example")]
    [Test(Description = "Public Suffix List, Format: \"An exclamation mark (!) at the start of a rule marks an exception to a previous wildcard rule. An exception rule takes priority over any other matching rule\"; RFC 7489 §3.2: \"a subject domain of \"a.b.c.d.example.com\" would have an Organizational Domain of \"example.com\"\"")]
    public void Rules_of_the_ICANN_division_apply(String Domain, String Registrable)
    {
        Assert.That(PublicSuffixList.GetRegistrableDomain(Domain), Is.EqualTo(Registrable));
    }


    [TestCase("alice.github.io",           "alice.github.io")]
    [TestCase("www.alice.github.io",       "alice.github.io")]
    [TestCase("shop.myshopify.com",        "shop.myshopify.com")]
    [Test(Description = "Public Suffix List, Divisions: \"PRIVATE domains are amendments submitted by the domain holder, as an expression of how they operate their domain security policy\"; RFC 7489 §3.2: the list is \"a list of DNS domain names reserved for registrations\" - the PRIVATE division counts, so two tenants of github.io are two organizations")]
    public void Rules_of_the_PRIVATE_division_apply(String Domain, String Registrable)
    {
        Assert.That(PublicSuffixList.GetRegistrableDomain(Domain), Is.EqualTo(Registrable));
    }


    [TestCase("www.example.co.uk.")]
    [TestCase("WWW.Example.CO.UK")]
    [TestCase(" www.example.co.uk ")]
    [Test(Description = "Public Suffix List, Formal algorithm: \"The domain, as well as all rules from the Public Suffix List, must be canonicalized in the normal way for hostnames - lower-case\"; a trailing dot names the same DNS domain - the Organizational Domain of RFC 7489 §3.2 does not change with case or the root label")]
    public void Case_and_a_trailing_dot_do_not_change_the_organizational_domain(String Domain)
    {
        Assert.That(PublicSuffixList.GetOrganizationalDomain(Domain).TrimEnd('.'), Is.EqualTo("example.co.uk"));
    }


    [TestCase("co.uk")]
    [TestCase("com")]
    [TestCase("github.io")]
    [Test(Description = "RFC 7489 §3.2 step 4 prefixes \"the \"x+1\"th label from the subject domain\" - a public suffix has none, so it has no registrable domain; as an Organizational Domain it stands for itself")]
    public void A_public_suffix_has_no_registrable_domain(String Suffix)
    {

        Assert.Multiple(() => {
            Assert.That(PublicSuffixList.GetRegistrableDomain(Suffix),     Is.Null);
            Assert.That(PublicSuffixList.GetOrganizationalDomain(Suffix),  Is.EqualTo(Suffix));
        });

    }

    #endregion

    #region DMARC on it (RFC 7489 §3.1, §6.6.3)

    private const String Policy = "v=DMARC1; p=reject";

    private static TXT Txt(String Name, String Text)
        => new (DNSServiceName.Parse(Name), DNSQueryClasses.IN, TimeSpan.FromHours(1), Text);

    /// <summary>
    /// DMARC for a message from the author domain, signed by the suite with a key for the
    /// signing domain, with the given DMARC records published. No SPF record anywhere: only the
    /// signature can align.
    /// </summary>
    private static async Task<(DmarcResult Result, String? PolicyDomain, String Queries)> Dmarc(String  AuthorDomain,
                                                                                                String  SigningDomain,
                                                                                                params (String Domain, String Record)[] Records)
    {

        var dns = new StubDnsClient();

        foreach (var (domain, record) in Records)
            dns.Answer("_dmarc." + domain, DNSResourceRecordTypes.TXT, Txt("_dmarc." + domain, record));

        using var key = new TestDkimKey(SigningDomain);
        dns.Answer(key.RecordName, DNSResourceRecordTypes.TXT, key.Record());

        var message  = key.Sign($"From: <news@{AuthorDomain}>\r\n" +
                                "To: <bob@hermod.test>\r\n" +
                                "Subject: Organizational domain\r\n" +
                                $"Message-ID: <{Guid.NewGuid():N}@{SigningDomain}>\r\n" +
                                "Date: Fri, 20 Nov 2026 10:00:00 +0000\r\n" +
                                "\r\n" +
                                "Hello.\r\n");

        var verifier = new DNSVerifier(dns, new CapturingLogger());
        var result   = await verifier.VerifyAsync("bounces.unrelated.test", IPAddress.Parse("192.0.2.25"), "bounce@bounces.unrelated.test",
                                                  "mx.unrelated.test", EMailMessage.Parse(message));

        return (result.Dmarc, result.DmarcDetail?.PolicyDomain, String.Join(", ", dns.Queries.Select(q => $"{q.Name}/{q.Type}")));

    }


    [Test(Description = "RFC 7489 §3.1.1: \"In relaxed mode, the Organizational Domains of both the [DKIM]-authenticated signing domain (taken from the value of the \"d=\" tag in the signature) and that of the RFC5322.From domain must be equal\"; §6.6.3: without a record at the From domain, \"the Mail Receiver MUST query the DNS for a DMARC TXT record at the DNS domain matching the Organizational Domain\" - news.example.co.uk under example.co.uk")]
    public async Task A_subdomain_under_a_two_label_suffix_is_aligned_and_finds_the_record_of_its_organizational_domain()
    {

        var (result, policyDomain, queries) = await Dmarc("news.example.co.uk", "example.co.uk", ("example.co.uk", Policy));

        Assert.Multiple(() => {
            Assert.That(result,        Is.EqualTo(DmarcResult.Pass), queries);
            Assert.That(policyDomain,  Is.EqualTo("example.co.uk"),  queries);
            Assert.That(queries,       Does.Not.Contain("_dmarc.co.uk"), "co.uk is no Organizational Domain");
        });

    }


    [TestCase("example.co.uk",      "attacker.co.uk",      Description = "two registrants under co.uk")]
    [TestCase("bank.test.ck",       "attacker.test.ck",    Description = "*.ck: test.ck is a public suffix")]
    [TestCase("alice.github.io",    "mallory.github.io",   Description = "PRIVATE division: two tenants of github.io")]
    [Test(Description = "RFC 7489 §3.1.1: relaxed alignment needs equal Organizational Domains - a signature of another registrant under the same public suffix does not align, and DMARC fails")]
    public async Task A_signature_of_another_registrant_under_the_same_suffix_does_not_align(String Author, String Signer)
    {

        var (result, _, queries) = await Dmarc(Author, Signer, (Author, Policy));

        Assert.That(result, Is.EqualTo(DmarcResult.Fail), queries);

    }


    [Test(Description = "RFC 7489 §3.1.1: \"In strict mode, only an exact match between both of the Fully Qualified Domain Names (FQDNs) is considered to produce Identifier Alignment\" - adkim=s, a signature of the Organizational Domain does not align a subdomain")]
    public async Task Strict_alignment_does_not_use_the_organizational_domain()
    {

        var (result, _, queries) = await Dmarc("news.example.co.uk", "example.co.uk", ("example.co.uk", "v=DMARC1; p=reject; adkim=s"));

        Assert.That(result, Is.EqualTo(DmarcResult.Fail), queries);

    }


    [Test(Description = "RFC 7489 §6.6.3: \"If the set is now empty, the Mail Receiver MUST query the DNS for a DMARC TXT record at the DNS domain matching the Organizational Domain in place of the RFC5322.From domain\" - for a domain under a wildcard rule, the Organizational Domain is three labels deep (*.ck makes test.ck a public suffix)")]
    public async Task The_record_of_an_organizational_domain_under_a_wildcard_is_found()
    {

        var (result, policyDomain, queries) = await Dmarc("mail.shop.test.ck", "shop.test.ck", ("shop.test.ck", Policy));

        Assert.Multiple(() => {
            Assert.That(result,        Is.EqualTo(DmarcResult.Pass),  queries);
            Assert.That(policyDomain,  Is.EqualTo("shop.test.ck"),  queries);
        });

    }



    [Test(Description = "RFC 8616 §6: RFC 7489 §6.6.1 \"is updated to say that all U-labels in the domain are converted to A-labels before further processing\" - an author domain in U-labels aligns with a signature of its A-label form, under the record published for the A-labels")]
    public async Task An_author_domain_in_U_labels_aligns_with_its_A_labels()
    {

        var (result, policyDomain, queries) = await Dmarc("news.食狮.中国", "xn--85x722f.xn--fiqs8s", ("xn--85x722f.xn--fiqs8s", Policy));

        Assert.Multiple(() => {
            Assert.That(result,        Is.EqualTo(DmarcResult.Pass),          queries);
            Assert.That(policyDomain,  Is.EqualTo("xn--85x722f.xn--fiqs8s"),  queries);
        });

    }

    #endregion

}
