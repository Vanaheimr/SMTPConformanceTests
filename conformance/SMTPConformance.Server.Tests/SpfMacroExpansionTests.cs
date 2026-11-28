using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 7208 §7: the macros of an SPF record as check_host() expands them in the records it
/// evaluates - not the examples of §7.4, which <c>SpfMacroTests</c> has, but the transformers
/// of §7.1 and §7.3, the delimiters of a domain-spec that has a prefix length after it, and
/// the "p" macro. Evaluated by <see cref="DNSVerifier.CheckSpfAsync"/>, the same evaluation the
/// server applies to the MAIL FROM and HELO identities, against the test's DNS: each record
/// names, by a macro, the name it looks up, and that name is published - check_host() passes
/// when the macro expands to it. The domain is email.macro.test, the client 192.0.2.25.
/// </summary>
[TestFixture]
public sealed class SpfMacroExpansionTests
{

    #region Setup

    private const String Domain         = "email.macro.test";
    private const String ClientAddress  = "192.0.2.25";

    private static TXT Txt(String Name, String Text)
        => new (DNSServiceName.Parse(Name), DNSQueryClasses.IN, TimeSpan.FromHours(1), Text);

    private static A Address(String Name, String Address)
        => new (DomainName.Parse(Name), DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse(Address));

    private static MX Mx(String Name, UInt16 Preference, String Host)
        => new (DomainName.Parse(Name), DNSQueryClasses.IN, TimeSpan.FromHours(1), Preference, DomainName.Parse(Host));

    /// <summary>
    /// A DNS that publishes the SPF record at email.macro.test, and an address at each name.
    /// </summary>
    private static StubDnsClient Publish(String Spf, params (String Name, String Address)[] Addresses)
    {

        var dns = new StubDnsClient();

        dns.Answer(Domain, DNSResourceRecordTypes.TXT, Txt(Domain, Spf));

        foreach (var (name, address) in Addresses)
            dns.Answer(name, DNSResourceRecordTypes.A, Address(name, address));

        return dns;

    }

    /// <summary>
    /// check_host() for email.macro.test and the client, and the DNS queries it made.
    /// </summary>
    private static async Task<(SPFResult Result, String Queries)> CheckHost(StubDnsClient Dns)
    {

        var (result, _) = await new DNSVerifier(Dns, new CapturingLogger()).CheckSpfAsync(Domain, System.Net.IPAddress.Parse(ClientAddress));

        return (result, "queries: " + String.Join(", ", Dns.Queries.Select(query => $"{query.Name}/{query.Type}")));

    }

    #endregion


    #region V-36: the transformers

    /// <summary>
    /// "exists:" the macro, and the name it expands to - null where the record is in error.
    /// </summary>
    private static TestCaseData Transformer(String Name, String Macro, String? Expanded, SPFResult Expected, String Finding)
        => new TestCaseData($"v=spf1 exists:{Macro}.check.macro.test -all", Expanded is null ? null : Expanded + ".check.macro.test", Expected)
               .SetName($"{Name}: {Macro}")
               .SetProperty("Finding", Finding);

    private static IEnumerable<TestCaseData> TransformersAsTheRfcHasThem()
    {

        const String Name = "A transformer is applied as the RFC has it";

        // transformers = *DIGIT [ "r" ], and ABNF strings are case-insensitive (RFC 5234 §2.3).
        yield return Transformer(Name, "%{dR}",                     "test.macro.email",  SPFResult.Pass,       "V-36");
        yield return Transformer(Name, "%{d2R}",                    "macro.email",       SPFResult.Pass,       "V-36");
        // "If a DIGIT is specified, the value MUST be nonzero."
        yield return Transformer(Name, "%{d0}",                     null,                SPFResult.PermError,  "V-36");
        // "if the value specifies more parts than are available, all the available parts are used."
        yield return Transformer(Name, "%{d99999999999999999999}",  Domain,              SPFResult.Pass,       "V-36");

    }


    [TestCaseSource(nameof(TransformersAsTheRfcHasThem))]
    [Description("RFC 7208 §7.1: transformers = *DIGIT [ \"r\" ], an ABNF string, which is case-insensitive (RFC 5234 §2.3); §7.3: \"If a DIGIT is specified, the value MUST be nonzero. If no DIGITs are specified, or if the value specifies more parts than are available, all the available parts are used\"")]
    public async Task A_transformer_is_applied_as_the_rfc_has_it(String Record, String? Expanded, SPFResult Expected)
    {

        var (result, queries) = await CheckHost(Expanded is null ? Publish(Record) : Publish(Record, (Expanded, "127.0.0.2")));

        Assert.That(result, Is.EqualTo(Expected), queries);

    }


    private static IEnumerable<TestCaseData> TransformersThatAreApplied()
    {

        const String Name = "A transformer is applied";

        yield return Transformer(Name, "%{dr}",    "test.macro.email",  SPFResult.Pass,  "V-36");
        yield return Transformer(Name, "%{d2}",    "macro.test",        SPFResult.Pass,  "V-36");
        // "Implementations MUST support at least a value of 127."
        yield return Transformer(Name, "%{d127}",  Domain,              SPFResult.Pass,  "V-36");

    }


    [TestCaseSource(nameof(TransformersThatAreApplied))]
    [Description("RFC 7208 §7.3: a lower-case r reverses, a DIGIT keeps that many right-hand parts, all of them where there are fewer - a guard for V-36")]
    public async Task A_transformer_is_applied(String Record, String Expanded, SPFResult Expected)
    {

        var (result, queries) = await CheckHost(Publish(Record, (Expanded, "127.0.0.2")));

        Assert.That(result, Is.EqualTo(Expected), queries);

    }

    #endregion

    #region V-37: "/" as a delimiter

    private static IEnumerable<TestCaseData> SlashesInTheDomainSpecOfAOrMx()
    {

        static TestCaseData Case(String Name, String Record, Action<StubDnsClient> Names)
            => new TestCaseData(Record, Names).SetName($"A \"/\" as delimiter in the domain-spec of a or mx is no syntax error: {Name}")
                                              .SetProperty("Finding", "V-37");

        yield return Case("a:%{d/}",       "v=spf1 a:%{d/}.a.macro.test -all",
                          dns => dns.Answer("email.macro.test.a.macro.test", DNSResourceRecordTypes.A, Address("email.macro.test.a.macro.test", ClientAddress)));

        yield return Case("a:%{d/}/24",    "v=spf1 a:%{d/}.a.macro.test/24 -all",
                          dns => dns.Answer("email.macro.test.a.macro.test", DNSResourceRecordTypes.A, Address("email.macro.test.a.macro.test", "192.0.2.1")));

        yield return Case("mx:%{d/}",      "v=spf1 mx:%{d/}.mx.macro.test -all",
                          dns => dns.Answer("email.macro.test.mx.macro.test", DNSResourceRecordTypes.MX, Mx("email.macro.test.mx.macro.test", 10, "mail.macro.test"))
                                    .Answer("mail.macro.test",                DNSResourceRecordTypes.A,  Address("mail.macro.test", ClientAddress)));

    }


    [TestCaseSource(nameof(SlashesInTheDomainSpecOfAOrMx))]
    [Description("RFC 7208 §5.3, §5.4: a = \"a\" [ \":\" domain-spec ] [ dual-cidr-length ], mx the same; §7.1: macro-expand = ( \"%{\" macro-letter transformers *delimiter \"}\" ), delimiter = \".\" / \"-\" / \"+\" / \",\" / \"/\" / \"_\" / \"=\" - a \"/\" within the braces is a delimiter, not the start of a prefix length")]
    public async Task A_slash_as_delimiter_in_the_domain_spec_of_a_or_mx_is_no_syntax_error(String Record, Action<StubDnsClient> Names)
    {

        var dns = Publish(Record);
        Names(dns);

        var (result, queries) = await CheckHost(dns);

        Assert.That(result, Is.EqualTo(SPFResult.Pass), queries);

    }


    [TestCase("v=spf1 exists:%{d/}.check.macro.test -all", "email.macro.test.check.macro.test", "127.0.0.2",  Description = "a \"/\" as delimiter in the domain-spec of exists")]
    [TestCase("v=spf1 a:%{d}.a.macro.test/24 -all",       "email.macro.test.a.macro.test",     "192.0.2.1",  Description = "a prefix length after a macro")]
    [Test(Description = "RFC 7208 §7.1: a \"/\" as delimiter where no prefix length can follow, and a prefix length after a macro without one - a guard for V-37")]
    [Property("Finding", "V-37")]
    public async Task A_slash_as_delimiter_in_exists_and_a_prefix_length_after_a_macro_are_read(String Record, String Name, String Address)
    {

        var (result, queries) = await CheckHost(Publish(Record, (Name, Address)));

        Assert.That(result, Is.EqualTo(SPFResult.Pass), queries);

    }

    #endregion

    #region V-38: the "p" macro

    /// <summary>
    /// The client's reverse name, mail.email.macro.test, and that name's address - the
    /// client's, when the name is to be validated.
    /// </summary>
    private static StubDnsClient Reverse(StubDnsClient Dns, String AddressOfName = ClientAddress)
    {

        Dns.Answer("25.2.0.192.in-addr.arpa", DNSResourceRecordTypes.PTR,
                   new PTR(DNSServiceName.Parse("25.2.0.192.in-addr.arpa"), DNSQueryClasses.IN, TimeSpan.FromHours(1), DNSServiceName.Parse("mail.email.macro.test")));
        Dns.Answer("mail.email.macro.test", DNSResourceRecordTypes.A, Address("mail.email.macro.test", AddressOfName));

        return Dns;

    }


    [Test(Description = "RFC 7208 §7.3: \"The \"p\" macro expands to the validated domain name of <ip>. The procedure for finding the validated domain name is defined in Section 5.5\" - the client's reverse name mail.email.macro.test has the client's address, and %{p} is that name")]
    [Property("Finding", "V-38")]
    public async Task The_p_macro_expands_to_the_validated_name_of_the_client()
    {

        var dns = Reverse(Publish("v=spf1 exists:%{p}.p.macro.test -all", ("mail.email.macro.test.p.macro.test", "127.0.0.2")));

        var (result, queries) = await CheckHost(dns);

        Assert.That(result, Is.EqualTo(SPFResult.Pass), queries);

    }


    [TestCase(false, Description = "the client has no reverse name")]
    [TestCase(true,  Description = "the client's reverse name does not have the client's address")]
    [Test(Description = "RFC 7208 §7.3: \"If there are no validated domain names or if a DNS error occurs, the string \"unknown\" is used\" - a guard for V-38")]
    [Property("Finding", "V-38")]
    public async Task The_p_macro_without_a_validated_name_expands_to_unknown(Boolean ReverseName)
    {

        var dns = Publish("v=spf1 exists:%{p}.p.macro.test -all", ("unknown.p.macro.test", "127.0.0.2"));
        if (ReverseName)
            Reverse(dns, AddressOfName: "192.0.2.99");

        var (result, queries) = await CheckHost(dns);

        Assert.That(result, Is.EqualTo(SPFResult.Pass), queries);

    }

    #endregion

}
