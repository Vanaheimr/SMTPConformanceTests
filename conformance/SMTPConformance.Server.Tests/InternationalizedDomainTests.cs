using System.Text.RegularExpressions;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// Internationalized domain names (IDNA, RFC 5890) where the server meets them: a domain of
/// an SMTPUTF8 transaction may come in U-labels ("bücher.test") or in A-labels
/// ("xn--bcher-kva.test"), and both are one domain. RFC 6531 §3.2: "Any domain name to be
/// looked up in the DNS MUST conform to and be processed as specified for Internationalizing
/// Domain Names in Applications (IDNA) [RFC5890]. When doing lookups, the SMTPUTF8-aware SMTP
/// client or server MUST either use a Unicode-aware DNS library, or transform the
/// internationalized domain name to A-label form". RFC 8616 says the same of SPF, DKIM and
/// DMARC: what is in the DNS is in A-labels.
/// </summary>
[TestFixture]
public sealed class InternationalizedDomainTests : HermodServerTestBase
{

    #region Setup

    private void Txt(String Name, String Text)
        => Server.Dns.Answer(Name, DNSResourceRecordTypes.TXT,
                             new TXT(DNSServiceName.Parse(Name), DNSQueryClasses.IN, TimeSpan.FromHours(1), Text));

    private static String Message(String From, String Marker)

        => $"From: <{From}>\r\n" +
           "To: <alice@hermod.test>\r\n" +
           $"Subject: {Marker}\r\n" +
           $"Message-ID: <{Guid.NewGuid():N}@client.example>\r\n" +
           "Date: Thu, 19 Nov 2026 10:00:00 +0000\r\n" +
           "\r\n" +
           "Hello.\r\n";

    /// <summary>
    /// One SMTPUTF8 transaction to alice: the reply to the end of data, the Authentication-Results
    /// of the message as stored if it was, and the wire transcript with the DNS queries.
    /// </summary>
    private async Task<(SmtpReply? Final, String Results, String Explanation)> Deliver(String MailFrom, String Message, String Marker)
    {

        await using var client = await Server.ConnectAndEhloAsync("mx.client.example");

        var mail = await client.CommandAsync($"MAIL FROM:<{MailFrom}> SMTPUTF8");
        var rcpt = await client.CommandAsync("RCPT TO:<alice@hermod.test>");
        Assert.That(mail.Code, Is.EqualTo(250), Explain(client));
        Assert.That(rcpt.Code, Is.EqualTo(250), Explain(client));

        var (_, final) = await client.DataAsync(Message);
        var stored     = final?.Code == 250 ? await Server.Storage.WaitForMarkerAsync(Marker) : null;

        var results    = stored is null
                             ? ""
                             : Regex.Match(stored.Raw, @"^Authentication-Results:(?<value>[^\r\n]*(?:\r\n[ \t][^\r\n]*)*)", RegexOptions.Multiline | RegexOptions.IgnoreCase) is { Success: true } match
                                   ? Regex.Replace(match.Groups["value"].Value.Replace("\r\n", ""), @"\s+", " ").Trim()
                                   : "";

        return (final, results, $"\nAuthentication-Results: {results}\nDNS queries: {Queries()}{Explain(client)}");

    }

    private String Queries()
        => String.Join(", ", Server.Dns.Queries.Select(query => $"{query.Name}/{query.Type}"));

    private static Boolean Says(String AuthenticationResults, String Result)
        => Regex.IsMatch(AuthenticationResults, $@"(^|[;\s]){Regex.Escape(Result)}([;\s]|$)", RegexOptions.IgnoreCase);

    #endregion


    #region V-23: SPF of a sender domain in U-labels

    // RFC 8616 §4: "An IDN in MAIL FROM can be either U-labels or A-labels. All U-labels MUST be
    // converted to A-labels before being used for an SPF validation. This includes both the
    // labels in the name used for the original DNS lookup, described in Section 3 of [RFC7208],
    // and those used in the macro expansion of domain-spec, described in Section 7."

    [Test(Description = "RFC 8616 §4: MAIL FROM in U-labels - the SPF record is the A-label's, and it passes the client it lists")]
    [Property("Finding", "V-23")]
    public async Task SPF_of_a_sender_domain_in_U_labels_is_the_record_of_its_A_labels()
    {

        Txt("pass.xn--bcher-kva.test", "v=spf1 ip4:127.0.0.1 -all");

        var marker = Marker();
        var (final, results, explanation) = await Deliver("news@pass.bücher.test", Message("news@client.example", marker), marker);

        Assert.Multiple(() => {
            Assert.That(final?.Code,               Is.EqualTo(250), explanation);
            Assert.That(Says(results, "spf=pass"),  Is.True,         explanation);
        });

    }


    [Test(Description = "RFC 8616 §4, RFC 7208 §8.4: MAIL FROM in U-labels, from a client its A-label's record does not list (-all) - SPF fails, as it does for the A-labels, and is not \"none\"")]
    [Property("Finding", "V-23")]
    public async Task SPF_fail_of_a_sender_domain_in_U_labels_is_not_lost()
    {

        Txt("fail.xn--bcher-kva.test", "v=spf1 -all");

        var marker = Marker();
        var (final, results, explanation) = await Deliver("news@fail.bücher.test", Message("news@client.example", marker), marker);

        Assert.That(final?.Class == 5 || Says(results, "spf=fail"), Is.True, explanation);

    }


    [Test(Description = "RFC 8616 §4: the U-labels of %{d} are A-labels in the macro expansion too - a:%{d} is the A record of the A-labels")]
    [Property("Finding", "V-23")]
    public async Task The_macro_of_a_sender_domain_in_U_labels_expands_to_A_labels()
    {

        Txt("macro.xn--bcher-kva.test", "v=spf1 a:%{d} -all");
        Server.Dns.Answer("macro.xn--bcher-kva.test", DNSResourceRecordTypes.A,
                          new A(DomainName.Parse("macro.xn--bcher-kva.test"), DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("127.0.0.1")));

        var marker = Marker();
        var (final, results, explanation) = await Deliver("news@macro.bücher.test", Message("news@client.example", marker), marker);

        Assert.Multiple(() => {
            Assert.That(final?.Code,               Is.EqualTo(250), explanation);
            Assert.That(Says(results, "spf=pass"),  Is.True,         explanation);
        });

    }


    [Test(Description = "RFC 7208 §4: MAIL FROM in A-labels - the record is found and passes (a guard)")]
    [Property("Finding", "V-23")]
    public async Task SPF_of_a_sender_domain_in_A_labels_passes()
    {

        Txt("guard.xn--bcher-kva.test", "v=spf1 ip4:127.0.0.1 -all");

        var marker = Marker();
        var (final, results, explanation) = await Deliver("news@guard.xn--bcher-kva.test", Message("news@client.example", marker), marker);

        Assert.That(Says(results, "spf=pass"), Is.True, explanation);

    }

    #endregion

    #region V-24: DKIM, d= in U-labels

    // RFC 8616 §5: in internationalized message header fields "IDNs SHOULD be represented as
    // U-labels" in d=, i= and s=, and RFC 8616 §3: "When a domain name found in a mail header
    // field includes U-labels, those labels are translated to A-labels before being looked up
    // in the DNS, as described in [RFC5891]."

    [Test(Description = "RFC 8616 §5, §3: a signature with d= in U-labels - its key is the record at selector._domainkey of the A-labels, and the signature passes")]
    [Property("Finding", "V-24")]
    public async Task A_signature_with_d_in_U_labels_is_verified_with_the_key_of_its_A_labels()
    {

        using var key = new TestDkimKey("sig.bücher.test");
        Server.Dns.Answer("test._domainkey.sig.xn--bcher-kva.test", DNSResourceRecordTypes.TXT, key.Record());

        var marker = Marker();
        var (final, results, explanation) = await Deliver("news@client.example", key.Sign(Message("ceo@sig.bücher.test", marker)), marker);

        Assert.Multiple(() => {
            Assert.That(final?.Code,                Is.EqualTo(250), explanation);
            Assert.That(Says(results, "dkim=pass"),  Is.True,         explanation);
        });

    }


    [Test(Description = "RFC 6376 §3.5: a signature with d= in A-labels on an internationalized message passes (a guard)")]
    [Property("Finding", "V-24")]
    public async Task A_signature_with_d_in_A_labels_on_an_internationalized_message_passes()
    {

        using var key = new TestDkimKey("asig.xn--bcher-kva.test");
        Server.Dns.Answer(key.RecordName, DNSResourceRecordTypes.TXT, key.Record());

        var marker = Marker();
        var (_, results, explanation) = await Deliver("news@client.example", key.Sign(Message("ceo@asig.bücher.test", marker)), marker);

        Assert.That(Says(results, "dkim=pass"), Is.True, explanation);

    }

    #endregion

    #region V-25: DMARC of an author domain in U-labels

    // RFC 8616 §6: RFC 7489 §6.6.1 "is updated to say that all U-labels in the domain are
    // converted to A-labels before further processing."

    [Test(Description = "RFC 8616 §6, RFC 7489 §6.6.3: the policy of an author domain in U-labels is the record of its A-labels - its p=reject is applied, not the p=none of the organizational domain")]
    [Property("Finding", "V-25")]
    public async Task The_policy_of_an_author_domain_in_U_labels_is_the_record_of_its_A_labels()
    {

        Txt("_dmarc.shop.xn--bcher-kva.test", "v=DMARC1; p=reject");
        Txt("_dmarc.xn--bcher-kva.test",      "v=DMARC1; p=none");

        var marker = Marker();
        var (final, results, explanation) = await Deliver("news@client.example", Message("ceo@shop.bücher.test", marker), marker);

        Assert.That(final?.Class, Is.EqualTo(5), "an unauthenticated author domain with p=reject" + explanation);

    }


    [Test(Description = "RFC 8616 §6, RFC 7489 §3.1.1: strict alignment compares the author domain in A-labels - a signature of the same domain in A-labels is aligned, and DMARC passes")]
    [Property("Finding", "V-25")]
    public async Task Strict_alignment_compares_an_author_domain_in_U_labels_by_its_A_labels()
    {

        Txt("_dmarc.strict.xn--bcher-kva.test", "v=DMARC1; p=reject; adkim=s");

        using var key = new TestDkimKey("strict.xn--bcher-kva.test");
        Server.Dns.Answer(key.RecordName, DNSResourceRecordTypes.TXT, key.Record());

        var marker = Marker();
        var (final, results, explanation) = await Deliver("news@client.example", key.Sign(Message("ceo@strict.bücher.test", marker)), marker);

        Assert.Multiple(() => {
            Assert.That(final?.Code,                 Is.EqualTo(250), explanation);
            Assert.That(Says(results, "dmarc=pass"),  Is.True,         explanation);
        });

    }


    [Test(Description = "RFC 7489 §6.6.3: the policy of the organizational domain applies to an author domain in U-labels without its own (a guard)")]
    [Property("Finding", "V-25")]
    public async Task The_organizational_policy_applies_to_an_author_domain_in_U_labels()
    {

        Txt("_dmarc.xn--bcher-kva.test", "v=DMARC1; p=reject");

        var marker = Marker();
        var (final, _, explanation) = await Deliver("news@client.example", Message("ceo@org.bücher.test", marker), marker);

        Assert.That(final?.Class, Is.EqualTo(5), explanation);

    }

    #endregion

    #region S-35: a local domain in the other form

    public static IEnumerable<TestCaseData> LocalDomainForms()
    {

        // RFC 6531 §3.7: "When RFC 5321 specifies a domain name, the internationalized domain name
        // SHOULD be in U-label form if the SMTPUTF8 extension is supported; otherwise, it SHOULD be
        // in A-label form." A client that follows it writes the U-labels with SMTPUTF8 and the
        // A-labels without - of the same domain.
        yield return new TestCaseData("xn--bcher-kva.test", "alice@bücher.test",        true)
                         .SetName("The local domain xn--bcher-kva.test, RCPT in U-labels with SMTPUTF8")
                         .SetProperty("Finding", "S-35");

        yield return new TestCaseData("bücher.test",        "alice@xn--bcher-kva.test", false)
                         .SetName("The local domain bücher.test, RCPT in A-labels without SMTPUTF8")
                         .SetProperty("Finding", "S-35");

        yield return new TestCaseData("xn--bcher-kva.test", "alice@xn--bcher-kva.test", false)
                         .SetName("The local domain xn--bcher-kva.test, RCPT in A-labels (a guard)")
                         .SetProperty("Finding", "S-35");

    }


    [TestCaseSource(nameof(LocalDomainForms))]
    [Description("RFC 5890 §2.3.2.1, RFC 6531 §3.7: a domain in U-labels and in A-labels is one domain - a recipient of a local domain in either form is local, delivered here, not refused as relaying")]
    public async Task A_recipient_of_a_local_domain_in_either_form_is_local(String LocalDomain, String Recipient, Boolean SmtpUtf8)
    {

        await using var server = await HermodSmtpServerFixture.StartAsync(new() { LocalDomains = [ LocalDomain, "hermod.test" ] });
        await using var client = await server.ConnectAndEhloAsync("mx.client.example");

        var marker = Marker();
        var mail   = await client.CommandAsync("MAIL FROM:<news@client.example>" + (SmtpUtf8 ? " SMTPUTF8" : ""));
        var rcpt   = await client.CommandAsync($"RCPT TO:<{Recipient}>");

        Assert.That(rcpt.Code, Is.EqualTo(250), $"MAIL: {mail}" + Explain(client));

        var (_, final) = await client.DataAsync(Message("news@client.example", marker));
        var stored     = final?.Code == 250 ? await server.Storage.WaitForMarkerAsync(marker) : null;

        Assert.That(stored, Is.Not.Null, "stored here, as a local recipient's" + Explain(client));

    }

    #endregion

}


/// <summary>
/// A server whose name is an internationalized domain name.
/// </summary>
[TestFixture]
public sealed class InternationalizedHostnameTests : HermodServerTestBase
{

    protected override HermodSmtpServerFixtureOptions Options
        => new() { Hostname = "mx.bücher.test" };

    #region S-36: the server's name in the greeting and in the reply to EHLO

    [Test(Description = "RFC 6531 §3.7.1: \"If the SMTPUTF8-aware SMTP server provides domain names in the EHLO response, they MUST be in the form of LDH labels or A-labels\"; RFC 5321 §4.2 - the greeting's Domain, which the client reads before it knows of SMTPUTF8, is ASCII too")]
    [Property("Finding", "S-36")]
    public async Task The_server_names_itself_in_A_labels_in_its_greeting_and_its_reply_to_EHLO()
    {

        var (client, greeting) = await Server.ConnectMtaAsync();
        await using var _ = client;

        var (ehlo, _) = await client.EhloAsync("client.example");

        // The first word after the code: greeting = "220 " ( Domain / address-literal ) ...,
        // ehlo-ok-rsp = "250" SP Domain ... or "250-" Domain ... (RFC 5321 §4.2, §4.1.1.1).
        var greetingDomain = greeting.Text.Split(' ')[0];
        var ehloDomain     = ehlo.Text.Split(' ')[0];

        Assert.Multiple(() => {
            Assert.That(greetingDomain, Is.EqualTo("mx.xn--bcher-kva.test"), Explain(client));
            Assert.That(ehloDomain,     Is.EqualTo("mx.xn--bcher-kva.test"), Explain(client));
        });

    }

    #endregion


    #region S-47: the server's name in the Received field of an SMTPUTF8 transaction

    private async Task<(String? By, String Explanation)> ReceivedBy(String MailParameters)
    {

        await using var client = await Server.ConnectAndEhloAsync();
        var marker = Marker();

        var mail  = await client.CommandAsync($"MAIL FROM:<sender@client.example>{MailParameters}");
        var rcpt  = await client.CommandAsync("RCPT TO:<alice@hermod.test>");
        Assume.That(mail.Code, Is.EqualTo(250), Explain(client));
        Assume.That(rcpt.Code, Is.EqualTo(250), Explain(client));

        var (_, final) = await client.DataAsync(RawSmtpClientExtensions.Message("sender@client.example", "alice@hermod.test", marker, "hello"));
        Assume.That(final?.Code, Is.EqualTo(250), Explain(client));

        var stored = await Server.Storage.WaitForMarkerAsync(marker);

        if (stored is null)
            return (null, Explain(client));

        // The topmost Received field - this server's - unfolded; its "by" clause.
        var end      = stored.Raw.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var received = Regex.Split(end >= 0 ? stored.Raw[..end] : stored.Raw, "\r\n(?![ \t])").
                           FirstOrDefault(field => field.StartsWith("Received:", StringComparison.OrdinalIgnoreCase));
        var by       = received is null ? null : Regex.Match(Regex.Replace(received, "\r\n[ \t]+", " "), @"\sby\s+(?<by>[^\s;]+)");

        return (by is { Success: true } ? by.Groups["by"].Value : null, Explain(client));

    }

    [Test(Description = "RFC 6531 §3.7.3: \"When an SMTPUTF8-aware SMTP server adds a trace field to a message that was or will be transmitted with the SMTPUTF8 parameter included in the MAIL commands, that server SHOULD use the U-label form for internationalized domain names in the new trace field\"")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-47")]
    public async Task In_an_SMTPUTF8_transaction_the_server_names_itself_in_U_labels_in_the_Received_field()
    {

        var (by, explanation) = await ReceivedBy(" SMTPUTF8");

        Assert.That(by, Is.EqualTo("mx.bücher.test"), explanation);

    }

    [Test(Description = "RFC 6531 §3.7.3: \"If the messages that include trace fields are sent ... without the SMTPUTF8 parameter included in the MAIL commands, trace field values must conform to RFC 5321\" - A-labels (S-36), a guard")]
    [Property("Finding", "S-47")]
    public async Task Without_SMTPUTF8_the_server_names_itself_in_A_labels_in_the_Received_field()
    {

        var (by, explanation) = await ReceivedBy("");

        Assert.That(by, Is.EqualTo("mx.xn--bcher-kva.test"), explanation);

    }

    #endregion

}
