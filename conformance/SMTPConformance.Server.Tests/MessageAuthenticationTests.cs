using System.Text.RegularExpressions;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC) and RFC 8601 (Authentication-Results)
/// on inbound mail: who the author is, which identity SPF checks, which signature DMARC
/// passes on, and what the receiver writes down about it. The messages are signed by the
/// suite's own DKIM signer, not by Hermod's.
/// </summary>
[TestFixture]
public sealed class MessageAuthenticationTests : HermodServerTestBase
{

    #region Setup

    /// <summary>
    /// Publish a domain's SPF and DMARC records in the test's DNS.
    /// </summary>
    private void Publish(String Domain, String? Spf = null, String? Dmarc = null)
    {

        if (Spf is not null)
            Server.Dns.Answer(Domain, DNSResourceRecordTypes.TXT,
                              new TXT(DNSServiceName.Parse(Domain), DNSQueryClasses.IN, TimeSpan.FromHours(1), Spf));

        if (Dmarc is not null)
            Server.Dns.Answer("_dmarc." + Domain, DNSResourceRecordTypes.TXT,
                              new TXT(DNSServiceName.Parse("_dmarc." + Domain), DNSQueryClasses.IN, TimeSpan.FromHours(1), Dmarc));

    }

    /// <summary>
    /// A DKIM key for the domain, its record published.
    /// </summary>
    private TestDkimKey KeyFor(String Domain, Boolean WithVersion = true)
    {
        var key = new TestDkimKey(Domain);
        Server.Dns.Answer(key.RecordName, DNSResourceRecordTypes.TXT, key.Record(WithVersion));
        return key;
    }

    /// <summary>
    /// A message from the given author header to alice, with a marker for its subject.
    /// </summary>
    private static String Message(String FromFields, String Marker)

        => FromFields +
           "To: <alice@hermod.test>\r\n" +
           $"Subject: {Marker}\r\n" +
           $"Message-ID: <{Guid.NewGuid():N}@client.example>\r\n" +
           "Date: Thu, 19 Nov 2026 10:00:00 +0000\r\n" +
           "\r\n" +
           "Hello.\r\n";

    /// <summary>
    /// One transaction to alice: the reply to the end of data, the message as stored if it
    /// was, and the wire transcript.
    /// </summary>
    private async Task<(SmtpReply? Final, StoredMessage? Stored, String Explanation)> Deliver(String  Helo,
                                                                                             String  MailFrom,
                                                                                             String  Message,
                                                                                             String  Marker)
    {

        await using var client = await Server.ConnectAndEhloAsync(Helo);

        var (mail, rcpts) = await client.EnvelopeAsync(MailFrom, "alice@hermod.test");
        Assert.That(mail.Code,      Is.EqualTo(250), Explain(client));
        Assert.That(rcpts[0].Code,  Is.EqualTo(250), Explain(client));

        var (_, final) = await client.DataAsync(Message);
        var stored     = final?.Code == 250 ? await Server.Storage.WaitForMarkerAsync(Marker) : null;

        return (final, stored, Explain(client));

    }

    /// <summary>
    /// The value of the topmost Authentication-Results field - this receiver's - unfolded.
    /// </summary>
    private static String AuthenticationResults(StoredMessage? Stored)
    {

        if (Stored is null)
            return "";

        var match = Regex.Match(Stored.Raw, @"^Authentication-Results:(?<value>[^\r\n]*(?:\r\n[ \t][^\r\n]*)*)", RegexOptions.Multiline | RegexOptions.IgnoreCase);

        return match.Success
                   ? Regex.Replace(match.Groups["value"].Value.Replace("\r\n", ""), @"\s+", " ").Trim()
                   : "";

    }

    private static Boolean Says(String AuthenticationResults, String Result)
        => Regex.IsMatch(AuthenticationResults, $@"(^|[;\s]){Regex.Escape(Result)}([;\s]|$)", RegexOptions.IgnoreCase);

    #endregion


    [Test(Description = "RFC 7489 §4.2: a valid DKIM signature of the author's own domain is aligned, and DMARC passes - a guard for the suite's DKIM signer and the tests below")]
    public async Task An_authors_aligned_signature_passes_DMARC()
    {

        Publish("guard.author.test", Dmarc: "v=DMARC1; p=reject");
        using var key = KeyFor("guard.author.test");

        var marker = Marker();
        var (final, stored, explanation) = await Deliver("mx.guard.author.test", "news@guard.author.test",
                                                         key.Sign(Message("From: <news@guard.author.test>\r\n", marker)), marker);
        var results = AuthenticationResults(stored);

        Assert.Multiple(() => {
            Assert.That(final?.Code,                Is.EqualTo(250),  explanation);
            Assert.That(Says(results, "dkim=pass"),  Is.True,          results);
            Assert.That(Says(results, "dmarc=pass"), Is.True,          results);
        });

    }


    [Test(Description = "RFC 6376 §3.6.1: the v= tag of a key record is \"RECOMMENDED, default is \"DKIM1\"\" - a key record without it is a key record")]
    [Property("Finding", "V-1")]
    public async Task A_key_record_without_a_version_tag_verifies()
    {

        Publish("noversion.author.test", Dmarc: "v=DMARC1; p=none");
        using var key = KeyFor("noversion.author.test", WithVersion: false);

        var marker = Marker();
        var (final, stored, explanation) = await Deliver("mx.noversion.author.test", "news@noversion.author.test",
                                                         key.Sign(Message("From: <news@noversion.author.test>\r\n", marker)), marker);
        var results = AuthenticationResults(stored);

        Assert.Multiple(() => {
            Assert.That(final?.Code,                Is.EqualTo(250),  explanation);
            Assert.That(Says(results, "dkim=pass"),  Is.True,          results);
        });

    }


    [Test(Description = "RFC 8301 §3.1: \"rsa-sha1 MUST NOT be used for signing or verifying\" - signatures with it \"have permanently failed evaluation\"")]
    [Category(TestCategories.KnownIssue), Property("Finding", "V-3")]
    public async Task A_signature_with_rsa_sha1_does_not_pass()
    {

        Publish("sha1.author.test", Dmarc: "v=DMARC1; p=none");
        using var key = KeyFor("sha1.author.test");

        var marker = Marker();
        var (final, stored, explanation) = await Deliver("mx.sha1.author.test", "news@sha1.author.test",
                                                         key.Sign(Message("From: <news@sha1.author.test>\r\n", marker), "rsa-sha1", false), marker);
        var results = AuthenticationResults(stored);

        Assert.Multiple(() => {
            Assert.That(final?.Code,                 Is.EqualTo(250),  explanation);
            Assert.That(Says(results, "dkim=pass"),   Is.False,         results);
            Assert.That(Says(results, "dmarc=pass"),  Is.False,         results);
        });

    }


    [Test(Description = "RFC 6376 §3.2: the tags of a tag-list come in any order; §3.7 - the b= value is removed wherever b= stands. A signature with b= first verifies")]
    [Category(TestCategories.KnownIssue), Property("Finding", "V-4")]
    public async Task A_signature_whose_b_tag_comes_first_verifies()
    {

        Publish("bfirst.author.test", Dmarc: "v=DMARC1; p=none");
        using var key = KeyFor("bfirst.author.test");

        var marker = Marker();
        var (final, stored, explanation) = await Deliver("mx.bfirst.author.test", "news@bfirst.author.test",
                                                         key.Sign(Message("From: <news@bfirst.author.test>\r\n", marker), "rsa-sha256", true), marker);
        var results = AuthenticationResults(stored);

        Assert.Multiple(() => {
            Assert.That(final?.Code,                Is.EqualTo(250),  explanation);
            Assert.That(Says(results, "dkim=pass"),  Is.True,          results);
        });

    }


    /// <summary>
    /// A message from the domain that fails DMARC: no SPF record, no signature.
    /// </summary>
    private async Task<(SmtpReply? Final, StoredMessage? Stored, String Explanation)> DeliverFailing(String Domain)
    {
        var marker = Marker();
        return await Deliver($"mx.{Domain}", $"news@{Domain}", Message($"From: <news@{Domain}>\r\n", marker), marker);
    }


    [Test(Description = "RFC 7489 §6.3: p=quarantine - a message that fails DMARC is taken and marked for quarantine (X-DMARC-Quarantine); a guard for how Hermod marks it")]
    public async Task A_message_failing_under_p_quarantine_is_quarantined()
    {

        Publish("quarantine.author.test", Dmarc: "v=DMARC1; p=quarantine");

        var (final, stored, explanation) = await DeliverFailing("quarantine.author.test");

        Assert.Multiple(() => {
            Assert.That(final?.Code,   Is.EqualTo(250),                          explanation);
            Assert.That(stored?.Raw,   Does.Contain("X-DMARC-Quarantine: true"), explanation);
        });

    }


    [Test(Description = "RFC 7489 §6.6.4: under p=reject, a message pct= does not select \"the Mail Receiver SHOULD treat the email as though the \"quarantine\" policy applies\" - with pct=0, every failing message")]
    [Category(TestCategories.KnownIssue), Property("Finding", "R-7")]
    public async Task Under_p_reject_with_pct_0_a_failing_message_is_quarantined()
    {

        Publish("pct0.author.test", Dmarc: "v=DMARC1; p=reject; pct=0");

        var (final, stored, explanation) = await DeliverFailing("pct0.author.test");

        Assert.Multiple(() => {
            Assert.That(final?.Code,   Is.EqualTo(250),                          explanation);
            Assert.That(stored?.Raw,   Does.Contain("X-DMARC-Quarantine: true"), "not quarantined, as if p=none " + explanation);
        });

    }


    [Test(Description = "RFC 5322 §3.6: one From: field, no more; RFC 7489 §6.6.1 - a second one must not let DMARC pass on the one while a reader is shown the other")]
    public async Task Two_From_fields_do_not_pass_DMARC_on_either()
    {

        Publish("victim.test",   Dmarc: "v=DMARC1; p=reject");
        Publish("attacker.test", Spf:   "v=spf1 ip4:127.0.0.1 -all", Dmarc: "v=DMARC1; p=none");
        using var key = KeyFor("attacker.test");

        // A reader shows the first; h=from signs the last (RFC 6376 §5.4.2), the attacker's own.
        var marker = Marker();
        var (final, stored, explanation) = await Deliver("mx.attacker.test", "me@attacker.test",
                                                         key.Sign(Message("From: <ceo@victim.test>\r\nFrom: <me@attacker.test>\r\n", marker)), marker);
        var results = AuthenticationResults(stored);

        Assert.That(final?.Class == 5 || !Says(results, "dmarc=pass"), Is.True,
                    $"delivered as dmarc=pass: {results}{explanation}");

    }


    [Test(Description = "RFC 5322 §3.6.2: more than one address in From: needs a Sender:; RFC 7489 §6.6.1 - DMARC must not pass on one of them while a reader is shown another")]
    public async Task A_From_field_with_two_addresses_does_not_pass_DMARC_on_one_of_them()
    {

        Publish("victim2.test",   Dmarc: "v=DMARC1; p=reject");
        Publish("attacker2.test", Spf:   "v=spf1 ip4:127.0.0.1 -all", Dmarc: "v=DMARC1; p=none");
        using var key = KeyFor("attacker2.test");

        var marker = Marker();
        var (final, stored, explanation) = await Deliver("mx.attacker2.test", "me@attacker2.test",
                                                         key.Sign(Message("From: <ceo@victim2.test>, <me@attacker2.test>\r\n", marker)), marker);
        var results = AuthenticationResults(stored);

        Assert.That(final?.Class == 5 || !Says(results, "dmarc=pass"), Is.True,
                    $"delivered as dmarc=pass: {results}{explanation}");

    }


    [Test(Description = "RFC 7489 §4.2, §10.1: forwarded mail fails SPF for the forwarder's envelope, but the author's aligned DKIM signature satisfies DMARC - an early SPF rejection must not pre-empt it")]
    public async Task Forwarded_mail_with_the_authors_signature_passes_DMARC_despite_an_SPF_fail()
    {

        Publish("forwarder.test", Spf:   "v=spf1 -all");
        Publish("fwd.author.test", Dmarc: "v=DMARC1; p=reject");
        using var key = KeyFor("fwd.author.test");

        var marker = Marker();
        var (final, stored, explanation) = await Deliver("mx.forwarder.test", "list@forwarder.test",
                                                         key.Sign(Message("From: <news@fwd.author.test>\r\n", marker)), marker);
        var results = AuthenticationResults(stored);

        Assert.Multiple(() => {
            Assert.That(final?.Code,                 Is.EqualTo(250),  explanation);
            Assert.That(Says(results, "spf=fail"),    Is.True,          "the SPF result is still written down: " + results);
            Assert.That(Says(results, "dmarc=pass"),  Is.True,          results);
        });

    }


    [Test(Description = "RFC 7208 §8.4: an SPF fail with nothing else to vouch for the author is not delivered as authenticated - a guard for the test above")]
    public async Task An_SPF_fail_with_only_a_foreign_signature_is_not_delivered_as_authenticated()
    {

        Publish("forwarder2.test", Spf:   "v=spf1 -all");
        Publish("own.author.test", Dmarc: "v=DMARC1; p=none");
        using var key = KeyFor("someone-else.test");

        var marker = Marker();
        var (final, stored, explanation) = await Deliver("mx.forwarder2.test", "list@forwarder2.test",
                                                         key.Sign(Message("From: <news@own.author.test>\r\n", marker)), marker);
        var results = AuthenticationResults(stored);

        Assert.That(final?.Class == 5 || Says(results, "spf=fail") && !Says(results, "dmarc=pass"), Is.True,
                    $"{results}{explanation}");

    }


    [Test(Description = "RFC 6376 §4.2: \"a Verifier SHOULD evaluate signatures independently and on their own merits\"; RFC 7489 §4.2 - DMARC passes on the author's signature, also behind a mail service's")]
    public async Task DMARC_passes_on_the_authors_signature_behind_a_mail_services()
    {

        Publish("esp.test",          Spf:   "v=spf1 ip4:127.0.0.1 -all");
        Publish("brand.author.test", Dmarc: "v=DMARC1; p=reject");
        using var brand   = KeyFor("brand.author.test");
        using var service = KeyFor("esp.test");

        // The author signs first, the mail service on top.
        var marker = Marker();
        var (final, stored, explanation) = await Deliver("mx.esp.test", "bounces@esp.test",
                                                         service.Sign(brand.Sign(Message("From: <news@brand.author.test>\r\n", marker))), marker);
        var results = AuthenticationResults(stored);

        Assert.Multiple(() => {
            Assert.That(final?.Code,                 Is.EqualTo(250),  explanation);
            Assert.That(Says(results, "dmarc=pass"),  Is.True,          results);
        });

    }


    [Test(Description = "RFC 7489 §6.6.1, §3.1: DMARC is about the From: domain - a null reverse-path does not exempt a message from it, or a bounce could carry any author")]
    public async Task A_null_sender_does_not_exempt_a_message_from_DMARC()
    {

        Publish("bouncer.test",        Spf:   "v=spf1 ip4:127.0.0.1 -all");
        Publish("strict.author.test",  Dmarc: "v=DMARC1; p=reject");

        var marker = Marker();
        var (final, stored, explanation) = await Deliver("bouncer.test", "",
                                                         Message("From: <ceo@strict.author.test>\r\n", marker), marker);
        var results = AuthenticationResults(stored);

        Assert.That(final?.Class == 5 || Says(results, "dmarc=fail"), Is.True,
                    $"neither refused nor marked dmarc=fail: {results}{explanation}");

    }


    [Test(Description = "RFC 7208 §2.4: with a null reverse-path SPF checks postmaster@ the HELO identity; RFC 8601 §2.7.2 - the result names that identity, as smtp.helo or smtp.mailfrom")]
    [Property("Finding", "V-2")]
    public async Task The_SPF_result_of_a_null_sender_names_the_HELO_identity()
    {

        Publish("helo-only.test", Spf: "v=spf1 ip4:127.0.0.1 -all");

        var marker = Marker();
        var (final, stored, explanation) = await Deliver("helo-only.test", "",
                                                         Message("From: <mailer-daemon@helo-only.test>\r\n", marker), marker);
        var results = AuthenticationResults(stored);

        Assert.Multiple(() => {
            Assert.That(final?.Code,               Is.EqualTo(250),  explanation);
            Assert.That(Says(results, "spf=pass"),  Is.True,          results);
            Assert.That(Says(results, "smtp.helo=helo-only.test") || Says(results, "smtp.mailfrom=postmaster@helo-only.test"), Is.True,
                        "the identity SPF checked: " + results);
        });

    }

}
