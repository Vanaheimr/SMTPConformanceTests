using System.Text.RegularExpressions;

using NUnit.Framework;

using SMTPConformance.Core;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;
using org.GraphDefined.Vanaheimr.Hermod.TLS;

using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// Hermod's <see cref="SMTPSubmissionClient"/> against a scripted server: what the
/// client puts on the wire, judged by RFC 5321 and its extensions.
/// </summary>
[TestFixture]
public sealed partial class SubmissionClientTests
{

    private static SMTPSubmissionClient ClientFor(ScriptedSmtpServer  Server,
                                                  TLSUsage            UseTLS       = TLSUsage.NoTLS,
                                                  String?             Login        = null,
                                                  String?             Password     = null,
                                                  String?             LocalDomain  = "client.example")

        => new (DomainName.Parse("127.0.0.1"),
                IPPort.Parse(Server.Port),
                Login:                       Login,
                Password:                    Password,
                LocalDomain:                 LocalDomain,
                UseTLS:                      UseTLS,
                RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Success(),
                ConnectionTimeout:           TimeSpan.FromSeconds(3),
                CommandTimeout:              TimeSpan.FromSeconds(3));


    private static EMailEnvelop Message(params String[] BodyLines)
        => new (EMail.Parse([
                    "From: app@client.example",
                    "To: you@scripted.test",
                    "Subject: client conformance",
                    "Content-Type: text/plain; charset=utf-8",
                    "",
                    .. BodyLines
                ]));


    private static String Explain(ScriptedSmtpServer Server)
        => "\n--- wire (server side) ---\n" + Server.Transcript;


    // RFC 5321 §4.1.2: Mail-parameters follow the path after a single SP.
    [GeneratedRegex(@"^MAIL FROM:<[^<>]*>( [A-Za-z0-9][A-Za-z0-9-]*(=[!-<>-~]+)?)*$")]
    private static partial Regex MailFromSyntax();


    #region Commands and their syntax

    [Test(Description = "RFC 5321 §2.3.8: every line the client sends ends in CR LF")]
    public async Task Every_client_line_ends_in_CRLF()
    {

        var script = new SmtpServerScript();
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        var result = await client.Send(Message("hello", "world"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        var lines = server.Sessions.SelectMany(s => s.Received).Select(r => r.Line)
                          .Concat(script.Transactions.SelectMany(t => t.DataLines));

        Assert.Multiple(() => {
            Assert.That(result, Is.EqualTo(MailSentStatus.ok), Explain(server));
            Assert.That(lines.Where(l => l.Terminator != LineTerminator.CRLF).Select(l => l.ToString()), Is.Empty, Explain(server));
        });

    }


    [Test(Description = "RFC 5321 §4.1.1.2, §4.1.2: MAIL FROM:<reverse-path> [SP Mail-parameters] — no space after the colon, single SPs between parameters")]
    public async Task Mail_from_is_syntactically_correct()
    {

        var script = new SmtpServerScript();
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        await client.Send(Message("hello"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        Assert.That(script.Transactions.Select(t => t.MailFromLine), Is.Not.Empty.And.All.Match(MailFromSyntax()), Explain(server));

    }


    [Test(Description = "RFC 5321 §4.1.4: \"The domain name given in the EHLO command MUST be either a primary host name ... or, if the host has no name, an address literal\" — checked with the client's default local domain")]
    [Property("Finding", "C-6")]
    public async Task Default_ehlo_argument_is_a_domain_or_address_literal()
    {

        var script = new SmtpServerScript();
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server, LocalDomain: null);

        await client.Send(Message("hello"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        var ehlo = script.Commands.Select(c => c.Line).First(l => l.StartsWith("EHLO ", StringComparison.OrdinalIgnoreCase));
        var arg  = ehlo[5..];

        Assert.That(arg, Does.Match(@"^(\[[^\]]+\]|[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+)$"),
                    $"\"{arg}\" is neither a fully-qualified domain nor an address literal" + Explain(server));

    }


    [Test(Description = "RFC 5321 §4.1.1.10: the client ends the session with QUIT")]
    public async Task The_client_sends_quit()
    {

        var script = new SmtpServerScript();
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        await client.Send(Message("hello"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        Assert.That(script.Commands.Select(c => c.Line).LastOrDefault(), Is.EqualTo("QUIT"), Explain(server));

    }


    [Test(Description = "RFC 5321 §3.2, §4.1.4: when EHLO is refused (502), the client falls back to HELO")]
    [Property("Finding", "C-2")]
    public async Task Ehlo_refused_falls_back_to_helo()
    {

        var script = new SmtpServerScript { EhloReply = [ "502 5.5.1 EHLO not implemented" ] };
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        var result = await client.Send(Message("hello"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        Assert.Multiple(() => {
            Assert.That(script.Commands.Select(c => c.Line), Has.Some.StartsWith("HELO "), Explain(server));
            Assert.That(result, Is.EqualTo(MailSentStatus.ok), Explain(server));
        });

    }


    [Test(Description = "RFC 5321 §4.2: a multiline greeting (220-…/220 …) is read as one reply")]
    public async Task A_multiline_greeting_is_understood()
    {

        var script = new SmtpServerScript { Greeting = "220-scripted.test ESMTP\r\n220-this greeting\r\n220 has three lines" };
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        var result = await client.Send(Message("hello"), NumberOfRetries: 0);

        Assert.That(result, Is.EqualTo(MailSentStatus.ok), Explain(server));

    }


    [Test(Description = "RFC 5321 §4.2.1: a reply that arrives in several TCP segments is reassembled")]
    public async Task A_reply_split_across_segments_is_reassembled()
    {

        await using var server = ScriptedSmtpServer.Start(async s => {

            await s.WriteRawAsync("22");
            await Task.Delay(100);
            await s.WriteRawAsync("0 split.test ready\r\n");

            await new SmtpServerScript { Greeting = "" }.RunAsync(s);

        });

        using var client = ClientFor(server);

        var result = await client.SendWithResult(Message("hello"), NumberOfRetries: 0);

        Assert.That(result.Status, Is.EqualTo(MailSentStatus.ok), Explain(server));

    }

    #endregion

    #region DATA

    [Test(Description = "RFC 5321 §4.5.2: a body line beginning with \".\" is sent with one more \".\" in front")]
    public async Task Body_lines_starting_with_a_period_are_stuffed()
    {

        var script = new SmtpServerScript();
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        var result = await client.Send(Message("before", ".", ".leading", "after"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        var data = script.Transactions.Single().DataLines.Select(l => l.Latin1).ToList();

        Assert.Multiple(() => {
            Assert.That(result, Is.EqualTo(MailSentStatus.ok), Explain(server));
            Assert.That(data,   Does.Contain("..").And.Contain("..leading").And.Contain("after"), Explain(server));
        });

    }


    [Test(Description = "RFC 5321 §2.3.8, §4.1.1.4: a bare LF inside the body text is never sent as a bare LF")]
    [Property("Finding", "C-5")]
    public async Task A_bare_LF_in_the_body_is_not_sent_bare()
    {

        var script = new SmtpServerScript();
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        await client.Send(Message("first\nsecond", "third"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        var data = script.Transactions.SelectMany(t => t.DataLines).ToList();

        Assert.That(data.Where(l => l.Terminator != LineTerminator.CRLF || l.ContainsBareCR).Select(l => l.ToString()), Is.Empty, Explain(server));

    }


    [Test(Description = "RFC 5321 §2.4: \"An SMTP client that has not successfully negotiated an appropriate extension ... MUST NOT transmit messages with information in the high-order bit of octets\"")]
    [Property("Finding", "C-4")]
    public async Task No_8bit_data_without_8bitmime()
    {

        var script = new SmtpServerScript { Extensions = [ "PIPELINING", "SIZE 10485760", "ENHANCEDSTATUSCODES" ] };
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        await client.Send(Message("Grüße aus Köln — ½ €"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        var eightBit = script.Transactions.SelectMany(t => t.DataLines).Where(l => l.Bytes.Any(b => b > 0x7F)).Select(l => l.Latin1);

        Assert.That(eightBit, Is.Empty, Explain(server));

    }


    [Test(Description = "RFC 6152 §2, RFC 1652: BODY= is only sent to a server that advertised 8BITMIME")]
    public async Task No_body_parameter_without_8bitmime()
    {

        var script = new SmtpServerScript { Extensions = [ "PIPELINING", "SIZE 10485760", "ENHANCEDSTATUSCODES" ] };
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        await client.Send(Message("hello"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        Assert.That(script.Transactions.Select(t => t.MailFromLine), Has.None.Contains("BODY="), Explain(server));

    }

    #endregion

    #region SIZE, SMTPUTF8

    [Test(Description = "RFC 1870 §5, §6: the declared SIZE= is not smaller than the octets then sent (CRLFs included, stuffing excluded)")]
    [Property("Finding", "C-7")]
    public async Task Declared_size_covers_the_message()
    {

        var script = new SmtpServerScript();
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        await client.Send(Message("line one", ".stuffed", "line three"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        var transaction = script.Transactions.Single();
        var declared    = Int64.Parse(Regex.Match(transaction.MailFromLine!, @"\bSIZE=(\d+)").Groups[1].Value);
        var actual      = transaction.DataLines.Sum(l => (l.Bytes is [ (Byte) '.', .. ] ? l.Bytes.Length - 1 : l.Bytes.Length) + 2L);

        Assert.That(declared, Is.GreaterThanOrEqualTo(actual), Explain(server));

    }


    [Test(Description = "RFC 1870 §6: a message larger than the server's advertised SIZE is not sent")]
    public async Task An_oversized_message_is_not_sent()
    {

        var script = new SmtpServerScript { Extensions = [ "SIZE 100", "8BITMIME" ] };
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        var result = await client.Send(Message(new String('x', 500)), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        Assert.Multiple(() => {
            Assert.That(result,               Is.EqualTo(MailSentStatus.MessageSizeExceeded), Explain(server));
            Assert.That(script.Transactions,  Is.Empty, "no MAIL may be sent for a message that cannot fit" + Explain(server));
        });

    }


    [Test(Description = "RFC 6531 §3.4: SMTPUTF8 is not requested for an all-ASCII message")]
    public async Task No_smtputf8_for_ascii()
    {

        var script = new SmtpServerScript();
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server);

        await client.Send(Message("plain ascii"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        Assert.That(script.Transactions.Select(t => t.MailFromLine), Has.None.Contains("SMTPUTF8"), Explain(server));

    }

    #endregion

    #region STARTTLS and AUTH

    [Test(Description = "RFC 3207 §4.2: after STARTTLS the client issues EHLO again before anything else")]
    public async Task Ehlo_is_repeated_after_starttls()
    {

        var script = new SmtpServerScript { Certificate = TestCertificate.CreateServerCertificate() };
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server, TLSUsage.STARTTLS);

        var result = await client.Send(Message("hello"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        var firstInTls = script.Commands.FirstOrDefault(c => c.Tls).Line;

        Assert.Multiple(() => {
            Assert.That(result,     Is.EqualTo(MailSentStatus.ok), Explain(server));
            Assert.That(firstInTls, Does.StartWith("EHLO "),        Explain(server));
            Assert.That(script.Transactions.Single().Tls, Is.True, "the transaction must run inside TLS" + Explain(server));
        });

    }


    [Test(Description = "RFC 3207 §4.1, §6: a client configured for STARTTLS does not send the message in cleartext when the server answers STARTTLS with 454")]
    [Property("Finding", "C-1")]
    public async Task A_refused_starttls_does_not_downgrade()
    {

        var script = new SmtpServerScript {
                         Certificate    = TestCertificate.CreateServerCertificate(),
                         StartTlsReply  = "454 4.7.0 TLS not available due to temporary reason"
                     };
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server, TLSUsage.STARTTLS);

        var result = await client.Send(Message("confidential"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        Assert.Multiple(() => {
            Assert.That(script.Transactions, Is.Empty, "no MAIL in cleartext after STARTTLS failed" + Explain(server));
            Assert.That(result,              Is.Not.EqualTo(MailSentStatus.ok), Explain(server));
        });

    }


    [Test(Description = "RFC 3207 §6: a client configured for STARTTLS does not send in cleartext when STARTTLS is not offered at all")]
    public async Task Missing_starttls_does_not_downgrade()
    {

        var script = new SmtpServerScript();
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server, TLSUsage.STARTTLS);

        var result = await client.Send(Message("confidential"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        Assert.Multiple(() => {
            Assert.That(script.Transactions, Is.Empty, Explain(server));
            Assert.That(result,              Is.Not.EqualTo(MailSentStatus.ok), Explain(server));
        });

    }


    [Test(Description = "RFC 5321 §2.4: EHLO keywords are case-insensitive — a lower-case 'starttls' is still STARTTLS")]
    [Property("Finding", "C-3")]
    public async Task Ehlo_keywords_are_case_insensitive()
    {

        var certificate = TestCertificate.CreateServerCertificate();
        var script = new SmtpServerScript {
                         Certificate  = certificate,
                         EhloReply    = [ "250-scripted.test Hello", "250-8bitmime", "250 starttls" ]
                     };
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server, TLSUsage.STARTTLS);

        var result = await client.Send(Message("hello"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        Assert.Multiple(() => {
            Assert.That(script.Commands.Select(c => c.Line), Does.Contain("STARTTLS"), Explain(server));
            Assert.That(result, Is.EqualTo(MailSentStatus.ok), Explain(server));
        });

    }


    [Test(Description = "RFC 8314 §3, RFC 4616 §6: credentials are never sent over a connection without TLS, even if the server offers AUTH PLAIN")]
    public async Task Credentials_are_never_sent_in_cleartext()
    {

        var script = new SmtpServerScript { AuthMechanisms = [ "PLAIN", "LOGIN" ], AuthBeforeTls = true };
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server, TLSUsage.NoTLS, Login: "app", Password: "secret");

        var result = await client.Send(Message("hello"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        Assert.Multiple(() => {
            Assert.That(script.Commands.Select(c => c.Line), Has.None.StartsWith("AUTH"), Explain(server));
            Assert.That(result, Is.Not.EqualTo(MailSentStatus.ok), Explain(server));
        });

    }


    [Test(Description = "RFC 4954 §4, RFC 4616 §2: over STARTTLS the client authenticates with PLAIN ([authzid] NUL authcid NUL passwd), then sends the message")]
    public async Task Auth_plain_over_starttls()
    {

        var script = new SmtpServerScript { Certificate = TestCertificate.CreateServerCertificate(), AuthMechanisms = [ "PLAIN" ] };
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server, TLSUsage.STARTTLS, Login: "app", Password: "secret");

        var result = await client.Send(Message("hello"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        var auth = script.Commands.FirstOrDefault(c => c.Line.StartsWith("AUTH PLAIN", StringComparison.OrdinalIgnoreCase));

        Assert.Multiple(() => {
            Assert.That(result,    Is.EqualTo(MailSentStatus.ok), Explain(server));
            Assert.That(auth.Tls,  Is.True, Explain(server));
            Assert.That(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(auth.Line.Split(' ')[2])),
                        Is.EqualTo("\0app\0secret"), Explain(server));
        });

    }

    #endregion

}
