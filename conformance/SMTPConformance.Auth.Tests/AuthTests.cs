using System.Text;

using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Auth.Tests;

/// <summary>
/// RFC 4954 (SMTP AUTH), RFC 4616 (PLAIN), draft-murchison-sasl-login (LOGIN),
/// RFC 5802/7677 (SCRAM-SHA-256) and RFC 6409 (submission) against Hermod's
/// submission port.
/// </summary>
[TestFixture]
public sealed class AuthTests : HermodServerTestBase
{

    private const String User     = "alice";
    private const String Password = "correct horse battery staple";

    protected override HermodSmtpServerFixtureOptions Options
        => new() { EnableTls = true };


    private static String B64(String text)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes(text));

    private static String Unb64(String text)
        => Encoding.UTF8.GetString(Convert.FromBase64String(text));


    /// <summary>
    /// Submission port, EHLO, STARTTLS, EHLO — ready for AUTH.
    /// </summary>
    private async Task<(RawSmtpClient Client, IReadOnlyDictionary<String, String> Extensions)> SubmissionOverTls()
    {
        var (client, _) = await Server.ConnectSubmissionAsync();
        await client.EhloAsync();
        await client.StartTlsAsync();
        var (_, extensions) = await client.EhloAsync();
        return (client, extensions);
    }

    private async Task<RawSmtpClient> AuthenticatedSubmission()
    {
        var (client, _) = await SubmissionOverTls();
        var auth = await client.CommandAsync("AUTH PLAIN " + B64($"\0{User}\0{Password}"));
        Assume.That(auth.Code, Is.EqualTo(235), Explain(client));
        return client;
    }


    #region Advertisement and the cleartext boundary

    [Test(Description = "RFC 4954 §3: AUTH is advertised on the submission port once TLS is up, with PLAIN, LOGIN and SCRAM-SHA-256")]
    public async Task Auth_is_advertised_after_tls()
    {

        var (client, extensions) = await SubmissionOverTls();
        await using var _ = client;

        Assert.That((extensions.GetValueOrDefault("AUTH") ?? "").Split(' '),
                    Does.Contain("PLAIN").And.Contain("LOGIN").And.Contain("SCRAM-SHA-256"), Explain(client));

    }


    [Test(Description = "RFC 4616 §6: PLAIN is not offered on an unprotected connection")]
    public async Task Plain_is_not_offered_in_cleartext()
    {

        var (client, _) = await Server.ConnectSubmissionAsync();
        await using var __ = client;

        var (_, extensions) = await client.EhloAsync();

        Assert.That((extensions.GetValueOrDefault("AUTH") ?? "").Split(' '),
                    Does.Not.Contain("PLAIN").And.Not.Contain("LOGIN"), Explain(client));

    }


    [Test(Description = "RFC 4954 §6: AUTH PLAIN over an unencrypted connection is answered with 538 (encryption required)")]
    public async Task Auth_plain_in_cleartext_is_538()
    {

        var (client, _) = await Server.ConnectSubmissionAsync();
        await using var __ = client;

        await client.EhloAsync();
        var reply = await client.CommandAsync("AUTH PLAIN " + B64($"\0{User}\0{Password}"));

        Assert.That(reply.Code, Is.EqualTo(538), Explain(client));

    }

    #endregion

    #region PLAIN and LOGIN

    [Test(Description = "RFC 4954 §4, RFC 4616 §2: AUTH PLAIN with an initial response and correct credentials is 235")]
    public async Task Auth_plain_with_initial_response_succeeds()
    {

        var (client, _) = await SubmissionOverTls();
        await using var __ = client;

        var reply = await client.CommandAsync("AUTH PLAIN " + B64($"\0{User}\0{Password}"));

        Assert.Multiple(() => {
            Assert.That(reply.Code,         Is.EqualTo(235),     Explain(client));
            Assert.That(reply.EnhancedCode, Is.EqualTo("2.7.0"), Explain(client));
        });

    }


    [Test(Description = "RFC 4954 §4: AUTH PLAIN without an initial response gets an empty 334 challenge, then accepts the response")]
    public async Task Auth_plain_without_initial_response_succeeds()
    {

        var (client, _) = await SubmissionOverTls();
        await using var __ = client;

        var challenge = await client.CommandAsync("AUTH PLAIN");
        var reply     = await client.CommandAsync(B64($"\0{User}\0{Password}"));

        Assert.Multiple(() => {
            Assert.That(challenge.Code, Is.EqualTo(334), Explain(client));
            Assert.That(challenge.Text, Is.Empty,        "PLAIN has no server challenge; the 334 text is empty" + Explain(client));
            Assert.That(reply.Code,     Is.EqualTo(235), Explain(client));
        });

    }


    [Test(Description = "RFC 4954 §4, §6: wrong credentials are 535 5.7.8")]
    [Property("Finding", "S-5")]
    public async Task Wrong_password_is_535()
    {

        var (client, _) = await SubmissionOverTls();
        await using var __ = client;

        var reply = await client.CommandAsync("AUTH PLAIN " + B64($"\0{User}\0not the password"));

        Assert.Multiple(() => {
            Assert.That(reply.Code,         Is.EqualTo(535),     Explain(client));
            Assert.That(reply.EnhancedCode, Is.EqualTo("5.7.8"), Explain(client));
        });

    }


    [Test(Description = "draft-murchison-sasl-login: AUTH LOGIN prompts for user name and password with 334, then 235")]
    public async Task Auth_login_succeeds()
    {

        var (client, _) = await SubmissionOverTls();
        await using var __ = client;

        var userPrompt     = await client.CommandAsync("AUTH LOGIN");
        var passwordPrompt = await client.CommandAsync(B64(User));
        var reply          = await client.CommandAsync(B64(Password));

        Assert.Multiple(() => {
            Assert.That(userPrompt.Code,     Is.EqualTo(334), Explain(client));
            Assert.That(passwordPrompt.Code, Is.EqualTo(334), Explain(client));
            Assert.That(reply.Code,          Is.EqualTo(235), Explain(client));
        });

    }

    #endregion

    #region Protocol errors

    [Test(Description = "RFC 4954 §4: an unsupported mechanism is answered with 504")]
    public async Task Unknown_mechanism_is_504()
    {

        var (client, _) = await SubmissionOverTls();
        await using var __ = client;

        var reply = await client.CommandAsync("AUTH NO-SUCH-MECHANISM");

        Assert.That(reply.Code, Is.EqualTo(504), Explain(client));

    }


    [Test(Description = "RFC 4954 §4: \"If the client wishes to cancel the authentication exchange, it issues a line with a single '*'. ... it MUST reject the AUTH command by sending a 501 reply.\"")]
    public async Task Cancelling_with_a_star_is_501()
    {

        var (client, _) = await SubmissionOverTls();
        await using var __ = client;

        await client.CommandAsync("AUTH LOGIN");
        var reply = await client.CommandAsync("*");

        Assert.That(reply.Code, Is.EqualTo(501), Explain(client));

    }


    [Test(Description = "RFC 4954 §4: \"If the server cannot [BASE64] decode any client response, it MUST reject the AUTH command with a 501 reply (and an enhanced status code of 5.5.2).\"")]
    [Property("Finding", "S-16")]
    public async Task An_undecodable_response_is_501_5_5_2()
    {

        var (client, _) = await SubmissionOverTls();
        await using var __ = client;

        var reply = await client.CommandAsync("AUTH PLAIN !!!not-base64!!!");

        Assert.Multiple(() => {
            Assert.That(reply.Code,         Is.EqualTo(501),     Explain(client));
            Assert.That(reply.EnhancedCode, Is.EqualTo("5.5.2"), Explain(client));
        });

    }


    [Test(Description = "RFC 4954 §4: \"After a successful AUTH command completes, a server MUST reject any further AUTH commands with a 503 reply.\"")]
    public async Task A_second_auth_is_503()
    {

        await using var client = await AuthenticatedSubmission();

        var reply = await client.CommandAsync("AUTH PLAIN " + B64($"\0{User}\0{Password}"));

        Assert.That(reply.Code, Is.EqualTo(503), Explain(client));

    }


    [Test(Description = "RFC 4954 §4: \"An AUTH command issued during a mail transaction MUST be rejected with a 503 reply.\"")]
    [Category(TestCategories.KnownIssue), Property("Finding", "S-15")]
    public async Task Auth_during_a_transaction_is_503()
    {

        var (client, _) = await SubmissionOverTls();
        await using var __ = client;

        var mail  = await client.CommandAsync("MAIL FROM:<alice@hermod.test>");
        Assume.That(mail.Code, Is.EqualTo(250), Explain(client));

        var reply = await client.CommandAsync("AUTH PLAIN " + B64($"\0{User}\0{Password}"));

        Assert.That(reply.Code, Is.EqualTo(503), Explain(client));

    }


    [Test(Description = "RFC 4954 §4: AUTH before EHLO is a bad sequence (503)")]
    public async Task Auth_before_ehlo_is_503()
    {

        var (client, _) = await Server.ConnectImplicitTlsAsync();
        await using var __ = client;

        var reply = await client.CommandAsync("AUTH PLAIN " + B64($"\0{User}\0{Password}"));

        Assert.That(reply.Code, Is.EqualTo(503), Explain(client));

    }

    #endregion

    #region SCRAM-SHA-256

    [Test(Description = "RFC 5802 §5, RFC 7677: a SCRAM-SHA-256 exchange succeeds, and the server proves it knows the password (v= matches the independent oracle)")]
    public async Task Scram_sha_256_succeeds_with_mutual_authentication()
    {

        var (client, _) = await SubmissionOverTls();
        await using var __ = client;

        var scram       = new ScramSha256(User, Password);

        var serverFirst = await client.CommandAsync("AUTH SCRAM-SHA-256 " + B64(scram.ClientFirst()));
        Assume.That(serverFirst.Code, Is.EqualTo(334), Explain(client));

        var serverFinal = await client.CommandAsync(B64(scram.ClientFinal(Unb64(serverFirst.Text))));

        // The server-final-message travels either in a 334 (then the client sends an
        // empty line and gets 235) or as the 235's additional data.
        String v;
        SmtpReply done;

        if (serverFinal.Code == 334)
        {
            v    = Unb64(serverFinal.Text);
            done = await client.CommandAsync("");
        }
        else
        {
            v    = serverFinal.Text.Split(' ').Select(TryUnb64).FirstOrDefault(s => s?.StartsWith("v=") == true) ?? "";
            done = serverFinal;
        }

        Assert.Multiple(() => {
            Assert.That(done.Code, Is.EqualTo(235),                    Explain(client));
            Assert.That(v,         Is.EqualTo(scram.ExpectedServerFinal()), "the server signature must match" + Explain(client));
        });

    }

    private static String? TryUnb64(String text)
    {
        try { return Unb64(text); } catch { return null; }
    }


    [Test(Description = "RFC 5802 §5.1: a SCRAM proof computed from the wrong password is refused with 535")]
    public async Task Scram_with_the_wrong_password_is_535()
    {

        var (client, _) = await SubmissionOverTls();
        await using var __ = client;

        var scram       = new ScramSha256(User, "wrong");

        var serverFirst = await client.CommandAsync("AUTH SCRAM-SHA-256 " + B64(scram.ClientFirst()));
        Assume.That(serverFirst.Code, Is.EqualTo(334), Explain(client));

        var reply       = await client.CommandAsync(B64(scram.ClientFinal(Unb64(serverFirst.Text))));

        Assert.That(reply.Code, Is.EqualTo(535), Explain(client));

    }

    #endregion

    #region Submission policy and session state

    [Test(Description = "RFC 6409 §4.3, RFC 4954 §6: an unauthenticated submission is refused with 530 5.7.0")]
    public async Task Unauthenticated_submission_is_530()
    {

        var (client, _) = await SubmissionOverTls();
        await using var __ = client;

        await client.EnvelopeAsync("alice@hermod.test", "bob@hermod.test");
        var data = await client.CommandAsync("DATA");

        Assert.That(data.Code, Is.EqualTo(530), Explain(client));

    }


    [Test(Description = "RFC 6409, RFC 5321 §3.6.1: an authenticated client may relay; the message is queued for the foreign domain")]
    public async Task Authenticated_relay_is_queued()
    {

        await using var client = await AuthenticatedSubmission();

        var marker = Marker();
        var final  = await client.SendMailAsync("alice@hermod.test", "bob@elsewhere.example",
                                                RawSmtpClientExtensions.Message("alice@hermod.test", "bob@elsewhere.example", marker, "x"));

        Assert.Multiple(() => {
            Assert.That(final.Code, Is.EqualTo(250), Explain(client));
            Assert.That(Server.Queue.Queued.Any(q => q.MessageContent.Contains(marker) && q.EnvelopeTo.Contains("bob@elsewhere.example")), Is.True);
        });

    }


    [Test(Description = "RFC 3461 §5.2.1: ENVID, RET and per-recipient NOTIFY received with a message MUST appear again when it is relayed — so they have to survive into the relay queue")]
    [Property("Finding", "S-14")]
    public async Task Dsn_parameters_are_carried_onto_the_relay_queue()
    {

        await using var client = await AuthenticatedSubmission();

        var marker = Marker();
        var mail   = await client.CommandAsync("MAIL FROM:<alice@hermod.test> RET=HDRS ENVID=QQ314159");
        var rcpt   = await client.CommandAsync("RCPT TO:<bob@elsewhere.example> NOTIFY=SUCCESS,FAILURE");
        var (_, final) = await client.DataAsync(RawSmtpClientExtensions.Message("alice@hermod.test", "bob@elsewhere.example", marker, "x"));

        Assume.That(new[] { mail.Code, rcpt.Code, final?.Code ?? 0 }, Is.All.EqualTo(250), Explain(client));

        var queued = Server.Queue.Queued.SingleOrDefault(q => q.MessageContent.Contains(marker));

        Assert.That(queued, Is.Not.Null, Explain(client));
        Assert.Multiple(() => {
            Assert.That(queued!.EnvId,  Is.EqualTo("QQ314159"),                                   "ENVID");
            Assert.That(queued.Ret,     Is.EqualTo(org.GraphDefined.Vanaheimr.Hermod.SMTP.DsnRet.Hdrs), "RET");
            Assert.That(queued.Notify,  Is.EqualTo(org.GraphDefined.Vanaheimr.Hermod.SMTP.DsnNotify.Success |
                                                   org.GraphDefined.Vanaheimr.Hermod.SMTP.DsnNotify.Failure), "NOTIFY");
        });

    }


    [Test(Description = "RFC 3848 §2: mail submitted with AUTH over TLS is stamped 'with ESMTPSA'")]
    public async Task Authenticated_tls_submission_is_esmtpsa()
    {

        await using var client = await AuthenticatedSubmission();

        var marker = Marker();
        await client.SendMailAsync("alice@hermod.test", "bob@hermod.test",
                                   RawSmtpClientExtensions.Message("alice@hermod.test", "bob@hermod.test", marker, "x"));

        var stored = await Server.Storage.WaitForMarkerAsync(marker);

        Assert.That(stored?.Raw, Does.Match(@"\bwith ESMTPSA\b"), Explain(client));

    }


    [Test(Description = "RFC 4954 §5: the AUTH=<> parameter on MAIL FROM is accepted")]
    public async Task Auth_parameter_on_mail_is_accepted()
    {

        await using var client = await AuthenticatedSubmission();

        var reply = await client.CommandAsync("MAIL FROM:<alice@hermod.test> AUTH=<>");

        Assert.That(reply.Code, Is.EqualTo(250), Explain(client));

    }


    [Test(Description = "RFC 5321 §4.1.1.5 with RFC 4954 §4: RSET clears the transaction, not the authentication — after RSET no further AUTH is permitted, so a server that forgot it would leave the client unable to authenticate again")]
    [Property("Finding", "S-17")]
    public async Task Rset_keeps_the_authentication()
    {

        await using var client = await AuthenticatedSubmission();

        await client.CommandAsync("RSET");

        var marker = Marker();
        var final  = await client.SendMailAsync("alice@hermod.test", "bob@elsewhere.example",
                                                RawSmtpClientExtensions.Message("alice@hermod.test", "bob@elsewhere.example", marker, "x"));

        Assert.That(final.Code, Is.EqualTo(250), "relay after RSET must still be authorised" + Explain(client));

    }

    #endregion

}
