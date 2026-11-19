using System.Text;

using NUnit.Framework;

using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Auth.Tests;

/// <summary>
/// RFC 4616 §2: whose password a PLAIN message carries, and whom it may act as.
/// </summary>
[TestFixture]
public sealed class PlainIdentityTests : HermodServerTestBase
{

    private const String AlicesPassword = "correct horse battery staple";
    private const String BobsPassword   = "tr0ub4dor&3";

    protected override HermodSmtpServerFixtureOptions Options
        => new() {
               EnableTls  = true,
               Users      = [ new("alice", AlicesPassword), new("bob", BobsPassword) ]
           };

    private async Task<(RawSmtpClient Client, SmtpReply Reply)> Plain(String AuthorizationIdentity, String AuthenticationIdentity, String Password)
    {

        var (client, _) = await Server.ConnectSubmissionAsync();
        await client.EhloAsync();
        await client.StartTlsAsync();
        await client.EhloAsync();

        var reply = await client.CommandAsync("AUTH PLAIN " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{AuthorizationIdentity}\0{AuthenticationIdentity}\0{Password}")));

        return (client, reply);

    }


    [Test(Description = "RFC 4616 §5, RFC 4954 §4: what carries a password - the PLAIN initial response, the LOGIN exchange - is not written to the server's log, in clear or in Base64")]
    public async Task Credentials_do_not_appear_in_the_servers_log()
    {

        const String password = "log-me-not-" + "7c1f";

        Server.Users.Add("carol", password);

        var plain = Convert.ToBase64String(Encoding.UTF8.GetBytes($"\0carol\0{password}"));
        var login = Convert.ToBase64String(Encoding.UTF8.GetBytes(password));

        var (client, reply) = await Plain("", "carol", password);
        await using (client)
            Assume.That(reply.Code, Is.EqualTo(235), Explain(client));

        var (second, _) = await Server.ConnectSubmissionAsync();
        await using (second)
        {
            await second.EhloAsync();
            await second.StartTlsAsync();
            await second.EhloAsync();
            await second.CommandAsync("AUTH LOGIN");
            await second.CommandAsync(Convert.ToBase64String(Encoding.UTF8.GetBytes("carol")));
            Assume.That((await second.CommandAsync(login)).Code, Is.EqualTo(235), Explain(second));
        }

        var log = Server.Log.ToString();

        // The server writes what the client says to its log at all - else there is nothing to find.
        Assume.That(log, Does.Contain("EHLO"), "the log holds the dialogue");

        Assert.Multiple(() => {
            Assert.That(log, Does.Not.Contain(password),  "the password in clear");
            Assert.That(log, Does.Not.Contain(plain),     "the PLAIN response");
            Assert.That(log, Does.Not.Contain(login),     "the LOGIN password");
        });

    }


    [Test(Description = "RFC 4616 §2: an authorization identity that is the authentication identity's own is accepted - a guard for the tests below")]
    public async Task Acting_as_oneself_is_accepted()
    {

        var (client, reply) = await Plain("alice", "alice", AlicesPassword);
        await using var _ = client;

        Assert.That(reply.Code, Is.EqualTo(235), Explain(client));

    }


    [Test(Description = "RFC 4616 §2: the authcid is the \"identity whose password will be used\" - alice's password does not sign in bob as alice")]
    public async Task The_password_is_checked_against_the_authentication_identity()
    {

        var (client, reply) = await Plain("alice", "bob", AlicesPassword);
        await using var _ = client;

        Assert.That(reply.Code, Is.Not.EqualTo(235), Explain(client));

    }


    [Test(Description = "RFC 4616 §2: the server verifies \"that the authentication credentials permit the client to act as the (presented or derived) authorization identity\" - alice may not act as bob")]
    public async Task Acting_as_somebody_else_is_refused()
    {

        var (client, reply) = await Plain("bob", "alice", AlicesPassword);
        await using var _ = client;

        Assert.That(reply.Code, Is.Not.EqualTo(235), Explain(client));

    }

}


/// <summary>
/// RFC 4954 §3, §4: the mechanisms a server is configured to offer are the ones it advertises
/// and the ones it takes.
/// </summary>
[TestFixture]
public sealed class ConfiguredMechanismsTests : HermodServerTestBase
{

    protected override HermodSmtpServerFixtureOptions Options
        => new() { EnableTls = true, AuthMechanisms = [ "PLAIN" ] };

    private async Task<(RawSmtpClient Client, IReadOnlyDictionary<String, String> Extensions)> SubmissionOverTls()
    {
        var (client, _) = await Server.ConnectSubmissionAsync();
        await client.EhloAsync();
        await client.StartTlsAsync();
        var (_, extensions) = await client.EhloAsync();
        return (client, extensions);
    }


    [Test(Description = "RFC 4954 §3: the AUTH keyword lists the mechanisms the server supports - here PLAIN alone")]
    public async Task Only_the_configured_mechanisms_are_advertised()
    {

        var (client, extensions) = await SubmissionOverTls();
        await using var _ = client;

        Assert.That((extensions.GetValueOrDefault("AUTH") ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries),
                    Is.EquivalentTo(new[] { "PLAIN" }), Explain(client));

    }


    [TestCase("LOGIN")]
    [TestCase("SCRAM-SHA-256")]
    [Test(Description = "RFC 4954 §4: \"If the requested authentication mechanism is invalid (e.g., is not supported ...), the server rejects the AUTH command with a 504 reply\", 5.5.4")]
    public async Task A_mechanism_that_is_not_offered_is_504(String Mechanism)
    {

        var (client, _) = await SubmissionOverTls();
        await using var _ = client;

        var reply = await client.CommandAsync("AUTH " + Mechanism);

        Assert.Multiple(() => {
            Assert.That(reply.Code,          Is.EqualTo(504),      Explain(client));
            Assert.That(reply.EnhancedCode,  Is.EqualTo("5.5.4"),  Explain(client));
        });

    }

}


/// <summary>
/// RFC 6409 §1, §3.1: submission is a service of its own port; a server may keep AUTH
/// off the port where other servers deliver.
/// </summary>
[TestFixture]
public sealed class AuthOnSubmissionOnlyTests : HermodServerTestBase
{

    protected override HermodSmtpServerFixtureOptions Options
        => new() { EnableTls = true, AuthOnMtaPort = false };

    private async Task<(RawSmtpClient Client, IReadOnlyDictionary<String, String> Extensions)> OverTls(Boolean MtaPort)
    {
        var (client, _) = MtaPort ? await Server.ConnectMtaAsync() : await Server.ConnectSubmissionAsync();
        await client.EhloAsync();
        await client.StartTlsAsync();
        var (_, extensions) = await client.EhloAsync();
        return (client, extensions);
    }

    private static String Plain
        => "AUTH PLAIN " + Convert.ToBase64String(Encoding.UTF8.GetBytes("\0alice\0correct horse battery staple"));


    [Test(Description = "RFC 4954 §3: a server that does not take AUTH on a port does not advertise it there")]
    public async Task AUTH_is_not_advertised_on_the_MTA_port()
    {

        var (client, extensions) = await OverTls(MtaPort: true);
        await using var _ = client;

        Assert.That(extensions.ContainsKey("AUTH"), Is.False, Explain(client));

    }


    [Test(Description = "RFC 4954 §3, RFC 5321 §4.2.4: AUTH where it is not offered is refused (5yz) - and signs nobody in")]
    public async Task AUTH_on_the_MTA_port_signs_nobody_in()
    {

        var (client, _) = await OverTls(MtaPort: true);
        await using var _ = client;

        var reply = await client.CommandAsync(Plain);

        Assert.That(reply.Class, Is.EqualTo(5), Explain(client));

    }


    [Test(Description = "RFC 6409 §4.3: the submission port still offers and takes AUTH - a guard for the tests above")]
    public async Task AUTH_on_the_submission_port_still_signs_in()
    {

        var (client, extensions) = await OverTls(MtaPort: false);
        await using var _ = client;

        var reply = await client.CommandAsync(Plain);

        Assert.Multiple(() => {
            Assert.That(extensions.ContainsKey("AUTH"),  Is.True,           Explain(client));
            Assert.That(reply.Code,                      Is.EqualTo(235),   Explain(client));
        });

    }

}
