using System.Text;

using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.RawSmtp;

namespace SMTPConformance.Auth.Tests;

/// <summary>
/// RFC 5802 and RFC 7677 in the details of the exchange, against Hermod's submission port:
/// how the server-final-message travels in SMTP (RFC 4422 §3, RFC 4954 §4), the channel
/// binding flag and the c= attribute (RFC 5802 §6), the authorization identity, user names
/// with "=" and ",", mandatory extensions (§5.1), and the normalization of passwords (§2.2).
/// The client half is the suite's own <see cref="ScramSha256"/>.
/// </summary>
[TestFixture]
public sealed class ScramTests : HermodServerTestBase
{

    private const String Password        = "correct horse battery staple";

    // As an administrator types it on a system that writes Unicode decomposed: "A" and a
    // combining diaeresis. SASLprep (RFC 4013 §2.2, NFKC) makes it the "Ä" of U+00C4.
    private const String Decomposed      = "Äpfelbaum";

    protected override HermodSmtpServerFixtureOptions Options

        => new() {
               EnableTls  = true,
               Users      = [ new("alice", Password),
                              new("bob",   Password),
                              new("a=b",   Password),
                              new("a,b",   Password),
                              new("bjoern", Decomposed) ]
           };


    private static String B64(String text)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes(text));

    private static String Unb64(String text)
        => Encoding.UTF8.GetString(Convert.FromBase64String(text));

    private async Task<RawSmtpClient> SubmissionOverTls()
    {
        var (client, _) = await Server.ConnectSubmissionAsync();
        await client.EhloAsync();
        await client.StartTlsAsync();
        await client.EhloAsync();
        return client;
    }

    /// <summary>
    /// One SCRAM-SHA-256 exchange: the reply to the client-first-message, the reply to the
    /// client-final-message, and - when that is a 334 - the reply to the empty response.
    /// </summary>
    private static async Task<(SmtpReply First, SmtpReply Final, SmtpReply? Done)> Exchange(RawSmtpClient Client, ScramSha256 Scram)
    {

        var first = await Client.CommandAsync("AUTH SCRAM-SHA-256 " + B64(Scram.ClientFirst()));
        if (first.Code != 334)
            return (first, first, null);

        var final = await Client.CommandAsync(B64(Scram.ClientFinal(Unb64(first.Text))));
        if (final.Code != 334)
            return (first, final, null);

        return (first, final, await Client.CommandAsync(""));

    }

    /// <summary>
    /// Whether the exchange ended in 235, however it got there.
    /// </summary>
    private static Boolean Authenticated((SmtpReply First, SmtpReply Final, SmtpReply? Done) Exchange)
        => (Exchange.Done ?? Exchange.Final).Code == 235;


    #region S-20: the server-final-message

    [Test(Description = "RFC 4954 §4: \"the SMTP protocol doesn't support the SASL feature of returning additional data with a successful outcome\"; RFC 4422 §3: \"Where the mechanism specifies that the server is to return additional data to the client with a successful outcome and this field is unavailable or unused, the additional data is sent as a challenge whose response is empty\" - SCRAM's server-final-message (v=) is a 334, the client answers it with an empty line, then 235")]
    [Property("Finding", "S-20")]
    public async Task The_server_final_message_is_a_challenge()
    {

        await using var client = await SubmissionOverTls();

        var scram                = new ScramSha256("alice", Password);
        var (_, final, done)     = await Exchange(client, scram);

        Assert.Multiple(() => {
            Assert.That(final.Code,                                   Is.EqualTo(334),                         Explain(client));
            Assert.That(final.Code == 334 ? Unb64(final.Text) : "",   Is.EqualTo(scram.ExpectedServerFinal()), Explain(client));
            Assert.That(done?.Code,                                   Is.EqualTo(235),                         Explain(client));
        });

    }

    #endregion

    #region S-21, S-22: channel binding

    [Test(Description = "RFC 5802 §6: \"If the flag is set to \"y\" and the server supports channel binding, the server MUST fail authentication\" - Hermod offers no SCRAM-SHA-256-PLUS, so a client that supports channel binding but sees no -PLUS sends \"y\" (\"the client MUST NOT use an \"n\" gs2-cbind-flag\"), and is authenticated")]
    [Property("Finding", "S-21")]
    public async Task A_client_that_supports_channel_binding_is_authenticated_with_the_y_flag()
    {

        await using var client = await SubmissionOverTls();

        var exchange = await Exchange(client, new ScramSha256("alice", Password) { Gs2Header = "y,," });

        Assert.That(Authenticated(exchange), Is.True, Explain(client));

    }


    [Test(Description = "RFC 5802 §6: \"The server MUST always validate the client's \"c=\" field. The server does this by constructing the value of the \"c=\" attribute and then checking that it matches the client's c= attribute value\" - a client-first-message with \"n,,\" and a c= of \"y,,\", the proof valid over it, is refused")]
    [Property("Finding", "S-22")]
    public async Task A_c_attribute_that_is_not_the_GS2_header_is_refused()
    {

        await using var client = await SubmissionOverTls();

        var exchange = await Exchange(client, new ScramSha256("alice", Password) { ChannelBinding = B64("y,,") });

        Assert.That(Authenticated(exchange), Is.False, Explain(client));

    }

    #endregion

    #region S-23: the authorization identity

    [Test(Description = "RFC 5802 §5.1, a: \"Upon the receipt of this value the server verifies its correctness according to the used SASL protocol profile. Failed verification results in failed authentication exchange\" - alice asking to act as bob is refused, as Hermod's PLAIN refuses it (AuthConfigurationTests.Acting_as_somebody_else_is_refused)")]
    [Property("Finding", "S-23")]
    public async Task Asking_to_act_as_another_user_is_refused()
    {

        await using var client = await SubmissionOverTls();

        var exchange = await Exchange(client, new ScramSha256("alice", Password) { Gs2Header = "n,a=bob," });

        Assert.That(Authenticated(exchange), Is.False, Explain(client));

    }


    [Test(Description = "RFC 5802 §5.1, a: an authorization identity that is the user's own is no request to act as another - a guard for S-23")]
    [Property("Finding", "S-23")]
    public async Task Naming_oneself_as_the_authorization_identity_is_authenticated()
    {

        await using var client = await SubmissionOverTls();

        var exchange = await Exchange(client, new ScramSha256("alice", Password) { Gs2Header = "n,a=alice," });

        Assert.That(Authenticated(exchange), Is.True, Explain(client));

    }

    #endregion

    #region S-24: "=2C" and "=3D"

    [TestCase("a=b", Description = "\"=\" sent as \"=3D\"")]
    [TestCase("a,b", Description = "\",\" sent as \"=2C\"")]
    [Test(Description = "RFC 5802 §5.1, n: \"The characters ',' or '=' in usernames are sent as '=2C' and '=3D' respectively\" - the server reads them back, and the user is authenticated")]
    [Property("Finding", "S-24")]
    public async Task A_user_name_with_an_escaped_comma_or_equals_sign_is_authenticated(String User)
    {

        await using var client = await SubmissionOverTls();

        var exchange = await Exchange(client, new ScramSha256(User, Password));

        Assert.That(Authenticated(exchange), Is.True, Explain(client));

    }


    [Test(Description = "RFC 5802 §5.1, n: \"If the server receives a username that contains '=' not followed by either '2C' or '3D', then the server MUST fail the authentication\" - \"n=a=b\", for the user a=b with the right password")]
    [Property("Finding", "S-24")]
    public async Task A_user_name_with_an_unescaped_equals_sign_is_refused()
    {

        await using var client = await SubmissionOverTls();

        var exchange = await Exchange(client, new ScramSha256("a=b", Password) { EscapeUsername = false });

        Assert.That(Authenticated(exchange), Is.False, Explain(client));

    }

    #endregion

    #region S-25: mandatory extensions

    [Test(Description = "RFC 5802 §5.1, m: \"its presence in a client or a server message MUST cause authentication failure when the attribute is parsed by the other end\"")]
    [Property("Finding", "S-25")]
    public async Task A_mandatory_extension_fails_the_authentication()
    {

        await using var client = await SubmissionOverTls();

        var exchange = await Exchange(client, new ScramSha256("alice", Password) { MandatoryExtension = "m=future" });

        Assert.That(Authenticated(exchange), Is.False, Explain(client));

    }

    #endregion

    #region S-26: SASLprep

    [Test(Description = "RFC 5802 §2.2: SaltedPassword := Hi(Normalize(password), salt, i), and \"Normalize(str): Apply the SASLprep profile [RFC4013] to the \"str\" string\" - a password set as \"A\" with a combining diaeresis is the password a client normalizing to \"Ä\" proves it knows")]
    [Property("Finding", "S-26")]
    public async Task A_password_is_normalized_as_SASLprep_has_it()
    {

        await using var client = await SubmissionOverTls();

        var exchange = await Exchange(client, new ScramSha256("bjoern", Decomposed) { NormalizePassword = true });

        Assert.That(Authenticated(exchange), Is.True, Explain(client));

    }


    [Test(Description = "RFC 5802 §2.2: a password that SASLprep leaves as it is authenticates either way - a guard for S-26")]
    [Property("Finding", "S-26")]
    public async Task An_ASCII_password_is_authenticated_normalized_or_not()
    {

        await using var client = await SubmissionOverTls();

        var exchange = await Exchange(client, new ScramSha256("alice", Password) { NormalizePassword = true });

        Assert.That(Authenticated(exchange), Is.True, Explain(client));

    }

    #endregion

}
