using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;
using org.GraphDefined.Vanaheimr.Hermod.TLS;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

public sealed partial class SubmissionClientTests
{

    #region SCRAM-SHA-256 (C-12, C-13)

    /// <summary>
    /// Send one message through a scripted server that offers SCRAM-SHA-256 only, over
    /// STARTTLS: the result, and whether the client went on to MAIL FROM.
    /// </summary>
    private static async Task<(MailSentStatus Result, Boolean SentMail, String Explanation)> SendWithScram(ScramEnding  Ending,
                                                                                                           String       ServerPassword  = "secret",
                                                                                                           String       ClientPassword  = "secret")
    {

        var script = new SmtpServerScript {
                         Certificate     = TestCertificate.CreateServerCertificate(),
                         AuthMechanisms  = [ "SCRAM-SHA-256" ],
                         ScramPassword   = ServerPassword,
                         ScramEnding     = Ending
                     };

        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server, TLSUsage.STARTTLS, Login: "app", Password: ClientPassword);

        var result = await client.Send(Message("hello"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        return (result,
                script.Commands.Any(command => command.Line.StartsWith("MAIL FROM", StringComparison.OrdinalIgnoreCase)),
                Explain(server));

    }


    [Test(Description = "RFC 5802 §5, RFC 4422 §3: a SCRAM-SHA-256 exchange whose server-final-message comes as a 334, answered with an empty line, then 235 - the client authenticates and sends the message: a guard for the scripted SCRAM server and C-12")]
    [Property("Finding", "C-12")]
    public async Task Scram_with_the_servers_signature_authenticates()
    {

        var (result, sentMail, explanation) = await SendWithScram(ScramEnding.ServerFinalAsChallenge);

        Assert.Multiple(() => {
            Assert.That(result,    Is.EqualTo(MailSentStatus.ok), explanation);
            Assert.That(sentMail,  Is.True,                       explanation);
        });

    }


    [Test(Description = "RFC 5802 §5: \"the client authenticates the server by computing the ServerSignature and comparing it to the value sent by the server. If the two are different, the client MUST consider the authentication exchange to be unsuccessful\" - a wrong v= is no authentication: a guard for C-12")]
    [Property("Finding", "C-12")]
    public async Task Scram_with_a_wrong_server_signature_does_not_authenticate()
    {

        var (_, sentMail, explanation) = await SendWithScram(ScramEnding.WrongServerSignature);

        Assert.That(sentMail, Is.False, "the message is not sent to a server that did not prove it knows the password" + explanation);

    }


    [Test(Description = "RFC 5802 §5: the client authenticates the server by its ServerSignature, which comes in the server-final-message - a 334 in SMTP (RFC 4422 §3, RFC 4954 §4: SMTP has no additional data with success). A 235 without it is a server that never proved it knows the password, and the exchange is not successful")]
    [Category(TestCategories.KnownIssue), Property("Finding", "C-12")]
    public async Task Scram_without_the_servers_signature_does_not_authenticate()
    {

        var (_, sentMail, explanation) = await SendWithScram(ScramEnding.SuccessWithoutServerFinal);

        Assert.That(sentMail, Is.False, "the message is not sent to a server that did not prove it knows the password" + explanation);

    }


    [Test(Description = "RFC 5802 §2.2: SaltedPassword := Hi(Normalize(password), salt, i), \"Normalize(str): Apply the SASLprep profile [RFC4013] to the \"str\" string\" - a password typed as \"A\" with a combining diaeresis is the server's \"Äpfelbaum\"")]
    [Category(TestCategories.KnownIssue), Property("Finding", "C-13")]
    public async Task Scram_normalizes_the_password_as_SASLprep_has_it()
    {

        var (result, _, explanation) = await SendWithScram(ScramEnding.ServerFinalAsChallenge,
                                                           ServerPassword:  "Äpfelbaum",
                                                           ClientPassword:  "Äpfelbaum");

        Assert.That(result, Is.EqualTo(MailSentStatus.ok), explanation);

    }

    #endregion

}
