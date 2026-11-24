using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;
using org.GraphDefined.Vanaheimr.Hermod.TLS;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

public sealed partial class SubmissionClientTests
{

    private static List<String> Commands(SmtpServerScript Script)
    {
        lock (Script.Commands)
            return [ .. Script.Commands.Select(command => command.Line) ];
    }


    #region C-17: no initial response beyond the line length

    [Test(Description = "RFC 4954 §4: \"If use of the initial response argument would cause the AUTH command to exceed this length, the client MUST NOT use the initial response parameter (and instead proceed as defined in Section 5.1 of [SASL])\" - RFC 5321 §4.5.3.1.4: 512 octets with CR LF; a password of 400 octets goes after the 334")]
    [Property("Finding", "C-17")]
    public async Task A_long_password_goes_without_an_initial_response()
    {

        var password = new String('p', 400);

        var script = new SmtpServerScript { Certificate = TestCertificate.CreateServerCertificate(), AuthMechanisms = [ "PLAIN" ] };
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server, TLSUsage.STARTTLS, Login: "app", Password: password);

        var result = await client.Send(Message("hello"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        var lines  = Commands(script);
        var auth   = lines.FindIndex(line => line.StartsWith("AUTH", StringComparison.OrdinalIgnoreCase));

        Assume.That(auth, Is.Not.Negative, "the client signed in" + Explain(server));

        Assert.Multiple(() => {
            Assert.That(Encoding.UTF8.GetByteCount(lines[auth]) + 2, Is.LessThanOrEqualTo(512), "the AUTH command fits a command line - the response after the 334 need not (RFC 4954 §4)" + Explain(server));
            Assert.That(lines[auth],  Is.EqualTo("AUTH PLAIN").IgnoreCase, Explain(server));
            Assert.That(Encoding.UTF8.GetString(Convert.FromBase64String(lines.ElementAtOrDefault(auth + 1) ?? "")),
                        Is.EqualTo("\0app\0" + password), Explain(server));
            Assert.That(result,       Is.EqualTo(MailSentStatus.ok), Explain(server));
        });

    }

    #endregion


    #region C-18: a challenge that is no base64 is cancelled

    public static IEnumerable<TestCaseData> ChallengesThatAreNoBase64()
    {

        TestCaseData Case(String Name, String Challenge)
            => new TestCaseData(Challenge).SetName($"A SCRAM challenge that is no base64: {Name}")
                                          .SetProperty("Finding", "C-18");

        var serverFirst = Convert.ToBase64String(Encoding.UTF8.GetBytes("r=abc,s=c2FsdA==,i=4096"));

        yield return Case("not the alphabet",     "334 %%% not base64 %%%");
        yield return Case("a space inside it",    "334 " + serverFirst.Insert(8, " "));

    }


    [TestCaseSource(nameof(ChallengesThatAreNoBase64))]
    [Description("RFC 4954 §4: \"If the client cannot BASE64 decode any of the server's challenges, it MUST cancel the authentication using the \"*\" response. In particular, servers and clients MUST reject (and not ignore) any character not explicitly allowed by the BASE64 alphabet\" - the answer to such a challenge is \"*\", and no message goes")]
    public async Task A_challenge_that_is_no_base64_is_cancelled(String Challenge)
    {

        var script = new SmtpServerScript {
                         Certificate          = TestCertificate.CreateServerCertificate(),
                         AuthMechanisms       = [ "SCRAM-SHA-256" ],
                         ScramFirstChallenge  = Challenge
                     };

        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server, TLSUsage.STARTTLS, Login: "app", Password: "secret");

        var result = await client.Send(Message("hello"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        var lines  = Commands(script);
        var auth   = lines.FindIndex(line => line.StartsWith("AUTH", StringComparison.OrdinalIgnoreCase));

        Assume.That(auth, Is.Not.Negative, "the client began to sign in" + Explain(server));

        Assert.Multiple(() => {
            // The scripted server records the initial response once more, on its own line.
            Assert.That(lines.Skip(auth + 1).SkipWhile(line => line == lines[auth].Split(' ').Last()).FirstOrDefault(),
                        Is.EqualTo("*"), "the answer to the challenge" + Explain(server));
            Assert.That(lines, Has.None.StartsWith("MAIL FROM"),                                     Explain(server));
            Assert.That(result, Is.Not.EqualTo(MailSentStatus.ok),                                   Explain(server));
        });

    }

    #endregion

}
