using NUnit.Framework;

using SMTPConformance.Core;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

public sealed partial class SubmissionClientTests
{

    #region C-16: the client's name in EHLO

    [Test(Description = "RFC 6531 §3.7.1: \"the SMTPUTF8-aware SMTP client MUST send only ASCII (LDH label or A-label [RFC5890]) domains in the EHLO command\" - it cannot know before the reply whether the server takes UTF-8 at all")]
    [Category(TestCategories.KnownIssue), Property("Finding", "C-16")]
    public async Task The_client_says_EHLO_with_its_name_in_A_labels()
    {

        var script = new SmtpServerScript();
        await using var server = ScriptedSmtpServer.Start(script);
        using var client = ClientFor(server, LocalDomain: "client.bücher.test");

        await client.Send(Message("hello"), NumberOfRetries: 0);
        await server.WhenIdleAsync();

        var ehlo = script.Commands.Select(command => command.Line).FirstOrDefault(line => line.StartsWith("EHLO ", StringComparison.OrdinalIgnoreCase));

        Assert.That(ehlo, Is.EqualTo("EHLO client.xn--bcher-kva.test"), Explain(server));

    }

    #endregion

}
