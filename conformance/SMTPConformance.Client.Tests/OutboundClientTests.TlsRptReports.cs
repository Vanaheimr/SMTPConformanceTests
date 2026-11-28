using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;
using org.GraphDefined.Vanaheimr.Hermod.SMTP.Server;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;
using SMTPConformance.Core.Scripted;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// The TLS report (RFC 8460) on its way and in what it says of the sessions behind it: the report
/// mail under the TLS policies of the next hop (§5.3), the result types of an MTA-STS policy that
/// could not be had (§4.3.2.2), and the failure-reason-code of a failure (§4.3.1, §4.3.3). The
/// smart host "localhost" is the policy domain (RFC 8461 §3.4), its policy served by the test.
/// </summary>
public sealed partial class OutboundClientTests
{

    #region Setup

    private const String StsPolicyId = "v=STSv1; id=20261128;";

    private static String StsPolicy(String Mode, String Mx = "localhost")
        => $"version: STSv1\r\nmode: {Mode}\r\nmx: {Mx}\r\nmax_age: 604800\r\n";

    /// <summary>
    /// One message to the smart host "localhost" - whose MTA-STS policy, when it has a policy host,
    /// is announced and served by it - and the TLS-RPT events of the session.
    /// </summary>
    private static async Task<(SendResult Result, IReadOnlyList<TlsRptEvent> Events, String Explanation)> SendReported(MtaStsPolicyHost?  Host,
                                                                                                                    Boolean            TrustCertificate)
    {

        var script  = new SmtpServerScript { Certificate = TestCertificate.CreateServerCertificate("localhost") };
        await using var server = ScriptedSmtpServer.Start(script);

        var dns     = new StubDnsClient();
        if (Host is not null)
            MtaStsPolicyHost.Announce(dns, "localhost", StsPolicyId);

        var events  = new ConcurrentQueue<TlsRptEvent>();
        var log     = new CapturingLogger();
        var client  = new SMTPOutboundClient(ConfigFor(server) with {
                                                 SmartHost                   = "localhost",
                                                 RemoteCertificateValidator  = TrustCertificate ? (_, _, _, _) => true : null,
                                                 MtaStsHttpHandler           = Host
                                             },
                                             null, dns, log, events.Enqueue);

        var result  = await SendWith(client, Envelope([ "you@outbound.test" ]), server);

        return (result, [ .. events ], $"{result.Status} {result.ResponseCode} {result.ResponseText}\nevents: {String.Join(", ", events)}\n--- client log ---\n{log}");

    }

    /// <summary>
    /// A TLS reporter whose queue is <paramref name="Queue"/>, reporting to tlsrpt@policy.test.
    /// </summary>
    private sealed class TlsReporter : IDisposable
    {

        private readonly String          directory = Directory.CreateTempSubdirectory("tlsrpt-").FullName;

        public  TlsRptReportService      Service   { get; }

        public TlsReporter(IMailQueue Queue)
        {

            var dns  = new StubDnsClient();
            var name = "_smtp._tls.policy.test";
            dns.Answer(name, DNSResourceRecordTypes.TXT,
                       new TXT(DNSServiceName.Parse(name), DNSQueryClasses.IN, TimeSpan.FromHours(1), "v=TLSRPTv1; rua=mailto:tlsrpt@policy.test"));

            var log  = new CapturingLogger();
            Service  = new TlsRptReportService(new TlsRptAggregator(Path.Combine(directory, "state.json"), log),
                                               new TlsRptResolver(dns, log),
                                               Queue,
                                               new TlsRptReportingOptions("Hermod conformance", "TLS Reports <tls-reports@relay.hermod.test>",
                                                                          "tls-reports@relay.hermod.test", "relay.hermod.test",
                                                                          "mailto:postmaster@relay.hermod.test", TimeSpan.FromDays(1)),
                                               log);

        }

        /// <summary>
        /// The report of the given sessions, as it is queued; the events are taken for sessions
        /// to policy.test.
        /// </summary>
        public async Task<QueuedMail> Report(IEnumerable<TlsRptEvent> Events, CapturingMailQueue Queue)
        {

            foreach (var e in Events)
                Service.Record(e with { PolicyDomain = "policy.test" });

            await Service.GenerateAndSendAsync(CancellationToken.None);

            return Queue.Queued.Single();

        }

        public void Dispose()
        {
            try { Directory.Delete(directory, recursive: true); } catch { }
        }

    }

    /// <summary>
    /// What became of a queued message at the first attempt of the QueueProcessor to deliver it
    /// with the given client.
    /// </summary>
    private static async Task<QueuedMail> FirstAttempt(CapturingMailQueue Queue, String Id, SMTPOutboundClient Client, ScriptedSmtpServer Server)
    {

        var logger    = new CapturingLogger();
        var processor = new QueueProcessor(Queue, Client, new BounceHandler(new SMTPServerConfig { Hostname = "relay.hermod.test" }, Queue, logger),
                                           new QueueProcessorConfig { DomainCooldownSeconds = 0 }, logger);

        await processor.StartAsync();

        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < TimeSpan.FromSeconds(30) &&
               (await Queue.GetByIdAsync(Id)) is { Status: QueueItemStatus.Pending or QueueItemStatus.Processing, RetryCount: 0 })
            await Task.Delay(50);

        await processor.StopAsync();
        await processor.DisposeAsync();
        await Server.WhenIdleAsync();

        return (await Queue.GetByIdAsync(Id))!;

    }

    /// <summary>
    /// A next hop whose TLS fails its policy - an MTA-STS policy in enforce mode and a certificate
    /// nobody vouches for, or a DANE-EE record of another certificate - and a client for it.
    /// </summary>
    private static (SMTPOutboundClient Client, IDisposable? Zone, CapturingLogger Log) PolicyFailing(String Policy, ScriptedSmtpServer Server)
    {

        var log = new CapturingLogger();

        if (Policy == "MTA-STS")
        {

            var dns = new StubDnsClient();
            MtaStsPolicyHost.Announce(dns, "localhost", StsPolicyId);

            return (new SMTPOutboundClient(ConfigFor(Server) with {
                                               SmartHost                   = "localhost",
                                               RemoteCertificateValidator  = null,
                                               MtaStsHttpHandler           = new MtaStsPolicyHost("localhost") { Policy = StsPolicy("enforce") }
                                           },
                                           null, dns, log),
                    null,
                    log);

        }

        var zone = new SignedLocalhost();
        zone.Tlsa(Server.Port, TLSA_CertificateUsage.DANE_EE, TestCertificate.CreateServerCertificate("another.test"));

        return (zone.ClientFor(Server), zone, zone.Log);

    }

    #endregion


    #region T-7: the report mail under the TLS policies of the next hop (§5.3)

    [TestCase("MTA-STS", TestName = "A TLS report sent by SMTP does not honor an MTA-STS failure")]
    [TestCase("DANE",    TestName = "A TLS report sent by SMTP does not honor a DANE TLSA failure")]
    [Description("RFC 8460 §5.3: \"when sending failure reports via SMTP, Sending MTAs MUST NOT honor MTA-STS or DANE TLSA failures\" - the report goes to a next hop whose TLS fails its policy")]
    [Property("Finding", "T-7")]
    public async Task A_TLS_report_does_not_honor_a_TLS_policy_failure(String Policy)
    {

        var script = new SmtpServerScript { Certificate = TestCertificate.CreateServerCertificate("localhost") };
        await using var server = ScriptedSmtpServer.Start(script);

        var (client, zone, log) = PolicyFailing(Policy, server);
        using var _ = zone;

        var queue  = new CapturingMailQueue();
        using var reporter = new TlsReporter(queue);
        var report = await reporter.Report([ new TlsRptEvent("policy.test", TlsRptPolicyType.Sts, "mx.policy.test", "192.0.2.25", "198.51.100.1", false, "certificate-expired") ], queue);

        var mail   = await FirstAttempt(queue, report.Id, client, server);

        Assert.That(mail.Status, Is.EqualTo(QueueItemStatus.Delivered),
                    $"{mail.LastError}" + Explain(server) + "\n--- client log ---\n" + log);

    }


    [TestCase("MTA-STS", TestName = "A message that is no TLS report waits for a next hop that fails its MTA-STS policy")]
    [TestCase("DANE",    TestName = "A message that is no TLS report waits for a next hop that fails its DANE TLSA records")]
    [Description("RFC 8461 §5, RFC 7672 §2.2: any other message waits for a next hop whose TLS fails its policy - a guard for T-7, the same next hops and the same way through the queue")]
    [Property("Finding", "T-7")]
    public async Task A_message_that_is_no_TLS_report_honors_a_TLS_policy_failure(String Policy)
    {

        var script = new SmtpServerScript { Certificate = TestCertificate.CreateServerCertificate("localhost") };
        await using var server = ScriptedSmtpServer.Start(script);

        var (client, zone, log) = PolicyFailing(Policy, server);
        using var _ = zone;

        var queue  = new CapturingMailQueue();
        var id     = (await new MailSender(queue, new CapturingLogger()).SendAsync(Envelope([ "tlsrpt@policy.test" ]))).Single();

        var mail   = await FirstAttempt(queue, id, client, server);

        Assert.Multiple(() => {
            Assert.That(mail.Status,                 Is.Not.EqualTo(QueueItemStatus.Delivered), $"{mail.LastError}" + Explain(server) + "\n--- client log ---\n" + log);
            Assert.That(script.Transactions,         Is.Empty,                                  Explain(server));
        });

    }

    #endregion

    #region T-8: an MTA-STS policy that could not be had (§4.3.2.2)

    [TestCase(500, null,                                                  "sts-policy-fetch-error", TestName = "A policy host that answers 500 is reported as sts-policy-fetch-error")]
    [TestCase(404, null,                                                  "sts-policy-fetch-error", TestName = "A policy host that answers 404 is reported as sts-policy-fetch-error")]
    [TestCase(200, "version: STSv1\r\nmode: enforce\r\nmx: localhost\r\n",  "sts-policy-invalid",     TestName = "A policy without max_age is reported as sts-policy-invalid")]
    [Description("RFC 8460 §4.3.2.2: \"sts-policy-fetch-error: This indicates a failure to retrieve an MTA-STS policy, for example, because the policy host is unreachable\"; \"sts-policy-invalid: This indicates a validation error for the overall MTA-STS Policy\" - a TXT record announces a policy that cannot be had")]
    [Property("Finding", "T-8")]
    public async Task An_MTA_STS_policy_that_could_not_be_had_is_reported(Int32 Status, String? Policy, String ResultType)
    {

        var host = new MtaStsPolicyHost("localhost") { Status = (System.Net.HttpStatusCode) Status };
        if (Policy is not null)
            host.Policy = Policy;

        var (result, events, explanation) = await SendReported(host, TrustCertificate: true);

        Assert.Multiple(() => {
            Assert.That(result.Status,                                                Is.EqualTo(SendStatus.Success), "without a policy the mail goes " + explanation);
            Assert.That(events.Select(e => (e.PolicyType, e.Success, e.FailureType)), Does.Contain((TlsRptPolicyType.Sts, false, (String?) ResultType)), explanation);
        });

    }


    [Test(Description = "RFC 8460 §4.4: without an MTA-STS TXT record there is no policy - the session is a success under \"no-policy-found\"; a guard for T-8")]
    [Property("Finding", "T-8")]
    public async Task Without_an_MTA_STS_record_a_session_is_reported_under_no_policy_found()
    {

        var (result, events, explanation) = await SendReported(null, TrustCertificate: true);

        Assert.Multiple(() => {
            Assert.That(result.Status,                                                Is.EqualTo(SendStatus.Success), explanation);
            Assert.That(events.Select(e => (e.PolicyType, e.Success, e.FailureType)), Is.EqualTo(new[] { (TlsRptPolicyType.NoPolicyFound, true, (String?) null) }), explanation);
        });

    }

    #endregion

    #region T-9: the failure-reason-code (§4.3.1, §4.3.3)

    [TestCase("enforce", "localhost",      false, "certificate-not-trusted", TestName = "A certificate-not-trusted failure has a failure-reason-code")]
    [TestCase("testing", "mx.other.test",  true,  "validation-failure",      TestName = "A validation-failure has a failure-reason-code")]
    [Description("RFC 8460 §4.3.1: certificate-not-trusted - \"When using this declaration, the reporting MTA SHOULD utilize the \"failure-reason-code\" to provide more information to the receiving entity\"; validation-failure the same, and §4.3.3: \"the reporter SHOULD also use \"failure-reason-code\" to give some feedback\"")]
    [Property("Finding", "T-9")]
    public async Task A_failure_of_a_general_result_type_has_a_failure_reason_code(String Mode, String Mx, Boolean TrustCertificate, String ResultType)
    {

        var (_, events, explanation) = await SendReported(new MtaStsPolicyHost("localhost") { Policy = StsPolicy(Mode, Mx) }, TrustCertificate);

        Assume.That(events.Select(e => e.FailureType), Is.EqualTo(new[] { ResultType }), explanation);

        var queue  = new CapturingMailQueue();
        using var reporter = new TlsReporter(queue);
        var report = await reporter.Report(events, queue);

        var detail = JsonDocument.Parse(ReportMail.Part(report.MessageContent, "application/tlsrpt+gzip").Gunzipped()).RootElement.
                         GetProperty("policies")[0].GetProperty("failure-details")[0];

        Assert.Multiple(() => {
            Assert.That(detail.GetProperty("result-type").GetString(),                                                    Is.EqualTo(ResultType),          detail.ToString());
            Assert.That(detail.TryGetProperty("failure-reason-code", out var code) ? code.GetString() : null,             Is.Not.Null.And.Not.Empty,       detail.ToString());
        });

    }

    #endregion

}
