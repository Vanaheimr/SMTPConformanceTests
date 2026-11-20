using System.IO.Compression;
using System.Net;
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;

namespace SMTPConformance.Server.Tests;

/// <summary>
/// RFC 7489 §7.2 from the other end: the aggregate reports other receivers send about a
/// domain of this server, as <see cref="DmarcReportReader"/> reads them - the XML of
/// Appendix C, gzipped as application/gzip (§7.2.1.1) or zipped, and the XML 1.0 it is
/// written in (§4.3.3, encodings). Hermod's server does not call the reader; an application
/// that reads its rua mailbox does, so the tests call it as that application would - with
/// hostile input too: a DTD, an external entity, a gzip and a ZIP bomb, deep nesting.
/// </summary>
[TestFixture]
public sealed class IncomingDmarcReportTests
{

    #region Setup

    /// <summary>
    /// An aggregate report of RFC 7489 Appendix C: one record of two messages from
    /// 192.0.2.25 that passed on aligned DKIM, one of one that failed.
    /// </summary>
    private static String Report(String  Begin   = "1700006400",
                                 String  End     = "1700092799",
                                 String  OrgName = "receiver.example")

        => $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <version>1.0</version>
              <report_metadata>
                <org_name>{OrgName}</org_name>
                <email>dmarc-noreply@receiver.example</email>
                <report_id>4c5a1b2e-7f0d-4f0b-9b8e-1d2c3b4a5f60</report_id>
                <date_range>
                  <begin>{Begin}</begin>
                  <end>{End}</end>
                </date_range>
              </report_metadata>
              <policy_published>
                <domain>hermod.test</domain>
                <adkim>r</adkim>
                <aspf>s</aspf>
                <p>reject</p>
                <sp>quarantine</sp>
                <pct>100</pct>
                <fo>0</fo>
              </policy_published>
              <record>
                <row>
                  <source_ip>192.0.2.25</source_ip>
                  <count>2</count>
                  <policy_evaluated>
                    <disposition>none</disposition>
                    <dkim>pass</dkim>
                    <spf>fail</spf>
                  </policy_evaluated>
                </row>
                <identifiers>
                  <envelope_from>bounces.hermod.test</envelope_from>
                  <header_from>hermod.test</header_from>
                </identifiers>
                <auth_results>
                  <dkim>
                    <domain>hermod.test</domain>
                    <selector>s2026</selector>
                    <result>pass</result>
                  </dkim>
                  <spf>
                    <domain>bounces.hermod.test</domain>
                    <scope>mfrom</scope>
                    <result>softfail</result>
                  </spf>
                </auth_results>
              </record>
              <record>
                <row>
                  <source_ip>198.51.100.7</source_ip>
                  <count>1</count>
                  <policy_evaluated>
                    <disposition>reject</disposition>
                    <dkim>fail</dkim>
                    <spf>fail</spf>
                  </policy_evaluated>
                </row>
                <identifiers>
                  <envelope_from>forger.example</envelope_from>
                  <header_from>hermod.test</header_from>
                </identifiers>
                <auth_results>
                  <spf>
                    <domain>forger.example</domain>
                    <scope>mfrom</scope>
                    <result>pass</result>
                  </spf>
                </auth_results>
              </record>
            </feedback>
            """;

    private static Byte[] Gzip(Byte[] Content)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
            gzip.Write(Content);
        return output.ToArray();
    }

    private static Byte[] Zip(String Name, Byte[] Content)
    {
        using var output = new MemoryStream();
        using (var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            using var entry = zip.CreateEntry(Name, CompressionLevel.SmallestSize).Open();
            entry.Write(Content);
        }
        return output.ToArray();
    }

    /// <summary>
    /// Gzip a run of spaces after the start of a report: a few hundred KiB that unpack to
    /// <paramref name="MiB"/> MiB - written straight into the compressor, never held whole.
    /// </summary>
    private static Byte[] Bomb(Int32 MiB, Func<Stream, Stream> Compressor)
    {
        using var output = new MemoryStream();
        using (var compressor = Compressor(output))
        {
            compressor.Write("<?xml version=\"1.0\"?><feedback>"u8);
            var spaces = new Byte[1024 * 1024];
            Array.Fill(spaces, (Byte) ' ');
            for (var i = 0; i < MiB; i++)
                compressor.Write(spaces);
            compressor.Write("</feedback>"u8);
        }
        return output.ToArray();
    }

    private static DmarcReceivedReport? Read(Byte[] Attachment)
        => DmarcReportReader.Unpack(Attachment) is { } xml ? DmarcReportReader.Parse(xml) : null;

    #endregion


    #region The aggregate report

    [Test(Description = "RFC 7489 Appendix C: feedback with report_metadata (org_name, email, report_id, date_range of begin and end in seconds since the epoch), policy_published (domain, adkim, aspf, p, sp, pct) and the records - row (source_ip, count, policy_evaluated), identifiers, auth_results")]
    public void A_report_as_Appendix_C_describes_it_is_read()
    {

        var report = DmarcReportReader.Parse(Report());

        Assert.That(report, Is.Not.Null);
        Assert.Multiple(() => {
            Assert.That(report!.OrganizationName,               Is.EqualTo("receiver.example"));
            Assert.That(report.Email,                           Is.EqualTo("dmarc-noreply@receiver.example"));
            Assert.That(report.ReportId,                        Is.EqualTo("4c5a1b2e-7f0d-4f0b-9b8e-1d2c3b4a5f60"));
            Assert.That(report.Begin,                           Is.EqualTo(DateTimeOffset.FromUnixTimeSeconds(1700006400)));
            Assert.That(report.End,                             Is.EqualTo(DateTimeOffset.FromUnixTimeSeconds(1700092799)));
            Assert.That(report.Domain,                          Is.EqualTo("hermod.test"));
            Assert.That((report.Policy, report.SubdomainPolicy), Is.EqualTo(("reject", "quarantine")));
            Assert.That(report.Percent,                         Is.EqualTo(100));
            Assert.That((report.Adkim, report.Aspf),            Is.EqualTo(("r", "s")));
            Assert.That(report.Records,                         Has.Count.EqualTo(2));
            Assert.That(report.Records[0].SourceIp,             Is.EqualTo("192.0.2.25"));
            Assert.That(report.Records[0].Count,                Is.EqualTo(2));
            Assert.That(report.Records[0].Disposition,          Is.EqualTo("none"));
            Assert.That((report.Records[0].Dkim, report.Records[0].Spf), Is.EqualTo(("pass", "fail")));
            Assert.That(report.Records[0].HeaderFrom,           Is.EqualTo("hermod.test"));
            Assert.That(report.Records[0].DkimResults,          Is.EqualTo(new[] { new DmarcReceivedAuth("hermod.test", "pass", "s2026") }));
            Assert.That(report.Records[0].SpfResults,           Is.EqualTo(new[] { new DmarcReceivedAuth("bounces.hermod.test", "softfail", null) }));
            Assert.That(report.Records[1].Disposition,          Is.EqualTo("reject"));
            Assert.That((report.Total, report.Passed),          Is.EqualTo((3L, 2L)), "aligned DKIM passed for two of three");
        });

    }


    [Test(Description = "RFC 7489 §7.2.1.1: \"The aggregate data MUST be an XML file that SHOULD be subjected to GZIP compression\", \"application/gzip\" if compressed and \"text/xml\" otherwise - both are read")]
    public void A_gzipped_report_and_a_plain_one_are_read()
    {

        var xml = Encoding.UTF8.GetBytes(Report());

        Assert.Multiple(() => {
            Assert.That(Read(Gzip(xml))?.Domain,  Is.EqualTo("hermod.test"), "application/gzip");
            Assert.That(Read(xml)?.Domain,        Is.EqualTo("hermod.test"), "text/xml");
        });

    }


    [Test(Description = "RFC 7489 §7.2.1.1 asks for gzip; receivers also send the XML in a ZIP (application/zip), which the reader documents taking - the .xml file in it is read")]
    public void A_report_in_a_ZIP_is_read()
    {

        Assert.That(Read(Zip("receiver.example!hermod.test!1700006400!1700092799.xml", Encoding.UTF8.GetBytes(Report())))?.Domain,
                    Is.EqualTo("hermod.test"));

    }


    [Test(Description = "RFC 7489 §7.2.1.1, Appendix C: the report Hermod's own DmarcReportService sends - its application/gzip attachment - is read back by Hermod's reader, record for record")]
    public async Task The_report_Hermod_writes_is_read_back()
    {

        var directory = Directory.CreateTempSubdirectory("dmarc-roundtrip-").FullName;

        try
        {

            var log      = new CapturingLogger();
            var queue    = new CapturingMailQueue();
            var service  = new DmarcReportService(new DmarcAggregator(Path.Combine(directory, "state.json"), log),
                                                  queue,
                                                  new DNSVerifier(new StubDnsClient(), log),
                                                  new DmarcReportingOptions("Hermod conformance", "DMARC Reports <dmarc-reports@mx.hermod.test>",
                                                                            "dmarc-reports@mx.hermod.test", "mx.hermod.test", TimeSpan.FromDays(1), EnableForensic: false),
                                                  log);

            var evaluation = new DmarcEvaluation("policy.test", "policy.test", "reject", null, "reject", 100, false, false,
                                                 "mailto:dmarc@policy.test", null, null,
                                                 SPFResult.Pass, "policy.test", true, DkimResult.Pass, "policy.test", true,
                                                 DmarcResult.Pass, DmarcDisposition.None);

            service.RecordInbound(evaluation, IPAddress.Parse("192.0.2.25"));
            service.RecordInbound(evaluation, IPAddress.Parse("192.0.2.25"));
            await service.GenerateAndSendAggregatesAsync(CancellationToken.None);

            var attachment = ReportMail.Part(queue.Queued.Single().MessageContent, "application/gzip");
            var report     = Read(attachment.Content);

            Assert.That(report, Is.Not.Null, attachment.Gunzipped());
            Assert.Multiple(() => {
                Assert.That(report!.OrganizationName,    Is.EqualTo("Hermod conformance"));
                Assert.That(report.Domain,               Is.EqualTo("policy.test"));
                Assert.That(report.Policy,               Is.EqualTo("reject"));
                Assert.That(report.Begin,                Is.LessThanOrEqualTo(report.End));
                Assert.That(report.Records.Single().SourceIp, Is.EqualTo("192.0.2.25"));
                Assert.That((report.Total, report.Passed),    Is.EqualTo((2L, 2L)));
            });

        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch { }
        }

    }

    #endregion

    #region The XML it is written in

    public static IEnumerable<TestCaseData> Encodings()
    {
        yield return new TestCaseData(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(Report())).ToArray()).
                         SetName("UTF-8 with a Byte Order Mark is read").SetProperty("Finding", "I-4");
        yield return new TestCaseData(Gzip([ .. Encoding.UTF8.GetPreamble(), .. Encoding.UTF8.GetBytes(Report()) ])).
                         SetName("UTF-8 with a Byte Order Mark is read, gzipped").SetProperty("Finding", "I-4");
        yield return new TestCaseData(Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes(Report().Replace("UTF-8", "UTF-16"))).ToArray()).
                         SetName("UTF-16 is read").SetProperty("Finding", "I-4");
        yield return new TestCaseData(Encoding.UTF8.GetBytes(Report())).
                         SetName("UTF-8 without a Byte Order Mark is read");
    }

    [TestCaseSource(nameof(Encodings))]
    [Description("XML 1.0 §4.3.3: \"All XML processors MUST be able to read entities in both the UTF-8 and UTF-16 encodings\"; \"Entities encoded in UTF-16 MUST and entities encoded in UTF-8 MAY begin with the Byte Order Mark\" - RFC 7489 §7.2.1.1: the report \"MUST be an XML file\"")]
    public void A_report_in_either_encoding_XML_requires_is_read(Byte[] Attachment)
    {

        Assert.That(Read(Attachment)?.Domain, Is.EqualTo("hermod.test"));

    }


    [TestCase("99999999999999",          "1700092799",  TestName = "A begin beyond the year 9999 does not throw")]
    [TestCase("1700006400",              "-99999999999", TestName = "An end before the year 1 does not throw")]
    [Description("RFC 7489 Appendix C: begin and end are xs:integer - seconds since the epoch a foreign receiver writes, any integer; a reader that throws on one loses the report and whatever its caller was doing")]
    [Property("Finding", "I-5")]
    public void A_date_range_out_of_range_does_not_throw(String Begin, String End)
    {

        DmarcReceivedReport? report = null;

        Assert.That(() => report = DmarcReportReader.Parse(Report(Begin: Begin, End: End)), Throws.Nothing);
        Assert.That(report?.Domain, Is.EqualTo("hermod.test"), "the report is still read");

    }

    #endregion

    #region Hostile reports

    [Test(Description = "RFC 7489 §7.2.1.1, Appendix C: the report is a schema without a DTD; a report is what a stranger sends - nested entities (\"billion laughs\") are not expanded")]
    [CancelAfter(10_000)]
    public void Entity_expansion_is_refused()
    {

        var laughs = new StringBuilder("<?xml version=\"1.0\"?><!DOCTYPE feedback [<!ENTITY l0 \"lol\">");
        for (var i = 1; i <= 10; i++)
            laughs.Append($"<!ENTITY l{i} \"{String.Concat(Enumerable.Repeat($"&l{i - 1};", 10))}\">");
        laughs.Append("]><feedback><policy_published><domain>&l10;</domain></policy_published></feedback>");

        Assert.That(DmarcReportReader.Parse(laughs.ToString()), Is.Null);

    }


    [Test(Description = "RFC 7489 §7.2.1.1: a report is what a stranger sends - an external entity (XXE) does not read a file of the reader's host into the report")]
    public void An_external_entity_is_not_resolved()
    {

        var secret = Path.Combine(Path.GetTempPath(), $"dmarc-secret-{Guid.NewGuid():N}.txt");
        File.WriteAllText(secret, "the-secret-content");

        try
        {

            var report = DmarcReportReader.Parse($"<?xml version=\"1.0\"?><!DOCTYPE feedback [<!ENTITY x SYSTEM \"{new Uri(secret).AbsoluteUri}\">]>" +
                                                 "<feedback><report_metadata><org_name>&x;</org_name></report_metadata><policy_published><domain>hermod.test</domain></policy_published></feedback>");

            Assert.That(report?.OrganizationName ?? "", Does.Not.Contain("the-secret-content"));

        }
        finally
        {
            File.Delete(secret);
        }

    }


    [TestCase("gzip", TestName = "A gzip bomb is not unpacked whole")]
    [TestCase("zip",  TestName = "A ZIP bomb is not unpacked whole")]
    [Description("RFC 6713 §4 (application/gzip, which RFC 7489 §7.2.1.1 names): \"fields that are supposed to be flags, lengths, or pointers could contain anything. Applications should treat any data with due skepticism\" - 300 KiB that unpack to 256 MiB are given up on, without holding the 256 MiB")]
    [CancelAfter(60_000)]
    public void A_bomb_is_not_unpacked_whole(String Kind)
    {

        var bomb = Kind == "gzip"
                       ? Bomb(256, output => new GZipStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
                       : ZipBomb(256);

        var before = GC.GetAllocatedBytesForCurrentThread();
        var xml    = DmarcReportReader.Unpack(bomb);
        var used   = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.Multiple(() => {
            Assert.That(xml,  Is.Null,                                  "more than the 20 MiB the reader allows");
            Assert.That(used, Is.LessThan(128L * 1024 * 1024),          $"{used / 1048576} MiB allocated");
        });

    }

    private static Byte[] ZipBomb(Int32 MiB)
    {
        using var output = new MemoryStream();
        using (var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            using var entry = zip.CreateEntry("report.xml", CompressionLevel.SmallestSize).Open();
            var spaces = new Byte[1024 * 1024];
            Array.Fill(spaces, (Byte) ' ');
            entry.Write("<?xml version=\"1.0\"?><feedback>"u8);
            for (var i = 0; i < MiB; i++)
                entry.Write(spaces);
        }
        return output.ToArray();
    }


    [Test(Description = "RFC 7489 §7.2.1.1: \"a commonly observed receiver limit is ten megabytes\" - plain XML beyond the reader's 20 MiB is refused, not parsed")]
    public void Plain_XML_beyond_the_limit_is_refused()
    {

        var xml = new Byte[DmarcReportReader.MaxXmlOctets + 1];
        Array.Fill(xml, (Byte) ' ');
        "<feedback>"u8.CopyTo(xml);

        Assert.That(DmarcReportReader.Unpack(xml), Is.Null);

    }


    public static IEnumerable<TestCaseData> Broken()
    {
        var gzip = Gzip(Encoding.UTF8.GetBytes(Report()));
        var zip  = Zip("report.xml", Encoding.UTF8.GetBytes(Report()));
        yield return new TestCaseData(gzip[..(gzip.Length / 2)]).SetName("A truncated gzip is no report");
        yield return new TestCaseData(zip[..(zip.Length / 2)]).  SetName("A truncated ZIP is no report");
        yield return new TestCaseData(Zip("report.txt", Encoding.UTF8.GetBytes(Report()))).SetName("A ZIP without an XML file is no report");
        yield return new TestCaseData(Encoding.UTF8.GetBytes(Report()[..(Report().Length / 2)])).SetName("Truncated XML is no report");
        yield return new TestCaseData(Encoding.UTF8.GetBytes("<feedback><report_metadata/></feedback>")).SetName("A report without policy_published is no report");
        yield return new TestCaseData(new Byte[] { 0x1F, 0x8B, 0x08, 0x00, 0xFF, 0xFF }).SetName("Six octets of gzip header are no report");
    }

    [TestCaseSource(nameof(Broken))]
    [Description("RFC 7489 §7.2.1.1: the aggregate data \"MUST be an XML file\" - what is not one, or is broken, is no report, and reading it does not throw")]
    public void What_is_broken_is_no_report(Byte[] Attachment)
    {

        DmarcReceivedReport? report = null;

        Assert.That(() => report = Read(Attachment), Throws.Nothing);
        Assert.That(report, Is.Null);

    }


    public static IEnumerable<TestCaseData> Depths()
    {
        yield return new TestCaseData(1_000). SetName("Nesting 1000 deep is read");
        yield return new TestCaseData(50_000).SetName("Nesting 50000 deep does not end the process").
                                              SetProperty("Finding", "I-2");
    }

    [TestCaseSource(nameof(Depths))]
    [Description("RFC 7489 §7.2.1.1: a report is what a stranger sends - 50000 elements nested in <domain>, 350 KiB of XML, well inside the 20 MiB the reader allows, are read or refused; the process reading them goes on. Run in a process of its own, on a 1.5 MiB stack")]
    [CancelAfter(120_000)]
    public async Task Deep_nesting_is_read_or_refused(Int32 Depth)
    {

        var file = Path.Combine(Path.GetTempPath(), $"dmarc-deep-{Guid.NewGuid():N}.xml");

        File.WriteAllText(file, "<?xml version=\"1.0\"?><feedback><policy_published><domain>" +
                                String.Concat(Enumerable.Repeat("<a>", Depth)) + "hermod.test" + String.Concat(Enumerable.Repeat("</a>", Depth)) +
                                "</domain></policy_published></feedback>");

        try
        {

            var (exitCode, output) = await IsolatedProcess.RunAsync(TimeSpan.FromSeconds(90), "dmarc-parse", file);

            Assert.Multiple(() => {
                Assert.That(exitCode, Is.EqualTo(0),               output);
                Assert.That(output,   Does.StartWith("parsed: "),  output);
            });

        }
        finally
        {
            File.Delete(file);
        }

    }

    #endregion

}
