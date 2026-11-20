using System.Security.Cryptography;
using System.Text.RegularExpressions;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core;
using SMTPConformance.Core.Fixtures;

namespace SMTPConformance.Client.Tests;

public sealed partial class OutboundClientTests
{

    #region The DKIM keys Hermod makes, and signs with

    private const String KeyTestMessage = "From: <news@hermod.test>\r\n" +
                                          "To: <you@outbound.test>\r\n" +
                                          "Subject: key size\r\n" +
                                          "Date: Fri, 20 Nov 2026 10:00:00 +0000\r\n" +
                                          "Message-ID: <keysize@hermod.test>\r\n" +
                                          "\r\n" +
                                          "Hello.\r\n";

    #region P-2: RSA keys of fewer than 1024 bits

    [Test(Description = "RFC 8301 §3.2: \"Signers MUST use RSA keys of at least 1024 bits for all keys\" - a signer given a 512-bit key refuses it, or signs nothing with it")]
    [Category(TestCategories.KnownIssue), Property("Finding", "P-2")]
    public void The_signer_does_not_sign_with_a_key_of_512_bits()
    {

        using var rsa = RSA.Create(512);
        var config    = new DkimConfig { Domain = "hermod.test", Selector = "small", PrivateKeyPem = rsa.ExportPkcs8PrivateKeyPem() };

        String? signed = null;

        try
        {
            signed = new DkimSigner(config, new CapturingLogger()).SignMessage(KeyTestMessage);
        }
        catch (ArgumentException)
        {
            // Refused: as good as not signing.
        }

        Assert.That(signed ?? "", Does.Not.Contain("DKIM-Signature"), signed);

    }


    [Test(Description = "RFC 8301 §3.2: \"Signers MUST use RSA keys of at least 1024 bits for all keys. Signers SHOULD use RSA keys of at least 2048 bits\" - the key generators do not make a 512-bit key")]
    [Category(TestCategories.KnownIssue), Property("Finding", "P-2")]
    public void The_key_generators_do_not_make_a_key_of_512_bits()
    {

        Assert.Multiple(() => {
            Assert.That(() => DkimKeyGenerator.GenerateKeyPair("hermod.test", "small", 512),  Throws.InstanceOf<ArgumentException>(), "DkimKeyGenerator.GenerateKeyPair");
            Assert.That(() => DkimKeyMaterial.NewRsaPem(512),                                 Throws.InstanceOf<ArgumentException>(), "DkimKeyMaterial.NewRsaPem");
        });

    }


    [Test(Description = "RFC 8301 §3.2: by default, the key generators make keys of at least 2048 bits - a guard for P-2")]
    [Property("Finding", "P-2")]
    public void The_key_generators_make_keys_of_2048_bits_by_default()
    {

        using var generated = RSA.Create();
        generated.ImportFromPem(DkimKeyGenerator.GenerateKeyPair("hermod.test", "big").PrivateKeyPem);

        using var made = RSA.Create();
        made.ImportFromPem(DkimKeyMaterial.NewRsaPem());

        Assert.Multiple(() => {
            Assert.That(generated.KeySize, Is.GreaterThanOrEqualTo(2048), "DkimKeyGenerator.GenerateKeyPair");
            Assert.That(made.KeySize,      Is.GreaterThanOrEqualTo(2048), "DkimKeyMaterial.NewRsaPem");
        });

    }

    #endregion

    #region P-3: the key record as a zone file line

    /// <summary>
    /// The character-strings of the TXT record in the zone file line the generator writes.
    /// </summary>
    private static List<String> CharacterStrings(String ZoneFileLine)
        => [ .. Regex.Matches(ZoneFileLine, "\"((?:[^\"\\\\]|\\\\.)*)\"").Select(match => match.Groups[1].Value) ];


    [Test(Description = "RFC 1035 §3.3: \"<character-string> is a single length octet followed by that number of characters\" - at most 255; RFC 6376 §3.6.2.2: \"Strings in a TXT RR MUST be concatenated together before use with no intervening whitespace\" - the record of a 2048-bit key, 410 characters, is written as several strings, each of at most 255")]
    [Category(TestCategories.KnownIssue), Property("Finding", "P-3")]
    public void The_generated_key_record_is_written_in_strings_of_at_most_255_characters()
    {

        var (_, _, line) = DkimKeyGenerator.GenerateKeyPair("hermod.test", "zone");
        var strings      = CharacterStrings(line);

        Assert.That(strings.Select(text => text.Length), Has.All.LessThanOrEqualTo(255), line);

    }


    [Test(Description = "RFC 6376 §3.6.1: joined, the strings are the key record of the key - v=DKIM1, k=rsa, and the public key in p= - at selector._domainkey.domain: a guard for P-3")]
    [Property("Finding", "P-3")]
    public void The_generated_key_record_names_the_generated_key()
    {

        var (privateKey, _, line) = DkimKeyGenerator.GenerateKeyPair("hermod.test", "zone");

        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKey);

        var record = String.Concat(CharacterStrings(line));

        Assert.Multiple(() => {
            Assert.That(line,    Does.StartWith("zone._domainkey.hermod.test."));
            Assert.That(record,  Does.StartWith("v=DKIM1;"));
            Assert.That(record,  Does.Contain("k=rsa"));
            Assert.That(record,  Does.EndWith("p=" + Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo())));
        });

    }

    #endregion

    #endregion

}
