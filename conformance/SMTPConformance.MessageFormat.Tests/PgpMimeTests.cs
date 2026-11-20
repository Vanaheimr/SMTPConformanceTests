using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

using SMTPConformance.Core;

namespace SMTPConformance.MessageFormat.Tests;

/// <summary>
/// RFC 3156 (MIME Security with OpenPGP) on the framework of RFC 1847: what Hermod's
/// e-mail builders write when they sign (multipart/signed, §5) and encrypt (multipart/encrypted,
/// §4, signed in the combined form of §6.2), what <see cref="PgpMime"/> wraps around a signature
/// or ciphertext made elsewhere, and what <see cref="EMail.VerifyPgpSignature(PgpPublicKeyRing)"/>
/// and <see cref="EMail.DecryptAndVerifyPgp(PgpSecretKeyRing, String, PgpPublicKeyRing)"/> make of
/// a message from someone else - with RFC 9580 (OpenPGP) where RFC 3156 hands over to it. The
/// MIME is read by the suite's own reader below, the signatures checked and made, the
/// ciphertexts opened and sealed with BouncyCastle directly, not through Hermod's OpenPGP class.
/// </summary>
[TestFixture]
public sealed class PgpMimeTests
{

    #region Keys

    private const String Passphrase = "conformance-passphrase";

    private PgpSecretKeyRing  alice      = null!;   // the sender
    private PgpPublicKeyRing  alicePub   = null!;
    private PgpSecretKeyRing  bob        = null!;   // the recipient
    private PgpPublicKeyRing  bobPub     = null!;
    private PgpSecretKeyRing  mallory    = null!;   // somebody else
    private PgpPublicKeyRing  malloryPub = null!;

    [OneTimeSetUp]
    public void GenerateKeys()
    {
        (alice,   alicePub)   = KeyRing("Alice <alice@example.com>");
        (bob,     bobPub)     = KeyRing("Bob <bob@example.org>");
        (mallory, malloryPub) = KeyRing("Mallory <mallory@example.net>");
    }

    private static (PgpSecretKeyRing, PgpPublicKeyRing) KeyRing(String Identity)
    {

        var rsa = new RsaKeyPairGenerator();
        rsa.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), new SecureRandom(), 2048, 25));

        var generator = new PgpKeyRingGenerator(PgpSignature.PositiveCertification,
                                                new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, rsa.GenerateKeyPair(), DateTime.UtcNow),
                                                Identity, SymmetricKeyAlgorithmTag.Aes256, Passphrase.ToCharArray(),
                                                true, null, null, new SecureRandom());

        return (generator.GenerateSecretKeyRing(), generator.GeneratePublicKeyRing());

    }

    private EMailAddress AliceWithKey  => new ("Alice", SimpleEMailAddress.Parse("alice@example.com"), alice, alicePub);
    private EMailAddress BobWithKey    => new ("Bob",   SimpleEMailAddress.Parse("bob@example.org"),   null,  bobPub);
    private static EMailAddress BobNoKey => (EMailAddress) SimpleEMailAddress.Parse("bob@example.org");

    #endregion

    #region What Hermod builds

    private static String Marker()
        => "pgp-" + Guid.NewGuid().ToString("N")[..12];

    /// <summary>
    /// The message as it goes out: its lines with CRLF, no Bcc.
    /// </summary>
    private static String Wire(EMail Mail)
        => String.Join("\r\n", Mail.ToText(false)) + "\r\n";

    private String SignedByHermod(String Text, HashAlgorithmTag Hash = HashAlgorithmTag.Sha256, Action<TextEMailBuilder>? More = null)
    {

        var builder = new TextEMailBuilder {
                          From           = AliceWithKey,
                          To             = BobNoKey,
                          Subject        = "Signed",
                          Text           = Text,
                          SecurityLevel  = EMailSecurity.sign,
                          HashAlgorithm  = Hash,
                          Passphrase     = Passphrase
                      };

        More?.Invoke(builder);

        EMail mail = builder;
        return Wire(mail);

    }

    private String EncryptedByHermod(String Text)
    {

        var builder = new TextEMailBuilder {
                          From           = AliceWithKey,
                          To             = BobWithKey,
                          Subject        = "Encrypted",
                          Text           = Text,
                          SecurityLevel  = EMailSecurity.encrypt,
                          HashAlgorithm  = HashAlgorithmTag.Sha256,
                          Passphrase     = Passphrase
                      };

        EMail mail = builder;
        return Wire(mail);

    }

    /// <summary>
    /// Texts a signed part has to carry through a relay unchanged: ASCII, not ASCII, white
    /// space at the end of a line, a line that begins with "From ", a line too long for 7bit.
    /// </summary>
    public static IEnumerable<TestCaseData> Texts()
    {
        yield return new TestCaseData("Hello Bob,\nall is well.\n").                                    SetArgDisplayNames("ASCII");
        yield return new TestCaseData("Grüße, Bob!\nÜbermorgen.\n").                                   SetArgDisplayNames("not ASCII");
        yield return new TestCaseData("Trailing space   \nand a tab\t\nand none\n").                    SetArgDisplayNames("trailing white space");
        yield return new TestCaseData("Hello\nFrom here on the line begins with From\n").              SetArgDisplayNames("From line");
        yield return new TestCaseData(new String('x', 120) + "\n").                                     SetArgDisplayNames("long line");
    }

    #endregion

    #region The suite's own MIME reader

    /// <summary>
    /// An entity split at its first empty line, the header fields unfolded (RFC 5322 §2.2.3).
    /// </summary>
    private static (List<(String Name, String Value)> Headers, String Body) Entity(String Text)
    {

        var end     = Text.StartsWith("\r\n", StringComparison.Ordinal) ? 0 : Text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var header  = end <= 0 ? "" : Text[..end];
        var body    = end <  0 ? "" : Text[(end == 0 ? 2 : end + 4)..];
        var fields  = new List<(String, String)>();

        foreach (var line in header.Split("\r\n"))
        {
            if (line.Length == 0)
                continue;
            if ((line[0] == ' ' || line[0] == '\t') && fields.Count > 0)
                fields[^1] = (fields[^1].Item1, fields[^1].Item2 + line);
            else
            {
                var colon = line.IndexOf(':');
                fields.Add((line[..colon].Trim(), line[(colon + 1)..].Trim()));
            }
        }

        return (fields, body);

    }

    private static String? Field(List<(String Name, String Value)> Headers, String Name)
        => Headers.Where(h => h.Name.Equals(Name, StringComparison.OrdinalIgnoreCase)).Select(h => h.Value).FirstOrDefault();

    /// <summary>
    /// The media type of a Content-Type value, lower case.
    /// </summary>
    private static String MediaType(String? ContentType)
        => (ContentType ?? "text/plain").Split(';')[0].Trim().ToLowerInvariant();

    /// <summary>
    /// The parameters of a Content-Type value (RFC 2045 §5.1): name in lower case, the value
    /// unquoted, and whether it was a quoted-string.
    /// </summary>
    private static Dictionary<String, (String Value, Boolean Quoted)> Parameters(String? ContentType)
    {

        var result = new Dictionary<String, (String, Boolean)>();
        var text   = ContentType ?? "";
        var i      = text.IndexOf(';');

        while (i >= 0 && i < text.Length)
        {

            i++;
            while (i < text.Length && Char.IsWhiteSpace(text[i])) i++;
            var eq = text.IndexOf('=', i);
            if (eq < 0) break;
            var name = text[i..eq].Trim().ToLowerInvariant();
            i = eq + 1;

            if (i < text.Length && text[i] == '"')
            {
                var value = new StringBuilder();
                i++;
                while (i < text.Length && text[i] != '"')
                {
                    if (text[i] == '\\' && i + 1 < text.Length) i++;
                    value.Append(text[i++]);
                }
                result[name] = (value.ToString(), true);
                i = text.IndexOf(';', i);
            }
            else
            {
                var semi = text.IndexOf(';', i);
                result[name] = ((semi < 0 ? text[i..] : text[i..semi]).Trim(), false);
                i = semi;
            }

        }

        return result;

    }

    /// <summary>
    /// The body parts of a multipart body, each exactly as it stands between its delimiter
    /// line and the CRLF that belongs to the next delimiter (RFC 2046 §5.1.1).
    /// </summary>
    private static List<String> Parts(String Body, String Boundary)
    {

        var delimiter = "--" + Boundary;
        var parts     = new List<String>();
        var at        = Body.StartsWith(delimiter, StringComparison.Ordinal) ? 0 : Body.IndexOf("\r\n" + delimiter, StringComparison.Ordinal) + 2;

        if (at < 2 && !Body.StartsWith(delimiter, StringComparison.Ordinal))
            return parts;

        while (true)
        {

            var lineEnd = Body.IndexOf("\r\n", at, StringComparison.Ordinal);
            var line    = lineEnd < 0 ? Body[at..] : Body[at..lineEnd];

            if (line.StartsWith(delimiter + "--", StringComparison.Ordinal) || lineEnd < 0)
                return parts;

            var start   = lineEnd + 2;
            var next    = Body.IndexOf("\r\n" + delimiter, start - 2, StringComparison.Ordinal);

            if (next < 0)
                return parts;

            parts.Add(next < start ? "" : Body[start..next]);
            at = next + 2;

        }

    }

    /// <summary>
    /// A multipart message read: its Content-Type, its parameters and its parts.
    /// </summary>
    private static (String Type, Dictionary<String, (String Value, Boolean Quoted)> Parameters, List<String> Parts) Multipart(String Message)
    {
        var (headers, body) = Entity(Message);
        var contentType     = Field(headers, "Content-Type");
        var parameters      = Parameters(contentType);
        var parts           = parameters.TryGetValue("boundary", out var boundary) ? Parts(body, boundary.Value) : [];
        return (MediaType(contentType), parameters, parts);
    }

    #endregion

    #region The suite's own OpenPGP

    private static PgpPublicKey SigningKey(PgpPublicKeyRing Ring)
        => Ring.GetPublicKey();

    private static PgpPublicKey EncryptionKey(PgpPublicKeyRing Ring)
        => Ring.GetPublicKeys().Cast<PgpPublicKey>().FirstOrDefault(key => key.IsEncryptionKey) ?? Ring.GetPublicKey();

    private static PgpSignature ReadSignature(String Armored)
    {

        using var input = PgpUtilities.GetDecoderStream(new MemoryStream(Encoding.ASCII.GetBytes(Armored)));
        var found       = new PgpObjectFactory(input).NextPgpObject();

        if (found is PgpCompressedData compressed)
            found = new PgpObjectFactory(compressed.GetDataStream()).NextPgpObject();

        return found is PgpSignatureList list && list.Count > 0
                   ? list[0]
                   : throw new AssertionException("The signature part holds no OpenPGP signature.");

    }

    private static Boolean Holds(PgpSignature Signature, Byte[] Signed, PgpPublicKeyRing Signer)
    {
        Signature.InitVerify(SigningKey(Signer));
        Signature.Update(Signed);
        return Signature.Verify();
    }

    private static String Armor(Byte[] Binary)
    {
        using var output = new MemoryStream();
        using (var armor = new ArmoredOutputStream(output))
            armor.Write(Binary);
        return Encoding.ASCII.GetString(output.ToArray());
    }

    /// <summary>
    /// A detached signature over the octets, armored - binary document (0x00) or canonical
    /// text (0x01), RFC 9580 §5.2.1.
    /// </summary>
    private static String Sign(Byte[] Data, PgpSecretKeyRing Signer, HashAlgorithmTag Hash = HashAlgorithmTag.Sha256, Int32 Type = PgpSignature.BinaryDocument)
    {

        var key       = Signer.GetSecretKey();
        var generator = new PgpSignatureGenerator(key.PublicKey.Algorithm, Hash);
        generator.InitSign(Type, key.ExtractPrivateKey(Passphrase.ToCharArray()));
        generator.Update(Data);

        using var binary = new MemoryStream();
        generator.Generate().Encode(binary);
        return Armor(binary.ToArray());

    }

    /// <summary>
    /// An OpenPGP message to Bob: the literal data, signed by the given key or not, in a SEIPD
    /// packet with its MDC (RFC 9580 §5.13.1) or in the obsolete SED packet (§5.7). Binary.
    /// </summary>
    private Byte[] EncryptToBob(Byte[] Plaintext, Boolean IntegrityProtected = true, PgpSecretKeyRing? SignedBy = null)
    {

        using var output = new MemoryStream();

        var encryption = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, IntegrityProtected, new SecureRandom());
        encryption.AddMethod(EncryptionKey(bobPub));

        using (var encrypted = encryption.Open(output, new Byte[1 << 12]))
        {

            PgpSignatureGenerator? signer = null;

            if (SignedBy is not null)
            {
                var key = SignedBy.GetSecretKey();
                signer  = new PgpSignatureGenerator(key.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
                signer.InitSign(PgpSignature.BinaryDocument, key.ExtractPrivateKey(Passphrase.ToCharArray()));
                signer.GenerateOnePassVersion(false).Encode(encrypted);
            }

            using (var literal = new PgpLiteralDataGenerator().Open(encrypted, PgpLiteralData.Binary, "", Plaintext.Length, DateTime.UtcNow))
                literal.Write(Plaintext);

            if (signer is not null)
            {
                signer.Update(Plaintext);
                signer.Generate().Encode(encrypted);
            }

        }

        return output.ToArray();

    }

    /// <summary>
    /// A multipart/encrypted message to Bob around an armored OpenPGP message (RFC 3156 §4).
    /// </summary>
    private static String EncryptedMessage(String ArmoredCiphertext)

        => "From: Alice <alice@example.com>\r\n" +
           "To: Bob <bob@example.org>\r\n" +
           "Subject: Encrypted\r\n" +
           "MIME-Version: 1.0\r\n" +
           "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"enc-boundary\"\r\n" +
           "\r\n" +
           "--enc-boundary\r\n" +
           "Content-Type: application/pgp-encrypted\r\n" +
           "\r\n" +
           "Version: 1\r\n" +
           "\r\n" +
           "--enc-boundary\r\n" +
           "Content-Type: application/octet-stream\r\n" +
           "\r\n" +
           ArmoredCiphertext.Replace("\r\n", "\n").Replace("\n", "\r\n").TrimEnd() + "\r\n" +
           "--enc-boundary--\r\n";

    /// <summary>
    /// A multipart/signed message with the given parts after the signed one (RFC 3156 §5).
    /// </summary>
    private static String SignedMessage(String SignedPart, String SignaturePart, String Protocol = "application/pgp-signature", params String[] More)
    {

        var message = new StringBuilder();

        message.Append("From: Alice <alice@example.com>\r\n");
        message.Append("To: Bob <bob@example.org>\r\n");
        message.Append("Subject: Signed\r\n");
        message.Append("MIME-Version: 1.0\r\n");
        message.Append($"Content-Type: multipart/signed; micalg=\"pgp-sha256\"; protocol=\"{Protocol}\"; boundary=\"sig-boundary\"\r\n");
        message.Append("\r\n");
        message.Append("--sig-boundary\r\n").Append(SignedPart).Append("\r\n");
        message.Append("--sig-boundary\r\n").Append(SignaturePart).Append("\r\n");

        foreach (var part in More)
            message.Append("--sig-boundary\r\n").Append(part).Append("\r\n");

        message.Append("--sig-boundary--\r\n");

        return message.ToString();

    }

    private static String SignaturePart(String Armored)
        => "Content-Type: application/pgp-signature; name=\"signature.asc\"\r\n\r\n" + Armored.Replace("\r\n", "\n").Replace("\n", "\r\n").TrimEnd();

    private const String ForeignSignedPart = "Content-Type: text/plain; charset=us-ascii\r\n" +
                                             "Content-Transfer-Encoding: 7bit\r\n" +
                                             "\r\n" +
                                             "Bob, please pay the invoice 4711.\r\n" +
                                             "Alice";

    private static EMail Parse(String Message)
        => EMail.Parse(Message.Split("\r\n"));

    #endregion


    #region The builders: multipart/signed (RFC 3156 §5)

    [Test(Description = "RFC 3156 §5: multipart/signed \"with a \"protocol\" parameter which MUST have a value of \"application/pgp-signature\" (MUST be quoted)\"")]
    public void A_signed_mail_is_multipart_signed_with_the_protocol_quoted()
    {

        var (type, parameters, _) = Multipart(SignedByHermod("Hello Bob.\n"));

        Assert.Multiple(() => {
            Assert.That(type,                                      Is.EqualTo("multipart/signed"));
            Assert.That(parameters.GetValueOrDefault("protocol"),  Is.EqualTo(("application/pgp-signature", true)));
        });

    }


    [TestCase(HashAlgorithmTag.Sha1,      "pgp-sha1")]
    [TestCase(HashAlgorithmTag.RipeMD160, "pgp-ripemd160")]
    [TestCase(HashAlgorithmTag.Sha224,    "pgp-sha224")]
    [TestCase(HashAlgorithmTag.Sha256,    "pgp-sha256")]
    [TestCase(HashAlgorithmTag.Sha384,    "pgp-sha384")]
    [TestCase(HashAlgorithmTag.Sha512,    "pgp-sha512")]
    [Test(Description = "RFC 3156 §5: micalg \"MUST contain exactly one hash-symbol of the format \"pgp-<hash-identifier>\", where <hash-identifier> identifies the Message Integrity Check (MIC) algorithm used to generate the signature\" - the text name of RFC 9580 §9.5, lower case")]
    public void The_micalg_names_the_hash_the_signature_was_made_with(HashAlgorithmTag Hash, String MicAlg)
    {

        var (_, parameters, parts) = Multipart(SignedByHermod("Hello Bob.\n", Hash));
        var signature              = ReadSignature(Entity(parts[1]).Body);

        Assert.Multiple(() => {
            Assert.That(parameters.GetValueOrDefault("micalg").Value,  Is.EqualTo(MicAlg));
            Assert.That(signature.HashAlgorithm,                       Is.EqualTo(Hash), "the hash the signature itself names");
        });

    }


    [TestCase(HashAlgorithmTag.Sha3_256,  "pgp-sha3-256")]
    [TestCase(HashAlgorithmTag.Sha3_512,  "pgp-sha3-512")]
    [Test(Description = "RFC 3156 §5: \"Hash-symbols are constructed from the text names registered in [1] ... by converting the text name to lower case and prefixing it with the four characters \"pgp-\"\"; RFC 9580 §9.5 registers the text names \"SHA3-256\" and \"SHA3-512\"")]
    [Property("Finding", "G-6")]
    public void The_micalg_of_a_SHA3_signature_is_its_registered_text_name(HashAlgorithmTag Hash, String MicAlg)
    {

        var (_, parameters, parts) = Multipart(SignedByHermod("Hello Bob.\n", Hash));
        var signature              = ReadSignature(Entity(parts[1]).Body);

        Assert.Multiple(() => {
            Assert.That(parameters.GetValueOrDefault("micalg").Value,  Is.EqualTo(MicAlg));
            Assert.That(signature.HashAlgorithm,                       Is.EqualTo(Hash), "the hash the signature itself names");
        });

    }


    [Test(Description = "RFC 3156 §5: \"The multipart/signed body MUST consist of exactly two parts\" ... \"The second body MUST contain the OpenPGP digital signature. It MUST be labeled with a content type of \"application/pgp-signature\"\"")]
    public void A_signed_mail_has_two_parts_the_second_an_application_pgp_signature()
    {

        var (_, _, parts) = Multipart(SignedByHermod("Hello Bob.\n"));

        Assert.That(parts, Has.Count.EqualTo(2));
        Assert.That(MediaType(Field(Entity(parts[1]).Headers, "Content-Type")), Is.EqualTo("application/pgp-signature"));

    }


    [TestCaseSource(nameof(Texts))]
    [Test(Description = "RFC 3156 §5: \"the digital signature MUST be calculated over both the data to be signed and its set of content headers\" ... \"(signed message and transmitted message MUST be identical)\" - the first part, as sent, verifies")]
    public void The_signature_holds_over_the_first_part_as_sent(String Text)
    {

        var (_, _, parts) = Multipart(SignedByHermod(Text));
        var signature     = ReadSignature(Entity(parts[1]).Body);

        Assert.That(Holds(signature, Encoding.ASCII.GetBytes(parts[0]), alicePub), Is.True, parts[0]);

    }


    [TestCaseSource(nameof(Texts))]
    [Test(Description = "RFC 3156 §3: \"all data signed according to this protocol MUST be constrained to 7 bits\" ... \"implementations MUST make sure that no trailing whitespace is present after the MIME encoding has been applied\"")]
    public void The_signed_part_is_7bit_without_trailing_white_space(String Text)
    {

        var (_, _, parts) = Multipart(SignedByHermod(Text));
        var lines         = parts[0].Split("\r\n");

        Assert.Multiple(() => {
            Assert.That(parts[0].All(c => c < 128),                                    Is.True, "7 bit");
            Assert.That(lines.Where(line => line.EndsWith(' ') || line.EndsWith('\t')), Is.Empty, "no trailing white space");
            Assert.That(lines.Where(line => line.StartsWith("From ")),                   Is.Empty, "no line that begins with \"From \"");
            Assert.That(lines.Max(line => line.Length),                                  Is.LessThanOrEqualTo(998));
        });

    }


    [Test(Description = "RFC 3156 §5 with RFC 1847 §2.1: the first part of multipart/signed \"may contain any valid MIME content type\" - text and an attachment in a multipart/mixed, signed with its headers, verify as sent")]
    public void A_signed_mail_with_an_attachment_holds()
    {

        var (_, _, parts) = Multipart(SignedByHermod("See the attachment.\n", More: builder => builder.AddAttachment(Encoding.UTF8.GetBytes("%PDF-1.7 not really"), "invoice.pdf")));
        var signature     = ReadSignature(Entity(parts[1]).Body);

        Assert.Multiple(() => {
            Assert.That(MediaType(Field(Entity(parts[0]).Headers, "Content-Type")),  Is.EqualTo("multipart/mixed"));
            Assert.That(Holds(signature, Encoding.ASCII.GetBytes(parts[0]), alicePub), Is.True);
        });

    }


    [Test(Description = "RFC 3156 §3: \"implementations MUST make sure that no trailing whitespace is present after the MIME encoding has been applied\"; §5: \"(signed message and transmitted message MUST be identical)\" - a text part the application attaches, with white space at the end of a line, is signed as it is sent")]
    [Property("Finding", "G-3")]
    public void An_attached_text_part_with_trailing_white_space_is_signed_as_sent()
    {

        var attachment = new EMailBodypart(ContentTypeBuilder:       _ => new MailContentType(MailContentTypes.text_plain) { CharSet = "us-ascii" },
                                           ContentTransferEncoding:  "7bit",
                                           ContentDisposition:       "attachment; filename=\"notes.txt\"",
                                           Content:                  [ "Item 1   ", "Item 2" ]);

        var (_, _, parts) = Multipart(SignedByHermod("Notes attached.\n", More: builder => builder.AddAttachment<TextEMailBuilder>(attachment)));
        var signature     = ReadSignature(Entity(parts[1]).Body);
        var lines         = parts[0].Split("\r\n");

        Assert.Multiple(() => {
            Assert.That(Holds(signature, Encoding.ASCII.GetBytes(parts[0]), alicePub),   Is.True,  "the signature over the part as sent");
            Assert.That(lines.Where(line => line.EndsWith(' ') || line.EndsWith('\t')), Is.Empty, "no trailing white space");
        });

    }


    [Test(Description = "RFC 3156 §3: \"all data signed according to this protocol MUST be constrained to 7 bits (8-bit data MUST be encoded using either Quoted-Printable or Base64)\" - a text part the application attaches in 8 bit is encoded before it is signed")]
    [Property("Finding", "G-3")]
    public void An_attached_8bit_text_part_is_signed_in_7bit()
    {

        var attachment = new EMailBodypart(ContentTypeBuilder:       _ => new MailContentType(MailContentTypes.text_plain) { CharSet = "utf-8" },
                                           ContentTransferEncoding:  "8bit",
                                           ContentDisposition:       "attachment; filename=\"notes.txt\"",
                                           Content:                  [ "Grüße aus Jena", "Item 2" ]);

        var message       = SignedByHermod("Notes attached.\n", More: builder => builder.AddAttachment<TextEMailBuilder>(attachment));
        var (_, _, parts) = Multipart(message);

        Assert.That(parts[0].All(c => c < 128), Is.True, parts[0]);

    }


    [Test(Description = "RFC 3156 §5: \"Upon receipt of a signed message, an application MUST\" ... \"Pass both the signed data and its associated content headers along with the OpenPGP signature to the signature verification service\" - Hermod's own verifier accepts what Hermod signed")]
    public void What_Hermod_signs_Hermod_verifies()
    {

        var verification = Parse(SignedByHermod("Grüße   \nFrom me\n")).VerifyPgpSignature(alicePub);

        Assert.That(verification.Status, Is.EqualTo(PgpVerificationStatus.Valid));

    }

    #endregion

    #region The builders: multipart/encrypted (RFC 3156 §4, §6.2)

    [Test(Description = "RFC 3156 §4: multipart/encrypted \"MUST have a \"protocol\" parameter value of \"application/pgp-encrypted\". Note that the value of the parameter MUST be enclosed in quotes\"; \"exactly two body parts, the first with content type \"application/pgp-encrypted\"\" with \"a \"Version: 1\" field\", the second \"MUST be labeled with a content type of \"application/octet-stream\"\"")]
    public void An_encrypted_mail_is_multipart_encrypted_as_section_4_has_it()
    {

        var (type, parameters, parts) = Multipart(EncryptedByHermod("Secret.\n"));

        Assert.Multiple(() => {

            Assert.That(type,                                      Is.EqualTo("multipart/encrypted"));
            Assert.That(parameters.GetValueOrDefault("protocol"),  Is.EqualTo(("application/pgp-encrypted", true)));
            Assert.That(parts,                                     Has.Count.EqualTo(2));

            Assert.That(MediaType(Field(Entity(parts[0]).Headers, "Content-Type")),  Is.EqualTo("application/pgp-encrypted"));
            Assert.That(Entity(parts[0]).Body.Split("\r\n"),                         Has.Member("Version: 1"));
            Assert.That(MediaType(Field(Entity(parts[1]).Headers, "Content-Type")),  Is.EqualTo("application/octet-stream"));
            Assert.That(Entity(parts[1]).Body.TrimStart(),                           Does.StartWith("-----BEGIN PGP MESSAGE-----"));

        });

    }


    /// <summary>
    /// Bob opens the ciphertext of an encrypted mail with BouncyCastle: the plaintext, whether
    /// the embedded signature holds for Alice, whether the MDC was there and held.
    /// </summary>
    private (Byte[] Plaintext, Boolean? SignedByAlice, Boolean IntegrityHeld) OpenAsBob(String Armored)
    {

        using var input   = PgpUtilities.GetDecoderStream(new MemoryStream(Encoding.ASCII.GetBytes(Armored)));
        var factory       = new PgpObjectFactory(input);
        var list          = factory.NextPgpObject() as PgpEncryptedDataList ?? factory.NextPgpObject() as PgpEncryptedDataList
                                ?? throw new AssertionException("no encrypted data list");
        var encrypted     = list.GetEncryptedDataObjects().Cast<PgpPublicKeyEncryptedData>().First(d => bob.GetSecretKey(d.KeyId) is not null);
        var clear         = new PgpObjectFactory(encrypted.GetDataStream(bob.GetSecretKey(encrypted.KeyId).ExtractPrivateKey(Passphrase.ToCharArray())));
        var next          = clear.NextPgpObject();

        if (next is PgpCompressedData compressed)
        {
            clear = new PgpObjectFactory(compressed.GetDataStream());
            next  = clear.NextPgpObject();
        }

        PgpOnePassSignature? onePass = null;
        if (next is PgpOnePassSignatureList onePassList)
        {
            onePass = onePassList[0];
            onePass.InitVerify(SigningKey(alicePub));
            next    = clear.NextPgpObject();
        }

        var literal   = (PgpLiteralData) next;
        using var raw = new MemoryStream();
        literal.GetInputStream().CopyTo(raw);
        var plaintext = raw.ToArray();

        Boolean? signed = null;
        if (onePass is not null)
        {
            onePass.Update(plaintext);
            signed = clear.NextPgpObject() is PgpSignatureList signatures && onePass.Verify(signatures[0]);
        }

        return (plaintext, signed, encrypted.IsIntegrityProtected() && encrypted.Verify());

    }


    [Test(Description = "RFC 3156 §6.2: the combined method signs and encrypts \"in a single OpenPGP message\"; §4: \"Before OpenPGP encryption, the data is written in MIME canonical format (body and headers)\" - Bob decrypts a MIME entity with its content headers, Alice's signature holds, and the MDC of RFC 9580 §5.13.1 is there")]
    public void An_encrypted_mail_opens_to_a_signed_MIME_entity()
    {

        var (_, _, parts)                       = Multipart(EncryptedByHermod("Secret.\n"));
        var (plaintext, signed, integrityHeld)  = OpenAsBob(Entity(parts[1]).Body);
        var inner                               = Encoding.UTF8.GetString(plaintext);

        Assert.Multiple(() => {
            Assert.That(MediaType(Field(Entity(inner).Headers, "Content-Type")),  Is.EqualTo("text/plain"), inner);
            Assert.That(Entity(inner).Body,                                       Does.Contain("Secret."));
            Assert.That(inner.Replace("\r\n", ""),                                Does.Not.Contain("\n").And.Not.Contain("\r"), "CRLF line ends");
            Assert.That(signed,                                                   Is.True,  "Alice's signature over the plaintext");
            Assert.That(integrityHeld,                                            Is.True,  "integrity protected, the MDC holds");
        });

    }


    [TestCaseSource(nameof(Texts))]
    [Test(Description = "RFC 3156 §6.2: \"Messages which are encrypted and signed in this combined fashion are REQUIRED to follow the same canonicalization rules as multipart/signed objects\" - 7 bit (§3), no trailing white space (§3, §5 step 4)")]
    public void The_combined_plaintext_is_canonical_as_a_signed_part(String Text)
    {

        var (_, _, parts)  = Multipart(EncryptedByHermod(Text));
        var (plaintext, _, _) = OpenAsBob(Entity(parts[1]).Body);
        var lines          = Encoding.UTF8.GetString(plaintext).Split("\r\n");

        Assert.Multiple(() => {
            Assert.That(plaintext.All(octet => octet < 128),                             Is.True, "7 bit");
            Assert.That(lines.Where(line => line.EndsWith(' ') || line.EndsWith('\t')), Is.Empty, "no trailing white space");
        });

    }


    [Test(Description = "RFC 3156 §6.2 and RFC 9580 §5.13.1: what Hermod encrypts and signs, Hermod decrypts for the recipient and finds signed by the sender")]
    public void What_Hermod_encrypts_Hermod_decrypts_and_finds_signed()
    {

        var result = Parse(EncryptedByHermod("Secret.\n")).DecryptAndVerifyPgp(bob, Passphrase, alicePub);

        Assert.Multiple(() => {
            Assert.That(result.IsSignatureValid,                                Is.True, result.Signature.Status.ToString());
            Assert.That(String.Join("\r\n", result.Body.ToText()),              Does.Contain("Secret."));
        });

    }

    #endregion

    #region PgpMime: around a signature or ciphertext made elsewhere

    private static Byte[] InnerPart(String Text = "Hello Bob.")
        => Encoding.ASCII.GetBytes("Content-Type: text/plain; charset=us-ascii\r\nContent-Transfer-Encoding: 7bit\r\n\r\n" + Text + "\r\n");

    private static String Write(MimeEntity Body)
    {
        var mail = new MimeMessageBuilder { From = new MailboxAddress("Alice", "alice@example.com"), Subject = "PGP/MIME", Body = Body };
        mail.To.Add(new MailboxAddress("Bob", "bob@example.org"));
        return Encoding.ASCII.GetString(mail.ToBytes());
    }


    [TestCase(HashAlgorithmTag.Sha256, "pgp-sha256")]
    [TestCase(HashAlgorithmTag.Sha384, "pgp-sha384")]
    [TestCase(HashAlgorithmTag.Sha512, "pgp-sha512")]
    [TestCase(HashAlgorithmTag.Sha1,   "pgp-sha1")]
    [Test(Description = "RFC 3156 §5: protocol=\"application/pgp-signature\" (quoted), micalg the hash \"used to generate the signature\", exactly two parts, the second application/pgp-signature, the first octet for octet what was signed")]
    public void PgpMime_Signed_wraps_a_signature_made_elsewhere(HashAlgorithmTag Hash, String MicAlg)
    {

        var inner                     = InnerPart();
        var (type, parameters, parts) = Multipart(Write(PgpMime.Signed(inner, Sign(inner, alice, Hash))));

        Assert.Multiple(() => {
            Assert.That(type,                                                           Is.EqualTo("multipart/signed"));
            Assert.That(parameters.GetValueOrDefault("protocol"),                       Is.EqualTo(("application/pgp-signature", true)));
            Assert.That(parameters.GetValueOrDefault("micalg").Value,                   Is.EqualTo(MicAlg));
            Assert.That(parts,                                                          Has.Count.EqualTo(2));
            Assert.That(MediaType(Field(Entity(parts[1]).Headers, "Content-Type")),     Is.EqualTo("application/pgp-signature"));
            Assert.That(Encoding.ASCII.GetBytes(parts[0]),                              Is.EqualTo(inner), "the signed part as it was signed");
            Assert.That(Holds(ReadSignature(Entity(parts[1]).Body), Encoding.ASCII.GetBytes(parts[0]), alicePub), Is.True);
        });

    }


    [Test(Description = "RFC 3156 §5 Note: the CRLF before a delimiter \"is not part of the signed data\" - a signed part that does not end with a line break is still sent octet for octet")]
    public void PgpMime_Signed_keeps_a_part_without_a_final_line_break()
    {

        var inner          = InnerPart()[..^2];
        var (_, _, parts)  = Multipart(Write(PgpMime.Signed(inner, Sign(inner, alice))));

        Assert.That(Encoding.ASCII.GetBytes(parts[0]), Is.EqualTo(inner));

    }


    [TestCase("Content-Type: text/plain\r\n\r\nGrüße\r\n", Description = "8 bit")]
    [TestCase("Content-Type: text/plain\n\nHello\n",                 Description = "bare LF")]
    [Test(Description = "RFC 3156 §3: \"all data signed according to this protocol MUST be constrained to 7 bits\"; §5: \"line endings in the encoded data MUST use the canonical <CR><LF> sequence\" - PgpMime.Signed refuses a part that is not")]
    public void PgpMime_Signed_refuses_a_part_that_is_not_7bit_with_CRLF(String Part)
    {

        var octets = Encoding.UTF8.GetBytes(Part);

        Assert.Throws<ArgumentException>(() => PgpMime.Signed(octets, Sign(octets, alice)));

    }


    [Test(Description = "RFC 3156 §3: \"implementations MUST make sure that no trailing whitespace is present after the MIME encoding has been applied\" - PgpMime.Signed, which refuses 8 bit and bare line ends for the same reason, takes white space at the end of a line")]
    [Property("Finding", "G-5")]
    public void PgpMime_Signed_refuses_a_part_with_trailing_white_space()
    {

        var octets = Encoding.ASCII.GetBytes("Content-Type: text/plain\r\n\r\nHello Bob,   \r\nAlice\r\n");

        Assert.Throws<ArgumentException>(() => PgpMime.Signed(octets, Sign(octets, alice)));

    }


    [Test(Description = "RFC 3156 §4: protocol=\"application/pgp-encrypted\" (quoted), two parts: application/pgp-encrypted with \"Version: 1\", then application/octet-stream with the ciphertext")]
    public void PgpMime_Encrypted_wraps_a_ciphertext_made_elsewhere()
    {

        var armored                   = Armor(EncryptToBob(InnerPart("Secret."), SignedBy: alice));
        var (type, parameters, parts) = Multipart(Write(PgpMime.Encrypted(armored)));

        Assert.Multiple(() => {
            Assert.That(type,                                                         Is.EqualTo("multipart/encrypted"));
            Assert.That(parameters.GetValueOrDefault("protocol"),                     Is.EqualTo(("application/pgp-encrypted", true)));
            Assert.That(parts,                                                        Has.Count.EqualTo(2));
            Assert.That(MediaType(Field(Entity(parts[0]).Headers, "Content-Type")),   Is.EqualTo("application/pgp-encrypted"));
            Assert.That(Entity(parts[0]).Body.Split("\r\n"),                          Has.Member("Version: 1"));
            Assert.That(MediaType(Field(Entity(parts[1]).Headers, "Content-Type")),   Is.EqualTo("application/octet-stream"));
            Assert.That(OpenAsBob(Entity(parts[1]).Body).Plaintext,                   Is.EqualTo(InnerPart("Secret.")));
        });

    }

    #endregion

    #region Receiving: VerifyPgpSignature

    [TestCase(PgpSignature.BinaryDocument,        Description = "binary document")]
    [TestCase(PgpSignature.CanonicalTextDocument, Description = "canonical text")]
    [Test(Description = "RFC 3156 §5: \"Implementations can either generate \"signatures of a canonical text document\" or \"signatures of a binary document\"\" - a message signed elsewhere, either way, verifies")]
    public void A_signature_made_elsewhere_verifies(Int32 SignatureType)
    {

        var armored      = Sign(Encoding.ASCII.GetBytes(ForeignSignedPart), alice, Type: SignatureType);
        var message      = Parse(SignedMessage(ForeignSignedPart, SignaturePart(armored)));

        Assert.Multiple(() => {
            Assert.That(message.IsPgpSigned,                           Is.True);
            Assert.That(message.VerifyPgpSignature(alicePub).Status,   Is.EqualTo(PgpVerificationStatus.Valid));
        });

    }


    [Test(Description = "RFC 3156 §5 Note: \"The accepted OpenPGP convention is for signed data to end with a <CR><LF> sequence\" ... the CRLF before the delimiter \"is not part of the signed data\" - a part signed with its own final line break verifies")]
    public void A_part_signed_with_its_final_line_break_verifies()
    {

        var part     = ForeignSignedPart + "\r\n";
        var armored  = Sign(Encoding.ASCII.GetBytes(part), alice);

        Assert.That(Parse(SignedMessage(part, SignaturePart(armored))).VerifyPgpSignature(alicePub).Status, Is.EqualTo(PgpVerificationStatus.Valid));

    }


    [TestCase("Bob, please pay the invoice 4711.", "Bob, please pay the invoice 4712.", Description = "the body")]
    [TestCase("charset=us-ascii",                  "charset=iso-8859-1",                Description = "a content header")]
    [TestCase("Alice",                             "Alice ",                            Description = "white space added")]
    [Test(Description = "RFC 1847 §2.1: \"The first body part is the body part over which the digital signature was created, including its MIME headers\" - a part changed after signing does not verify")]
    public void A_changed_part_does_not_verify(String Was, String Is_)
    {

        var armored = Sign(Encoding.ASCII.GetBytes(ForeignSignedPart), alice);
        var result  = Parse(SignedMessage(ForeignSignedPart.Replace(Was, Is_), SignaturePart(armored))).VerifyPgpSignature(alicePub);

        Assert.That(result.Status, Is.EqualTo(PgpVerificationStatus.Invalid));

    }


    [Test(Description = "RFC 3156 §5: the signature is the sender's - one made with somebody else's key is not reported as valid for the sender")]
    public void A_signature_by_another_key_is_not_valid()
    {

        var armored = Sign(Encoding.ASCII.GetBytes(ForeignSignedPart), mallory);
        var result  = Parse(SignedMessage(ForeignSignedPart, SignaturePart(armored))).VerifyPgpSignature(alicePub);

        Assert.That(result.IsValid, Is.False, result.Status.ToString());

    }


    [Test(Description = "RFC 1847 §2.1 / RFC 3156 §5: a message that is not multipart/signed carries no signature - not reported as signed")]
    public void An_unsigned_mail_is_not_signed()
    {

        var message = Parse("From: Alice <alice@example.com>\r\nTo: Bob <bob@example.org>\r\nSubject: Plain\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nHello.\r\n");

        Assert.Multiple(() => {
            Assert.That(message.IsPgpSigned,                          Is.False);
            Assert.That(message.VerifyPgpSignature(alicePub).Status,  Is.EqualTo(PgpVerificationStatus.NoSignature));
        });

    }


    [Test(Description = "RFC 3156 §5: \"The multipart/signed body MUST consist of exactly two parts\"; RFC 1847 §2.1: \"The multipart/signed content type contains exactly two body parts\" - a third part, which no signature covers, does not ride along as signed")]
    [Property("Finding", "G-2")]
    public void A_multipart_signed_with_a_third_part_is_not_valid()
    {

        var armored  = Sign(Encoding.ASCII.GetBytes(ForeignSignedPart), alice);
        var message  = Parse(SignedMessage(ForeignSignedPart, SignaturePart(armored), More: "Content-Type: text/plain\r\n\r\nP.S.: No, pay the invoice to account 666 instead."));
        var result   = message.VerifyPgpSignature(alicePub);

        Assert.That(result.IsValid, Is.False, $"{result.Status} - with {message.Body?.NestedBodyparts.Count()} parts");

    }


    [Test(Description = "RFC 1847 §2.1: the second part \"is labeled according to the value of the protocol parameter\"; §2: \"If the value of the protocol parameter is unrecognized the MIME agent will not be able to process the security multipart\" - an S/MIME multipart/signed is neither verified as OpenPGP nor does it throw")]
    public void An_SMIME_signed_mail_is_not_verified_as_OpenPGP()
    {

        var smime   = "Content-Type: application/pkcs7-signature; name=smime.p7s\r\nContent-Transfer-Encoding: base64\r\n\r\nMIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0BBwEAAKCAMIIC";
        var message = Parse(SignedMessage(ForeignSignedPart, smime, Protocol: "application/pkcs7-signature"));

        PgpSignatureVerification? result = null;

        Assert.DoesNotThrow(() => result = message.VerifyPgpSignature(alicePub));
        Assert.That(result?.IsValid, Is.False);

    }


    public static IEnumerable<TestCaseData> NoSignatures()
    {
        yield return new TestCaseData("not a signature at all").                                                     SetArgDisplayNames("no armor");
        yield return new TestCaseData("-----BEGIN PGP SIGNATURE-----\r\n\r\nAAAA\r\n-----END PGP SIGNATURE-----").  SetArgDisplayNames("armor around a broken packet").   SetProperty("Finding", "G-4");
        yield return new TestCaseData("-----BEGIN PGP SIGNATURE-----\r\n\r\n%%%%\r\n-----END PGP SIGNATURE-----").  SetArgDisplayNames("armor around no base64").         SetProperty("Finding", "G-4");
    }


    [TestCaseSource(nameof(NoSignatures))]
    [Test(Description = "RFC 3156 §5: \"The second body MUST contain the OpenPGP digital signature\" - a second part that holds none is no valid signature, and a foreign sender's garbage there is answered with a result, not an exception")]
    public void A_signature_part_without_a_signature_is_not_valid(String Signature)
    {

        var message = Parse(SignedMessage(ForeignSignedPart, "Content-Type: application/pgp-signature\r\n\r\n" + Signature));

        PgpSignatureVerification? result = null;

        Assert.DoesNotThrow(() => result = message.VerifyPgpSignature(alicePub));
        Assert.That(result?.IsValid, Is.False);

    }

    #endregion

    #region Receiving: DecryptPgp, DecryptAndVerifyPgp

    [Test(Description = "RFC 3156 §6.2 combined method, from elsewhere: a message encrypted to Bob and signed by Alice decrypts, and the signature is found valid")]
    public void A_combined_message_made_elsewhere_decrypts_and_verifies()
    {

        var result = Parse(EncryptedMessage(Armor(EncryptToBob(InnerPart("Secret."), SignedBy: alice)))).DecryptAndVerifyPgp(bob, Passphrase, alicePub);

        Assert.Multiple(() => {
            Assert.That(result.IsSignatureValid,                    Is.True, result.Signature.Status.ToString());
            Assert.That(String.Join("\r\n", result.Body.ToText()),  Does.Contain("Secret."));
        });

    }


    [Test(Description = "RFC 3156 §6.2: an encrypted message that nobody signed - anyone with Bob's public key can write one - is not reported as signed")]
    public void An_encrypted_but_unsigned_message_is_not_reported_signed()
    {

        var result = Parse(EncryptedMessage(Armor(EncryptToBob(InnerPart("Pay Mallory."))))).DecryptAndVerifyPgp(bob, Passphrase, alicePub);

        Assert.That(result.IsSignatureValid, Is.False, result.Signature.Status.ToString());

    }


    [Test(Description = "RFC 3156 §6.2: a message signed by Mallory inside the encryption is not reported as signed by Alice")]
    public void An_encrypted_message_signed_by_another_key_is_not_valid_for_the_sender()
    {

        var result = Parse(EncryptedMessage(Armor(EncryptToBob(InnerPart("Pay Mallory."), SignedBy: mallory)))).DecryptAndVerifyPgp(bob, Passphrase, alicePub);

        Assert.That(result.IsSignatureValid, Is.False, result.Signature.Status.ToString());

    }


    [Test(Description = "RFC 3156 §6.1: \"the data is first signed as a multipart/signature body, and then encrypted\" - after decryption, the multipart/signed inside verifies")]
    public void A_signed_then_encrypted_message_decrypts_to_a_multipart_signed_that_verifies()
    {

        var armored   = Sign(Encoding.ASCII.GetBytes(ForeignSignedPart), alice);
        var signed    = SignedMessage(ForeignSignedPart, SignaturePart(armored));
        var inner     = signed[signed.IndexOf("Content-Type: multipart/signed", StringComparison.Ordinal)..];

        var body      = Parse(EncryptedMessage(Armor(EncryptToBob(Encoding.ASCII.GetBytes(inner))))).DecryptPgp(bob, Passphrase);
        var result    = EMail.Parse(body.RawContent ?? body.ToText()).VerifyPgpSignature(alicePub);

        Assert.Multiple(() => {
            Assert.That(body.IsPgpSigned,  Is.True);
            Assert.That(result.Status,     Is.EqualTo(PgpVerificationStatus.Valid));
        });

    }


    /// <summary>
    /// A plaintext long enough that a changed octet in its middle lies inside the literal data,
    /// far from the MDC at the end.
    /// </summary>
    private static Byte[] LongPlaintext
        => InnerPart(String.Join("\r\n", Enumerable.Range(1, 20).Select(i => $"Line {i:00}: pay the invoice to account 4711 as agreed.")));


    [Test(Description = "RFC 9580 §5.13.1: \"A mismatch of the hash indicates that the message has been modified and MUST be treated as a security problem\"; §13.7: \"it SHOULD NOT attempt to parse nor release decrypted data to the user\" - a ciphertext changed in transit is refused, not decrypted")]
    [Property("Finding", "G-1")]
    public void A_ciphertext_changed_in_transit_is_refused()
    {

        var ciphertext = EncryptToBob(LongPlaintext);
        ciphertext[ciphertext.Length - 300] ^= 0x01;

        var message = Parse(EncryptedMessage(Armor(ciphertext)));

        String released;

        try
        {
            released = String.Join("\r\n", message.DecryptPgp(bob, Passphrase).ToText());
        }
        catch (Exception)
        {
            return;   // refused
        }

        Assert.Fail("decrypted a modified ciphertext, ending in: " + released.Replace("\r\n", " | ")[^Math.Min(400, released.Length)..]);

    }


    [Test(Description = "RFC 9580 §5.7: the Symmetrically Encrypted Data packet \"is obsolete\" ... \"An implementation SHOULD reject such a packet and stop processing the message. If an implementation chooses to process the packet anyway, it MUST return a clear warning that a non-integrity-protected packet has been processed\" - DecryptPgp has no warning to give, so it refuses")]
    [Property("Finding", "G-1")]
    public void A_ciphertext_without_integrity_protection_is_refused()
    {

        var message = Parse(EncryptedMessage(Armor(EncryptToBob(LongPlaintext, IntegrityProtected: false))));

        Assert.That(() => message.DecryptPgp(bob, Passphrase), Throws.Exception, "decrypted a SED packet without a word");

    }

    #endregion

}
