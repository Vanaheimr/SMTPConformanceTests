using NUnit.Framework;

namespace SMTPConformance.Auth.Tests;

/// <summary>
/// The SCRAM oracle is only worth something if it is right. RFC 7677 §3 gives a
/// complete SCRAM-SHA-256 exchange; the oracle has to reproduce it byte for byte.
/// </summary>
[TestFixture]
public sealed class ScramOracleTests
{

    [Test(Description = "RFC 7677 §3: the example exchange (user \"user\", password \"pencil\") is reproduced exactly")]
    public void The_oracle_reproduces_the_rfc_7677_example()
    {

        var scram       = new ScramSha256("user", "pencil", "rOprNGfwEbeRWgbNEkqO");

        var clientFirst = scram.ClientFirst();
        var clientFinal = scram.ClientFinal("r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096");

        Assert.Multiple(() => {
            Assert.That(clientFirst,                 Is.EqualTo("n,,n=user,r=rOprNGfwEbeRWgbNEkqO"));
            Assert.That(clientFinal,                 Is.EqualTo("c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="));
            Assert.That(scram.ExpectedServerFinal(), Is.EqualTo("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="));
        });

    }

}
