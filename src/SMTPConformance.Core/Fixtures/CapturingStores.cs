using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Channels;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;
using org.GraphDefined.Vanaheimr.Hermod.SMTP.Server;

namespace SMTPConformance.Core.Fixtures;

/// <summary>
/// One message as the server handed it to local storage.
/// </summary>
public sealed record StoredMessage(EMailMessage           Message,
                                   String                 EnvelopeFrom,
                                   IReadOnlyList<String>  EnvelopeTo)
{

    /// <summary>
    /// The message as stored, trace headers included.
    /// </summary>
    public String Raw
        => Message.RawMessage;

}


/// <summary>
/// An <see cref="IMailStorage"/> that keeps every delivered message in memory, so a
/// test can assert on exactly what the server accepted — byte for byte, after its
/// own dot-unstuffing, trace stamping and decoding.
/// </summary>
public sealed class CapturingMailStorage : IMailStorage
{


    private readonly ConcurrentQueue<StoredMessage>  stored   = new();

    public IReadOnlyCollection<StoredMessage> Messages
        => stored;

    public Task<String> StoreAsync(EMailMessage         message,
                                   String               envelopeFrom,
                                   IEnumerable<String>  envelopeTo,
                                   CancellationToken    ct = default)
    {

        var entry = new StoredMessage(message, envelopeFrom, [.. envelopeTo]);

        stored.Enqueue(entry);


        return Task.FromResult($"memory://{stored.Count}");

    }

    /// <summary>
    /// The first stored message that satisfies <paramref name="Predicate"/>, waiting for
    /// it if need be. Null if none arrives in time.
    /// </summary>
    /// <remarks>
    /// Tests in one fixture share a server, so "the next message" could be one a
    /// previous test left behind. Every test therefore marks its message (a unique
    /// subject, usually) and waits for that.
    /// </remarks>
    public async Task<StoredMessage?> WaitForAsync(Func<StoredMessage, Boolean> Predicate,
                                                   TimeSpan?                    Timeout = null)
    {

        var deadline = DateTime.UtcNow + (Timeout ?? TimeSpan.FromSeconds(5));

        while (true)
        {

            var match = stored.FirstOrDefault(Predicate);

            if (match is not null)
                return match;

            if (DateTime.UtcNow >= deadline)
                return null;

            await Task.Delay(20);

        }

    }

    /// <summary>
    /// The stored message whose raw text contains <paramref name="Marker"/>.
    /// </summary>
    public Task<StoredMessage?> WaitForMarkerAsync(String Marker, TimeSpan? Timeout = null)
        => WaitForAsync(message => message.Raw.Contains(Marker, StringComparison.Ordinal), Timeout);

    /// <summary>
    /// How many stored messages contain <paramref name="Marker"/> — for asserting that
    /// something was <i>not</i> delivered, or not twice.
    /// </summary>
    public Int32 CountWithMarker(String Marker)
        => stored.Count(message => message.Raw.Contains(Marker, StringComparison.Ordinal));

}


/// <summary>
/// An <see cref="IMailQueue"/> that only records what the server queued for relay.
/// Nothing is ever delivered.
/// </summary>
public sealed class CapturingMailQueue : IMailQueue
{

    private readonly ConcurrentDictionary<String, QueuedMail> mails = new();
    private readonly Channel<QueuedMail>                      newMail = Channel.CreateUnbounded<QueuedMail>();
    private readonly Channel<Boolean>                         retry   = Channel.CreateUnbounded<Boolean>();

    public IReadOnlyCollection<QueuedMail> Queued
        => [.. mails.Values];

    public Task EnqueueAsync(QueuedMail mail, CancellationToken ct = default)
    {
        mails[mail.Id] = mail;
        newMail.Writer.TryWrite(mail);
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<QueuedMail>> GetPendingAsync(Int32 maxItems = 50, CancellationToken ct = default)
        => Task.FromResult<IReadOnlyList<QueuedMail>>([]);

    public Task<QueuedMail?> GetByIdAsync(String id, CancellationToken ct = default)
        => Task.FromResult(mails.TryGetValue(id, out var mail) ? mail : null);

    public Task UpdateAsync(QueuedMail mail, CancellationToken ct = default)
    {
        mails[mail.Id] = mail;
        return Task.CompletedTask;
    }

    public Task RemoveAsync(String id, CancellationToken ct = default)
    {
        mails.TryRemove(id, out _);
        return Task.CompletedTask;
    }

    public Task<Int32> GetQueueLengthAsync(CancellationToken ct = default)
        => Task.FromResult(mails.Count);

    public Task<IReadOnlyList<QueuedMail>> GetFailedAsync(Int32 maxItems = 100, CancellationToken ct = default)
        => Task.FromResult<IReadOnlyList<QueuedMail>>([]);

    public ChannelReader<QueuedMail> NewMailReader
        => newMail.Reader;

    public void SignalRetryCheck()
        => retry.Writer.TryWrite(true);

    public ChannelReader<Boolean> RetryCheckReader
        => retry.Reader;

}


/// <summary>
/// An <see cref="IUserStore"/> held in memory, with PLAIN/LOGIN hashes and SCRAM-SHA-256
/// credentials derived from the clear-text passwords a test hands in.
/// </summary>
public sealed class InMemoryUserStore : IUserStore
{

    private readonly Dictionary<String, (UserCredentials Credentials, String Password)> users = new(StringComparer.Ordinal);

    public InMemoryUserStore(IEnumerable<KeyValuePair<String, String>> UsersAndPasswords)
    {
        foreach (var (user, password) in UsersAndPasswords)
            Add(user, password);
    }

    public void Add(String Username, String Password, params String[] AllowedCertThumbprints)
    {

        var scram = ScramCredentialGenerator.Generate(Password);

        users[Username] = (new UserCredentials(
                               Username,
                               Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Password))),
                               scram.SaltBase64,
                               scram.StoredKeyBase64,
                               scram.ServerKeyBase64,
                               scram.Iterations,
                               AllowedCertThumbprints
                           ),
                           Password);

    }

    public Task<UserCredentials?> GetUserAsync(String username, CancellationToken ct = default)
        => Task.FromResult(users.TryGetValue(username, out var user) ? user.Credentials : null);

    public Task<UserCredentials?> GetUserByCertificateAsync(X509Certificate2 cert, CancellationToken ct = default)
        => Task.FromResult(users.Values.Select(user => user.Credentials).
                                        FirstOrDefault(credentials => credentials.AllowedCertThumbprints.Contains(cert.Thumbprint, StringComparer.OrdinalIgnoreCase)));

    public Task<Boolean> ValidatePasswordAsync(String username, String password, CancellationToken ct = default)
        => Task.FromResult(users.TryGetValue(username, out var user) && user.Password == password);

}


/// <summary>
/// The SMTP server's own log, kept for failure messages rather than printed.
/// </summary>
public sealed class CapturingLogger : org.GraphDefined.Vanaheimr.Hermod.SMTP.ILogger
{

    private readonly ConcurrentQueue<String> lines = new();

    public IReadOnlyCollection<String> Lines
        => lines;

    public void Log(LogLevel level, String message)
        => lines.Enqueue($"{DateTimeOffset.UtcNow:HH:mm:ss.fff} {level,-7} {message}");

    public override String ToString()
        => String.Join(Environment.NewLine, lines);

}
