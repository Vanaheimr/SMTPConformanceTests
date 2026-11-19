using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SMTP;

using SMTPConformance.Core.Fixtures;

namespace SMTPConformance.Client.Tests;

/// <summary>
/// RFC 5321 §6.1: a server that has said 250 "MUST NOT lose the message for frivolous reasons,
/// such as because the host later crashes" - Hermod's FileMailQueue, opened again after a
/// crash at each of the places a crash can come.
/// </summary>
/// <remarks>
/// A crash is the state of the queue directory it leaves; the tests write that state where
/// the queue keeps its entries (queue/pending/&lt;id&gt;.json) and open the queue again.
/// </remarks>
[TestFixture]
public sealed class FileMailQueueTests
{

    private String directory = null!;

    [SetUp]
    public void CreateDirectory()
        => directory = Directory.CreateTempSubdirectory("smtp-conformance-queue-").FullName;

    [TearDown]
    public void DeleteDirectory()
    {
        try { Directory.Delete(directory, recursive: true); } catch { }
    }

    private FileMailQueue Open()
        => new (directory, new CapturingLogger());

    private String PendingFile(String Id)
        => Path.Combine(directory, "queue", "pending", Id + ".json");

    /// <summary>
    /// Queue one message the way an application does - through MailSender - and return the
    /// entry the queue holds for it.
    /// </summary>
    private static async Task<QueuedMail> Enqueue(FileMailQueue Queue, String Marker)
    {

        var ids = await new MailSender(Queue, new CapturingLogger()).
                            SendAsync("app@hermod.test", [ "you@outbound.test" ],
                                      $"From: app@hermod.test\r\nTo: you@outbound.test\r\nSubject: {Marker}\r\n\r\nhello\r\n");

        return (await Queue.GetByIdAsync(ids.Single()))!;

    }


    [Test(Description = "RFC 5321 §6.1: a message the queue holds is still there - and due - when the queue is opened again (a guard)")]
    public async Task A_queued_message_survives_a_restart()
    {

        QueuedMail mail;

        using (var queue = Open())
            mail = await Enqueue(queue, "survives");

        using var reopened = Open();
        var pending = await reopened.GetPendingAsync();

        Assert.That(pending.Select(pending => pending.MessageContent), Is.EqualTo(new[] { mail.MessageContent }));

    }


    [Test(Description = "RFC 5321 §6.1: a message that was being delivered when the process ended may not have arrived - it is tried again, not dropped")]
    public async Task A_message_that_was_being_delivered_is_tried_again()
    {

        QueuedMail mail;

        using (var queue = Open())
        {
            mail        = await Enqueue(queue, "in flight");
            mail.Status = QueueItemStatus.Processing;
            await queue.UpdateAsync(mail);
        }

        using var reopened = Open();
        var pending = await reopened.GetPendingAsync();

        Assert.That(pending.Select(pending => pending.Id), Is.EqualTo(new[] { mail.Id }));

    }


    [Test(Description = "RFC 5321 §6.1: a crash after the delivered record was written but before the pending entry was removed - the message arrived, and is not sent a second time")]
    public async Task A_message_already_delivered_is_not_delivered_again()
    {

        QueuedMail mail;
        String     pendingEntry;

        using (var queue = Open())
        {
            mail           = await Enqueue(queue, "delivered");
            pendingEntry   = await File.ReadAllTextAsync(PendingFile(mail.Id));
            mail.Status    = QueueItemStatus.Delivered;
            mail.DeliveredAt = DateTimeOffset.UtcNow;
            await queue.UpdateAsync(mail);
        }

        // The pending entry as it was before the crash took the process.
        await File.WriteAllTextAsync(PendingFile(mail.Id), pendingEntry);

        using var reopened = Open();

        Assert.That(await reopened.GetPendingAsync(), Is.Empty);

    }


    [Test(Description = "RFC 5321 §6.1: an entry a crash left unreadable does not stop the queue - the other messages are still delivered")]
    public async Task An_unreadable_entry_does_not_hold_up_the_others()
    {

        QueuedMail mail;

        using (var queue = Open())
            mail = await Enqueue(queue, "intact");

        await File.WriteAllTextAsync(PendingFile("0000broken"), "{ \"Id\": \"0000broken\", \"EnvelopeFr");

        using var reopened = Open();
        var pending = await reopened.GetPendingAsync();

        Assert.That(pending.Select(pending => pending.Id), Is.EqualTo(new[] { mail.Id }));

    }


    [Test(Description = "RFC 5321 §6.1: a write a crash cut short leaves the entry as it was - a half-written copy beside it is not taken for the message")]
    public async Task A_write_cut_short_leaves_the_entry_as_it_was()
    {

        QueuedMail mail;

        using (var queue = Open())
            mail = await Enqueue(queue, "whole");

        // What a crash during the next update leaves: the beginning of the new content, beside the entry.
        var entry = await File.ReadAllTextAsync(PendingFile(mail.Id));
        await File.WriteAllTextAsync(Path.Combine(directory, "queue", "pending", $".{mail.Id}.json.{Guid.NewGuid():N}.tmp"), entry[..(entry.Length / 2)]);

        using var reopened = Open();
        var pending = await reopened.GetPendingAsync();

        Assert.Multiple(() => {
            Assert.That(pending.Select(pending => pending.Id),              Is.EqualTo(new[] { mail.Id }));
            Assert.That(pending.Select(pending => pending.MessageContent),  Is.EqualTo(new[] { mail.MessageContent }));
        });

    }

}
