using Google.Cloud.Firestore;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace SMD.AspNetCore.Identity.Firestore
{
    public interface IFirestoreDbContext
    {
        CollectionReference Collection(string path);
        WriteBatch StartBatch();
        Task<IList<DocumentSnapshot>> GetAllSnapshotsAsync(IEnumerable<DocumentReference> documents, CancellationToken cancellationToken = default);
        Task RunTransactionAsync(Func<Transaction, Task> callback, TransactionOptions options = null, CancellationToken cancellationToken = default);
        Task<T> RunTransactionAsync<T>(Func<Transaction, Task<T>> callback, TransactionOptions options = null, CancellationToken cancellationToken = default);
    }

    public class FirestoreDbContext : IFirestoreDbContext
    {
        private readonly FirestoreDb _db;

        public FirestoreDbContext(FirestoreDb db)
        {
            _db = db ?? throw new ArgumentNullException(nameof(db));
        }

        public CollectionReference Collection(string path)
        {
            return _db.Collection(path);
        }
        public Task<IList<DocumentSnapshot>> GetAllSnapshotsAsync(IEnumerable<DocumentReference> documents, CancellationToken cancellationToken = default)
        {
            return _db.GetAllSnapshotsAsync(documents, cancellationToken);
        }

        public WriteBatch StartBatch()
        {
            return _db.StartBatch();
        }

        public Task<T> RunTransactionAsync<T>(Func<Transaction, Task<T>> callback, TransactionOptions options = null, CancellationToken cancellationToken = default)
        {
            return _db.RunTransactionAsync<T>(callback, options, cancellationToken);
        }

        public Task RunTransactionAsync(Func<Transaction, Task> callback, TransactionOptions options = null, CancellationToken cancellationToken = default)
        {
            return _db.RunTransactionAsync(callback, options, cancellationToken);
        }
    }
}
