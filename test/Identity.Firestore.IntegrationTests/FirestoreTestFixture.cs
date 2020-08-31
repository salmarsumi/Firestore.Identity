using Google.Api.Gax;
using Google.Cloud.Firestore;
using Microsoft.Extensions.Configuration;
using SMD.AspNetCore.Identity.Firestore;
using System.IO;

namespace Identity.Firestore.IntegrationTests
{
    public class FirestoreTestFixture
    {
        private readonly FirestoreDb _db;

        private readonly  IConfiguration _config = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", true)
                .AddUserSecrets<FirestoreTestFixture>()
                .AddEnvironmentVariables()
                .Build();

        public FirestoreTestFixture()
        {
            _db = CreateDbInstance();
            Clean(_db.Collection(Constants.Collections.Users));
            Clean(_db.Collection(Constants.Collections.Roles));
            Clean(_db.Collection(Constants.Collections.UserClaims));
            Clean(_db.Collection(Constants.Collections.UserLogins));
            Clean(_db.Collection(Constants.Collections.UserRoles));
            Clean(_db.Collection(Constants.Collections.UserTokens));
            Clean(_db.Collection(Constants.Collections.RoleClaims));
        }

        public FirestoreDb DB => _db;

        private FirestoreDb CreateDbInstance()
        {
            return new FirestoreDbBuilder
            {
                ProjectId = _config["ProjectId"],
                EmulatorDetection = EmulatorDetection.EmulatorOrProduction
            }.Build();
        }

        private void Clean(CollectionReference collection)
        {
            var snapShot = collection.GetSnapshotAsync().GetAwaiter().GetResult();
            foreach (var doc in snapShot.Documents)
            {
                doc.Reference.DeleteAsync().GetAwaiter().GetResult();
            }
        }
    }
}
