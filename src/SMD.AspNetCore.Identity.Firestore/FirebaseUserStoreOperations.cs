using Google.Cloud.Firestore;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace SMD.AspNetCore.Identity.Firestore
{
    internal sealed class FirebaseUserStoreOperations<TUser, TUserLogin, TUserToken>
        where TUser : IdentityUser<string>, new()
        where TUserLogin : IdentityUserLogin<string>, new()
        where TUserToken : IdentityUserToken<string>, new()
    {
        private readonly FirestoreDb _db;
        private readonly IdentityErrorDescriber _errorDescriber;

        public FirebaseUserStoreOperations(FirestoreDb db, IdentityErrorDescriber errorDescriber)
        {
            _db = db;
            _errorDescriber = errorDescriber;
        }

        private CollectionReference UsersSet { get { return _db.Collection(Constants.Collections.Users); } }
        private CollectionReference UserTokens { get { return _db.Collection(Constants.Collections.UserTokens); } }
        private CollectionReference UserLogins { get { return _db.Collection(Constants.Collections.UserLogins); } }
        private CollectionReference UserClaims { get { return _db.Collection(Constants.Collections.UserClaims); } }

        internal async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken = default)
        {
            // create a new document reference and use the generated Id
            var doc = UsersSet.Document();
            user.Id = doc.Id;

            // save the user document
            await doc.CreateAsync(user.ToDictionary(), cancellationToken: cancellationToken).ConfigureAwait(false);

            return IdentityResult.Success;
        }

        internal Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken = default)
        {
            // get the stored user document reference
            var doc = UsersSet.Document(user.Id);

            return _db.RunTransactionAsync(async transaction =>
            {
                var snapshot = await transaction.GetSnapshotAsync(doc, cancellationToken).ConfigureAwait(false);

                if (!snapshot.Exists || snapshot.GetValue<string>("ConcurrencyStamp") != user.ConcurrencyStamp)
                {
                    return IdentityResult.Failed(_errorDescriber.ConcurrencyFailure());
                }

                transaction.Update(doc, user.ToDictionary());

                return IdentityResult.Success;
            }, cancellationToken: cancellationToken);
        }

        internal Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken = default)
        {
            // get the stored user document reference
            var doc = UsersSet.Document(user.Id);

            return _db.RunTransactionAsync(async transaction =>
            {
                var snapshot = await transaction.GetSnapshotAsync(doc, cancellationToken).ConfigureAwait(false);

                // check if the user was deleted or updated while running the transaction
                if (!snapshot.Exists || snapshot.GetValue<string>("ConcurrencyStamp") != user.ConcurrencyStamp)
                {
                    return IdentityResult.Failed(_errorDescriber.ConcurrencyFailure());
                }

                // delete the user logins
                var loginSnapshots = await UserLogins.WhereEqualTo("UserId", user.Id).GetSnapshotAsync(cancellationToken).ConfigureAwait(false);
                if (loginSnapshots.Count > 0)
                {
                    foreach (var login in loginSnapshots)
                    {
                        transaction.Delete(login.Reference);
                    }
                }
                // delete the user tokens
                var tokenSnapshots = await UserTokens.WhereEqualTo("UserId", user.Id).GetSnapshotAsync(cancellationToken).ConfigureAwait(false);
                if (tokenSnapshots.Count > 0)
                {
                    foreach (var token in tokenSnapshots)
                    {
                        transaction.Delete(token.Reference);
                    }
                }

                // delete the user claims
                transaction.Delete(UserClaims.Document(user.Id));

                transaction.Delete(doc);

                return IdentityResult.Success;
            }, cancellationToken: cancellationToken);
        }

        internal async Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            var snapshot = await UsersSet.Document(userId).GetSnapshotAsync(cancellationToken).ConfigureAwait(false);

            if (snapshot.Exists)
            {
                return snapshot.ToDictionary().ToObject<TUser>();
            }

            return default;
        }

        internal async Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            var snapshots = await UsersSet.WhereEqualTo("NormalizedUserName", normalizedUserName).GetSnapshotAsync(cancellationToken).ConfigureAwait(false);
            if (snapshots.Count > 0)
            {
                return snapshots[0].ToDictionary().ToObject<TUser>();
            }

            return default;
        }

        internal IQueryable<TUser> GetAllUsersAsQueryable()
        {
            var docs = UsersSet.GetSnapshotAsync().ConfigureAwait(false).GetAwaiter().GetResult();
            return docs.Select(d => d.ToDictionary().ToObject<TUser>()).AsQueryable();
        }

        internal async Task<TUserLogin> FindUserLoginAsync(string userId, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            var snapshots = await UserLogins
                .WhereEqualTo("UserId", userId)
                .WhereEqualTo("LoginProvider", loginProvider)
                .WhereEqualTo("ProviderKey", providerKey)
                .GetSnapshotAsync(cancellationToken).ConfigureAwait(false);

            if (snapshots.Count > 0)
            {
                return snapshots[0].ToDictionary().ToObject<TUserLogin>();
            }

            return default;
        }

        internal async Task<TUserLogin> FindUserLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            var snapshots = await UserLogins
                .WhereEqualTo("LoginProvider", loginProvider)
                .WhereEqualTo("ProviderKey", providerKey)
                .GetSnapshotAsync(cancellationToken).ConfigureAwait(false);

            if (snapshots.Count > 0)
            {
                return snapshots[0].ToDictionary().ToObject<TUserLogin>();
            }

            return default;
        }

        internal async Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken)
        {
            var snapshot = await UserClaims.Document(user.Id)
                .GetSnapshotAsync(cancellationToken)
                .ConfigureAwait(false);

            if (snapshot.TryGetValue<Dictionary<string, object>[]>("Claims", out var claims))
            {
                return claims.Select(c => new Claim(c["Type"].ToString(), c["Value"].ToString())).ToList();
            }

            return new List<Claim>();
        }

        internal Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            var docRef = UserClaims.Document(user.Id);

            var batch = _db.StartBatch();
            foreach(var claim in claims)
            {
                batch.Update(docRef, "Claims", FieldValue.ArrayUnion(claim.ToDictionary()), Precondition.None);
            }
            return batch.CommitAsync(cancellationToken);
        }

        internal Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            var docRef = UserClaims.Document(user.Id);

            // batch the update requests in one atomic operation
            var batch = _db.StartBatch();
            batch.Update(docRef, "Claims", FieldValue.ArrayRemove(claim.ToDictionary()));
            batch.Update(docRef, "Claims", FieldValue.ArrayUnion(newClaim.ToDictionary()));

            return batch.CommitAsync(cancellationToken);
        }

        internal Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            var docRef = UserClaims.Document(user.Id);

            return _db.RunTransactionAsync(async transaction =>
            {
                // manipulate the array client side and then save the updates.
                // this will elemenate the need for multiple writes
                var snapshot = await docRef
                .GetSnapshotAsync(cancellationToken)
                .ConfigureAwait(false);

                if (snapshot.Exists && snapshot.TryGetValue<Dictionary<string, object>[]>("Claims", out var claimArray))
                {
                    var newClaims = claimArray
                        .Where(c => !claims
                            .Any(cc =>
                                cc.Type == c["Type"].ToString() &&
                                cc.Value == c["Value"].ToString()
                                )
                            ).ToArray();

                    transaction.Set(docRef, new Dictionary<string, object>
                    {
                        { "Claims", newClaims }
                    }, SetOptions.Overwrite);
                }
            }, cancellationToken: cancellationToken);
        }

        internal Task AddLoginAsync(TUserLogin userLogin, CancellationToken cancellationToken)
        {
            return UserLogins.AddAsync(userLogin.ToDictionary(), cancellationToken);
        }

        internal Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            return _db.RunTransactionAsync(async transaction =>
            {
                var snapshots = await UserLogins
                    .WhereEqualTo("UserId", user.Id)
                    .WhereEqualTo("LoginProvider", loginProvider)
                    .WhereEqualTo("ProviderKey", providerKey)
                    .GetSnapshotAsync(cancellationToken)
                    .ConfigureAwait(false);

                if (snapshots.Count > 0)
                {
                    foreach (var doc in snapshots)
                    {
                        transaction.Delete(doc.Reference);
                    }
                }
            }, cancellationToken: cancellationToken);
        }

        internal async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken)
        {
            var snapshots = await UserLogins.WhereEqualTo("UserId", user.Id).GetSnapshotAsync(cancellationToken).ConfigureAwait(false);

            return snapshots.Select(d => new UserLoginInfo(
                d.GetValue<string>("LoginProvider"),
                d.GetValue<string>("ProviderKey"),
                d.GetValue<string>("ProviderDisplayName")))
                .ToList();
        }

        internal async Task<TUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            var userLogin = await FindUserLoginAsync(loginProvider, providerKey, cancellationToken);
            if (userLogin != null)
            {
                return await FindByIdAsync(userLogin.UserId, cancellationToken);
            }
            return default;
        }

        internal async Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            var snapshot = await UsersSet
                .WhereEqualTo("NormalizedEmail", normalizedEmail)
                .GetSnapshotAsync(cancellationToken)
                .ConfigureAwait(false);

            if (snapshot.Count > 0)
            {
                return snapshot[0].ToDictionary().ToObject<TUser>();
            }

            return default;
        }

        internal async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            var snapshots = await UserClaims
                .WhereArrayContains("Claims", claim.ToDictionary())
                .GetSnapshotAsync(cancellationToken)
                .ConfigureAwait(false);

            if (snapshots.Count > 0)
            {
                var docRefs = snapshots.Select(d => UsersSet.Document(d.Id));
                var usersSnapshots = await _db.GetAllSnapshotsAsync(docRefs, cancellationToken).ConfigureAwait(false);

                if (usersSnapshots.Count > 0)
                {
                    return usersSnapshots.Select(d => d.ToDictionary().ToObject<TUser>()).ToList();
                }
            }

            return new List<TUser>();
        }

        internal async Task<TUserToken> FindTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            var snapshots = await UserTokens
                .WhereEqualTo("UserId", user.Id)
                .WhereEqualTo("LoginProvider", loginProvider)
                .WhereEqualTo("Name", name)
                .GetSnapshotAsync(cancellationToken)
                .ConfigureAwait(false);

            if (snapshots.Count > 0)
            {
                return snapshots[0].ToDictionary().ToObject<TUserToken>();
            }

            return default;
        }

        internal Task AddUserTokenAsync(TUserToken token)
        {
            return UserTokens.AddAsync(token.ToDictionary());
        }

        internal async Task RemoveUserTokenAsync(TUserToken token)
        {
            var snapshots = await UserTokens
                .WhereEqualTo("UserId", token.UserId)
                .WhereEqualTo("LoginProvider", token.LoginProvider)
                .WhereEqualTo("Name", token.Name)
                .GetSnapshotAsync()
                .ConfigureAwait(false);

            if (snapshots.Count > 0)
            {
                await UserTokens.Document(snapshots[0].Id).DeleteAsync();
            }
        }
    }
}