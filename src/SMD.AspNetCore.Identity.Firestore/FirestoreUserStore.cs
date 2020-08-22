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
    /// <summary>
    /// Represents a new instance of a persistence store for users, using the default implementation
    /// of <see cref="IdentityUser{TKey}"/> with a string as a primary key.
    /// </summary>
    public class FirestoreUserStore : FirestoreUserStore<IdentityUser<string>>
    {
        /// <summary>
        /// Constructs a new instance of <see cref="FirestoreUserStore"/>.
        /// </summary>
        /// <param name="db">The <see cref="FirestoreDb"/>.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/>.</param>
        public FirestoreUserStore(FirestoreDb db, IdentityErrorDescriber describer = null) : base(db, describer) { }
    }

    /// <summary>
    /// Creates a new instance of a persistence store for the specified user type.
    /// </summary>
    /// <typeparam name="TUser">The type representing a user.</typeparam>
    public class FirestoreUserStore<TUser> : FirestoreUserStore<TUser, IdentityRole>
        where TUser : IdentityUser<string>, new()
    {
        /// <summary>
        /// Constructs a new instance of <see cref="UserStore{TUser}"/>.
        /// </summary>
        /// <param name="db">The <see cref="FirestoreDb"/>.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/>.</param>
        public FirestoreUserStore(FirestoreDb db, IdentityErrorDescriber describer = null) : base(db, describer) { }
    }

    /// <summary>
    /// Represents a new instance of a persistence store for the specified user and role types.
    /// </summary>
    /// <typeparam name="TUser">The type representing a user.</typeparam>
    /// <typeparam name="TRole">The type representing a role.</typeparam>
    public class FirestoreUserStore<TUser, TRole> : FirestoreUserStore<TUser, TRole, IdentityUserClaim<string>, IdentityUserRole<string>, IdentityUserLogin<string>, IdentityUserToken<string>, IdentityRoleClaim<string>>
        where TUser : IdentityUser<string>, new()
        where TRole : IdentityRole<string>, new()
    {
        /// <summary>
        /// Constructs a new instance of <see cref="UserStore{TUser, TRole, TContext, TKey}"/>.
        /// </summary>
        /// <param name="db">The <see cref="FirestoreDb"/>.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/>.</param>
        public FirestoreUserStore(FirestoreDb db, IdentityErrorDescriber describer = null) : base(db, describer) { }
    }

    /// <summary>
    /// Represents a new instance of a persistence store for the specified user and role types.
    /// </summary>
    /// <typeparam name="TUser">The type representing a user.</typeparam>
    /// <typeparam name="TRole">The type representing a role.</typeparam>
    /// <typeparam name="TKey">The type of the primary key for a role.</typeparam>
    /// <typeparam name="TUserClaim">The type representing a claim.</typeparam>
    /// <typeparam name="TUserRole">The type representing a user role.</typeparam>
    /// <typeparam name="TUserLogin">The type representing a user external login.</typeparam>
    /// <typeparam name="TUserToken">The type representing a user token.</typeparam>
    /// <typeparam name="TRoleClaim">The type representing a role claim.</typeparam>
    public class FirestoreUserStore<TUser, TRole, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim> :
        UserStoreBase<TUser, TRole, string, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim>,
        IProtectedUserStore<TUser>
        where TUser : IdentityUser<string>, new()
        where TRole : IdentityRole<string>, new()
        where TUserClaim : IdentityUserClaim<string>, new()
        where TUserRole : IdentityUserRole<string>, new()
        where TUserLogin : IdentityUserLogin<string>, new()
        where TUserToken : IdentityUserToken<string>, new()
        where TRoleClaim : IdentityRoleClaim<string>, new()
    {
        /// <summary>
        /// Creates a new instance of the store.
        /// </summary>
        /// <param name="db">The Firestore instance used to access the store.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/> used to describe store errors.</param>
        public FirestoreUserStore(FirestoreDb db, IdentityErrorDescriber describer = null) : base(describer ?? new IdentityErrorDescriber())
        {
            DB = db ?? throw new ArgumentNullException(nameof(db));
        }

        /// <summary>
        /// Gets the database instance for this store.
        /// </summary>
        public FirestoreDb DB { get; private set; }

        /// <summary>
        /// Firestore Collections
        /// </summary>
        private CollectionReference UsersSet { get { return DB.Collection(Constants.Collections.Users); } }
        private CollectionReference Roles { get { return DB.Collection(Constants.Collections.Roles); } }
        private CollectionReference UserTokens { get { return DB.Collection(Constants.Collections.UserTokens); } }
        private CollectionReference UserLogins { get { return DB.Collection(Constants.Collections.UserLogins); } }
        private CollectionReference UserClaims { get { return DB.Collection(Constants.Collections.UserClaims); } }

        /// <summary>
        /// Gets a reference to the user claims subcollection.
        /// </summary>
        /// <param name="userId">The user ID</param>
        /// <returns>The <see cref="CollectionReference"/> that represents the User Claims subcollection.</returns>
        //private CollectionReference UserClaims(string userId) => DB.Collection(Constants.Collections.Users).Document(userId).Collection(Constants.Collections.UserClaims);


        /// <summary>
        /// Creates the specified <paramref name="user"/> in the user store.
        /// </summary>
        /// <param name="user">The user to create.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the creation operation.</returns>
        public async override Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user is null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            // create a new document reference and use the generated Id
            var doc = UsersSet.Document();
            user.Id = doc.Id;

            // save the user document
            await doc.CreateAsync(user.ToDictionary(), cancellationToken: cancellationToken).ConfigureAwait(false);

            return IdentityResult.Success;
        }

        /// <summary>
        /// Updates the specified <paramref name="user"/> in the user store.
        /// </summary>
        /// <param name="user">The user to update.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the update operation.</returns>
        public override Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user is null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            // get the stored user document reference
            var doc = UsersSet.Document(user.Id);

            var result = DB.RunTransactionAsync(async transaction =>
            {
                var snapshot = await transaction.GetSnapshotAsync(doc, cancellationToken).ConfigureAwait(false);

                if (!snapshot.Exists || snapshot.GetValue<string>("ConcurrencyStamp") != user.ConcurrencyStamp)
                {
                    return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
                }

                transaction.Update(doc, user.ToDictionary());

                return IdentityResult.Success;
            }, cancellationToken: cancellationToken);

            return result;
        }

        /// <summary>
        /// Deletes the specified <paramref name="user"/> from the user store.
        /// </summary>
        /// <param name="user">The user to delete.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the update operation.</returns>
        public override Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user is null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            // get the stored user document reference
            var doc = UsersSet.Document(user.Id);

            var result = DB.RunTransactionAsync(async transaction =>
            {
                var snapshot = await transaction.GetSnapshotAsync(doc, cancellationToken).ConfigureAwait(false);

                // check if the user was deleted or updated while running the transaction
                if (!snapshot.Exists || snapshot.GetValue<string>("ConcurrencyStamp") != user.ConcurrencyStamp)
                {
                    return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
                }

                // delete the user logins
                var loginSnapshots = await UserLogins.WhereEqualTo("UserId", user.Id).GetSnapshotAsync(cancellationToken).ConfigureAwait(false);
                if(loginSnapshots.Count > 0)
                {
                    foreach(var login in loginSnapshots)
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

            return result;
        }

        /// <summary>
        /// Finds and returns a user, if any, who has the specified <paramref name="userId"/>.
        /// </summary>
        /// <param name="userId">The user ID to search for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="userId"/> if it exists.
        /// </returns>
        public async override Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(userId))
            {
                throw new ArgumentNullException(nameof(userId));
            }

            var snapshot = await UsersSet.Document(userId).GetSnapshotAsync(cancellationToken).ConfigureAwait(false);

            if (snapshot.Exists)
            {
                return snapshot.ToDictionary().ToObject<TUser>();
            }

            return default;
        }

        /// <summary>
        /// Finds and returns a user, if any, who has the specified normalized user name.
        /// </summary>
        /// <param name="normalizedUserName">The normalized user name to search for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="normalizedUserName"/> if it exists.
        /// </returns>
        public override async Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if(string.IsNullOrEmpty(normalizedUserName))
            {
                throw new ArgumentNullException(nameof(normalizedUserName));
            }

            var snapshots = await UsersSet.WhereEqualTo("NormalizedUserName", normalizedUserName).GetSnapshotAsync(cancellationToken).ConfigureAwait(false);
            if(snapshots.Count > 0)
            {
                return snapshots[0].ToDictionary().ToObject<TUser>();
            }

            return default;
        }

        /// <summary>
        /// A navigation property for the users the store contains.
        /// The query will run client side and should be avoided.
        /// The property is included for compatability with the 
        /// Asp.Net Core implementation.
        /// </summary>
        public override IQueryable<TUser> Users
        {
            get
            {
                var docs = UsersSet.GetSnapshotAsync().ConfigureAwait(false).GetAwaiter().GetResult();
                return docs.Select(d => d.ToDictionary().ToObject<TUser>()).AsQueryable();
            }
        }

        /// <summary>
        /// Return a role with the normalized name if it exists.
        /// </summary>
        /// <param name="normalizedRoleName">The normalized role name.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The role if it exists.</returns>
        protected override async Task<TRole> FindRoleAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(normalizedRoleName))
            {
                throw new ArgumentNullException(nameof(normalizedRoleName));
            }

            var snapshots = await Roles.WhereEqualTo("NormalizedName", normalizedRoleName).GetSnapshotAsync(cancellationToken).ConfigureAwait(false);
            if(snapshots.Count > 0)
            {
                return snapshots[0].ToDictionary().ToObject<TRole>();
            }

            return default;
        }

        /// <summary>
        /// Return a user role for the userId and roleId if it exists.
        /// </summary>
        /// <param name="userId">The user's id.</param>
        /// <param name="roleId">The role's id.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The user role if it exists.</returns>
        protected override async Task<TUserRole> FindUserRoleAsync(string userId, string roleId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(userId))
            {
                throw new ArgumentNullException(nameof(userId));
            }

            if (string.IsNullOrEmpty(roleId))
            {
                throw new ArgumentNullException(nameof(roleId));
            }

            // get the user snapshot
            var snapshot = await UsersSet.Document(userId).GetSnapshotAsync(cancellationToken).ConfigureAwait(false);

            if(snapshot.Exists)
            {
                // get the roles array saved on the user document
                if(snapshot.TryGetValue<Dictionary<string, object>[]>("Roles", out var roles))
                {
                    var role = roles.Where(r => r["RoleId"].ToString() == roleId).FirstOrDefault();
                    if(role != null)
                    {
                        role.Add("UserId", userId);
                        return role.ToObject<TUserRole>();
                    }
                }
            }

            return default;
        }

        /// <summary>
        /// Return a user with the matching userId if it exists.
        /// </summary>
        /// <param name="userId">The user's id.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The user if it exists.</returns>
        protected override Task<TUser> FindUserAsync(string userId, CancellationToken cancellationToken)
        {
            return FindByIdAsync(userId, cancellationToken);
        }

        /// <summary>
        /// Return a user login with the matching userId, provider, providerKey if it exists.
        /// </summary>
        /// <param name="userId">The user's id.</param>
        /// <param name="loginProvider">The login provider name.</param>
        /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The user login if it exists.</returns>
        protected override async Task<TUserLogin> FindUserLoginAsync(string userId, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(userId))
            {
                throw new ArgumentNullException(nameof(userId));
            }

            if (string.IsNullOrEmpty(loginProvider))
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }

            if (string.IsNullOrEmpty(providerKey))
            {
                throw new ArgumentNullException(nameof(providerKey));
            }

            var snapshots = await UserLogins
                .WhereEqualTo("UserId", userId)
                .WhereEqualTo("LoginProvider", loginProvider)
                .WhereEqualTo("ProviderKey", providerKey)
                .GetSnapshotAsync(cancellationToken).ConfigureAwait(false);

            if(snapshots.Count > 0)
            {
                return snapshots[0].ToDictionary().ToObject<TUserLogin>();
            }

            return default;
        }

        /// <summary>
        /// Return a user login with  provider, providerKey if it exists.
        /// </summary>
        /// <param name="loginProvider">The login provider name.</param>
        /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The user login if it exists.</returns>
        protected override async Task<TUserLogin> FindUserLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(loginProvider))
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }

            if (string.IsNullOrEmpty(providerKey))
            {
                throw new ArgumentNullException(nameof(providerKey));
            }

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

        /// <summary>
        /// Adds the given <paramref name="normalizedRoleName"/> to the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to add the role to.</param>
        /// <param name="normalizedRoleName">The role to add.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public async override Task AddToRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user is null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (string.IsNullOrWhiteSpace(normalizedRoleName))
            {
                throw new ArgumentException("Value cannot be null or empty", nameof(normalizedRoleName));
            }

            var role = await FindRoleAsync(normalizedRoleName, cancellationToken).ConfigureAwait(false);
            if (role is null)
            {
                throw new InvalidOperationException($"Role not found, {normalizedRoleName}");
            }

            var userRole = new Dictionary<string, object>
            {
                { "RoleId", role.Id },
                { "RoleName", role.Name }
            };

            // store the role info in an Array object on the user document
            // this will minimize the server round trips for role-user queries
            await UsersSet.Document(user.Id)
                .UpdateAsync("Roles", FieldValue.ArrayUnion(userRole), cancellationToken: cancellationToken)
                .ConfigureAwait(false);
        }

        /// <summary>
        /// Removes the given <paramref name="normalizedRoleName"/> from the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to remove the role from.</param>
        /// <param name="normalizedRoleName">The role to remove.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public async override Task RemoveFromRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user is null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (string.IsNullOrWhiteSpace(normalizedRoleName))
            {
                throw new ArgumentException("Value cannot be null or empty", nameof(normalizedRoleName));
            }

            var role = await FindRoleAsync(normalizedRoleName, cancellationToken);
            if (role != null)
            {
                var element = new Dictionary<string, object>()
                {
                    { "RoleId", role.Id },
                    { "RoleName", role.Name }
                };

                await UsersSet.Document(user.Id)
                    .UpdateAsync("Roles", FieldValue.ArrayRemove(element), cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Retrieves the roles the specified <paramref name="user"/> is a member of.
        /// </summary>
        /// <param name="user">The user whose roles should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that contains the roles the user is a member of.</returns>
        public override async Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user is null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var snapshot = await UsersSet.Document(user.Id)
                .GetSnapshotAsync(cancellationToken)
                .ConfigureAwait(false);

            if(snapshot.TryGetValue<Dictionary<string, object>[]>("Roles", out var roles))
            {
                return roles.Select(r => r["RoleName"].ToString()).ToList();
            }

            return new List<string>();
        }

        /// <summary>
        /// Returns a flag indicating if the specified user is a member of the give <paramref name="normalizedRoleName"/>.
        /// </summary>
        /// <param name="user">The user whose role membership should be checked.</param>
        /// <param name="normalizedRoleName">The role to check membership of</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> containing a flag indicating if the specified user is a member of the given group. If the
        /// user is a member of the group the returned value with be true, otherwise it will be false.</returns>
        public override async Task<bool> IsInRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user is null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (string.IsNullOrWhiteSpace(normalizedRoleName))
            {
                throw new ArgumentException("Value cannot be null or empty", nameof(normalizedRoleName));
            }

            var role = await FindRoleAsync(normalizedRoleName, cancellationToken);
            if (role != null)
            {
                var userRole = await FindUserRoleAsync(user.Id, role.Id, cancellationToken);
                return userRole != null;
            }
            return false;
        }

        /// <summary>
        /// Get the claims associated with the specified <paramref name="user"/> as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user whose claims should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that contains the claims granted to a user.</returns>
        public async override Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            if (user is null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var snapshot = await UserClaims.Document(user.Id)
                .GetSnapshotAsync(cancellationToken)
                .ConfigureAwait(false);

            if (snapshot.TryGetValue<Dictionary<string, object>[]>("Claims", out var claims))
            {
                return claims.Select(c => new Claim(c["Type"].ToString(), c["Value"].ToString())).ToList();
            }

            return new List<Claim>();
        }

        /// <summary>
        /// Adds the <paramref name="claims"/> given to the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to add the claim to.</param>
        /// <param name="claims">The claim to add to the user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            if (user is null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (claims is null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            await UserClaims.Document(user.Id)
                .SetAsync(new Dictionary<string, object>
                {
                    { 
                        "Claims", claims.Select(c => c.ToDictionary()).ToArray() 
                    }
                }, options: SetOptions.MergeAll)
                .ConfigureAwait(false);
        }

        /// <summary>
        /// Replaces the <paramref name="claim"/> on the specified <paramref name="user"/>, with the <paramref name="newClaim"/>.
        /// </summary>
        /// <param name="user">The user to replace the claim on.</param>
        /// <param name="claim">The claim replace.</param>
        /// <param name="newClaim">The new claim replacing the <paramref name="claim"/>.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            if (user is null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (claim is null)
            {
                throw new ArgumentNullException(nameof(claim));
            }
            if (newClaim is null)
            {
                throw new ArgumentNullException(nameof(newClaim));
            }

            var docRef = UserClaims.Document(user.Id);

            // batch the update requests in one atomic operation
            var batch = DB.StartBatch();
            batch.Update(docRef, "Claims", FieldValue.ArrayRemove(claim.ToDictionary()));
            batch.Update(docRef, "Claims", FieldValue.ArrayUnion(newClaim.ToDictionary()));

            return batch.CommitAsync(cancellationToken);
        }

        /// <summary>
        /// Removes the <paramref name="claims"/> given from the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to remove the claims from.</param>
        /// <param name="claims">The claim to remove.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            if (user is null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (claims is null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            var docRef = UserClaims.Document(user.Id);

            return DB.RunTransactionAsync(async transaction =>
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

        /// <summary>
        /// Adds the <paramref name="login"/> given to the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to add the login to.</param>
        /// <param name="login">The login to add to the user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override Task AddLoginAsync(TUser user, UserLoginInfo login,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user is null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (login is null)
            {
                throw new ArgumentNullException(nameof(login));
            }

            return UserLogins.AddAsync(CreateUserLogin(user, login).ToDictionary(), cancellationToken);            
        }

        /// <summary>
        /// Removes the <paramref name="loginProvider"/> given from the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to remove the login from.</param>
        /// <param name="loginProvider">The login to remove from the user.</param>
        /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user is null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return DB.RunTransactionAsync(async transaction =>
            {
                var snapshots = await UserLogins
                    .WhereEqualTo("UserId", user.Id)
                    .WhereEqualTo("LoginProvider", loginProvider)
                    .WhereEqualTo("ProviderKey", providerKey)
                    .GetSnapshotAsync(cancellationToken)
                    .ConfigureAwait(false);

                if (snapshots.Count > 0)
                {
                    foreach(var doc in snapshots)
                    {
                        transaction.Delete(doc.Reference);
                    }
                }
            }, cancellationToken: cancellationToken);
        }

        /// <summary>
        /// Retrieves the associated logins for the specified <param ref="user"/>.
        /// </summary>
        /// <param name="user">The user whose associated logins to retrieve.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> for the asynchronous operation, containing a list of <see cref="UserLoginInfo"/> for the specified <paramref name="user"/>, if any.
        /// </returns>
        public async override Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user is null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var snapshots = await UserLogins.WhereEqualTo("UserId", user.Id).GetSnapshotAsync(cancellationToken).ConfigureAwait(false);

            return snapshots.Select(d => new UserLoginInfo(
                d.GetValue<string>("LoginProvider"),
                d.GetValue<string>("ProviderKey"),
                d.GetValue<string>("ProviderDisplayName")))
                .ToList();
        }

        /// <summary>
        /// Retrieves the user associated with the specified login provider and login provider key.
        /// </summary>
        /// <param name="loginProvider">The login provider who provided the <paramref name="providerKey"/>.</param>
        /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> for the asynchronous operation, containing the user, if any which matched the specified login provider and key.
        /// </returns>
        public async override Task<TUser> FindByLoginAsync(string loginProvider, string providerKey,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            var userLogin = await FindUserLoginAsync(loginProvider, providerKey, cancellationToken);
            if (userLogin != null)
            {
                return await FindUserAsync(userLogin.UserId, cancellationToken);
            }
            return null;
        }

        /// <summary>
        /// Gets the user, if any, associated with the specified, normalized email address.
        /// </summary>
        /// <param name="normalizedEmail">The normalized email address to return the user for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The task object containing the results of the asynchronous lookup operation, the user if any associated with the specified normalized email address.
        /// </returns>
        public async override Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            var snapshot = await UsersSet
                .WhereEqualTo("NormalizedEmail", normalizedEmail)
                .GetSnapshotAsync(cancellationToken)
                .ConfigureAwait(false);

            if(snapshot.Count > 0)
            {
                return snapshot[0].ToDictionary().ToObject<TUser>();
            }

            return default;
        }

        /// <summary>
        /// Retrieves all users with the specified claim.
        /// </summary>
        /// <param name="claim">The claim whose users should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> contains a list of users, if any, that contain the specified claim.
        /// </returns>
        public async override Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            var snapshots = await UserClaims
                .WhereArrayContains("Claims", claim.ToDictionary())
                .GetSnapshotAsync(cancellationToken)
                .ConfigureAwait(false);

            if(snapshots.Count > 0)
            {
                var docRefs = snapshots.Select(d => UsersSet.Document(d.Id));
                var usersSnapshots = await DB.GetAllSnapshotsAsync(docRefs, cancellationToken).ConfigureAwait(false);

                if(usersSnapshots.Count > 0)
                {
                    return usersSnapshots.Select(d => d.ToDictionary().ToObject<TUser>()).ToList();
                }
            }

            return new List<TUser>();
        }

        /// <summary>
        /// Retrieves all users in the specified role.
        /// </summary>
        /// <param name="normalizedRoleName">The role whose users should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> contains a list of users, if any, that are in the specified role.
        /// </returns>
        public async override Task<IList<TUser>> GetUsersInRoleAsync(string normalizedRoleName, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (string.IsNullOrEmpty(normalizedRoleName))
            {
                throw new ArgumentNullException(nameof(normalizedRoleName));
            }

            var role = await FindRoleAsync(normalizedRoleName, cancellationToken);

            if (role != null)
            {
                var snapshots = await UsersSet
                .WhereArrayContains("Roles", new Dictionary<string, object>
                {
                    { "RoleId", role.Id },
                    { "RoleName", role.Name }
                })
                .GetSnapshotAsync(cancellationToken)
                .ConfigureAwait(false);

                if(snapshots.Count > 0)
                {
                    return snapshots.Select(u => u.ToDictionary().ToObject<TUser>()).ToList();
                }
            }
            return new List<TUser>();
        }

        /// <summary>
        /// Find a user token if it exists.
        /// </summary>
        /// <param name="user">The token owner.</param>
        /// <param name="loginProvider">The login provider for the token.</param>
        /// <param name="name">The name of the token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The user token if it exists.</returns>
        protected override async Task<TUserToken> FindTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user is null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (string.IsNullOrEmpty(loginProvider))
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentNullException(nameof(name));
            }

            var snapshots = await UserTokens
                .WhereEqualTo("UserId", user.Id)
                .WhereEqualTo("LoginProvider", loginProvider)
                .WhereEqualTo("Name", name)
                .GetSnapshotAsync(cancellationToken)
                .ConfigureAwait(false);

            if(snapshots.Count > 0)
            {
                return snapshots[0].ToDictionary().ToObject<TUserToken>();
            }

            return default;
        }

        /// <summary>
        /// Add a new user token.
        /// </summary>
        /// <param name="token">The token to be added.</param>
        /// <returns></returns>
        protected override Task AddUserTokenAsync(TUserToken token)
        {
            ThrowIfDisposed();
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            return UserTokens.AddAsync(token.ToDictionary());
        }

        /// <summary>
        /// Remove a new user token.
        /// </summary>
        /// <param name="token">The token to be removed.</param>
        /// <returns></returns>
        protected override async Task RemoveUserTokenAsync(TUserToken token)
        {
            ThrowIfDisposed();
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            var snapshots = await UserTokens
                .WhereEqualTo("UserId", token.UserId)
                .WhereEqualTo("LoginProvider", token.LoginProvider)
                .WhereEqualTo("Name", token.Name)
                .GetSnapshotAsync()
                .ConfigureAwait(false);

            if(snapshots.Count > 0)
            {
                await UserTokens.Document(snapshots[0].Id).DeleteAsync();
            }
        }
    }
}
