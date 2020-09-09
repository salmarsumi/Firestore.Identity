using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("Identity.Firestore.Test")]
[assembly: InternalsVisibleTo("Identity.Firestore.IntegrationTests")]
namespace SMD.AspNetCore.Identity.Firestore
{
    internal class Constants
    {
        internal class Collections
        {
            internal const string Users = "aspnet-users";
            internal const string Roles = "aspnet-roles";
            internal const string UserClaims = "aspnet-user-claims";
            internal const string UserRoles = "aspnet-user-roles";
            internal const string UserLogins = "aspnet-user-logins";
            internal const string UserTokens = "aspnet-user-tokens";
            internal const string RoleClaims = "aspnet-role-claims";
        }
    }
}
