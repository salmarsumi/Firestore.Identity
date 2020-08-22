using System;
using System.Collections.Generic;
using System.Text;

namespace SMD.AspNetCore.Identity.Firestore
{
    internal class Constants
    {
        internal class Collections
        {
            internal const string Users = "users";
            internal const string Roles = "roles";
            internal const string UserClaims = "user-claims";
            internal const string UserRoles = "user-roles";
            internal const string UserLogins = "user-logins";
            internal const string UserTokens = "user-tokens";
            internal const string RoleClaims = "role-claims";
        }
    }
}
