using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Text;

namespace Identity.Firestore.IntegrationTests
{
    public class TestIdentityUser : IdentityUser
    {
        public TestIdentityUser() : base()
        { }

        public TestIdentityUser(string name) : base(name)
        { }

        public override bool Equals(object obj)
        {
            if (obj is IdentityUser<string> other)
            {
                return other.Email == Email
                    && other.Id == Id
                    && other.PasswordHash == PasswordHash
                    && other.UserName == UserName;
            }
            return false;
        }

        public override int GetHashCode()
        {
            return Id.GetHashCode();
        }
    }
}
