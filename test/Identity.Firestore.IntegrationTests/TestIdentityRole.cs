using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Text;

namespace Identity.Firestore.IntegrationTests
{
    public class TestIdentityRole : IdentityRole
    {
        public TestIdentityRole() : base()
        { }

        public TestIdentityRole(string name) : base(name)
        { }

        public override bool Equals(object obj)
        {
            if (obj is IdentityRole<string> other)
            {
                return other.Id == Id
                    && other.Name == Name;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return Id.GetHashCode();
        }
    }
}
