﻿using Google.Cloud.Firestore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Test;
using Microsoft.Extensions.DependencyInjection;
using SMD.AspNetCore.Identity.Firestore;
using System;
using System.Linq.Expressions;
using System.Threading.Tasks;
using Xunit;

namespace Identity.Firestore.IntegrationTests
{
    [Collection("FirestoreTests")]
    public class UserStoreTest : IdentitySpecificationTestBase<TestIdentityUser, TestIdentityRole, string>, IClassFixture<FirestoreTestFixture>
    {
        private readonly FirestoreTestFixture _fixture;
        private readonly FirestoreDb _db;

        public UserStoreTest(FirestoreTestFixture fixture)
        {
            _fixture = fixture;
            _db = _fixture.DB;
        }

        [Fact]
        public async Task DeleteUserRemovesTokensTest()
        {
            // Need fail if not empty?
            var userMgr = CreateManager();
            var user = CreateTestUser();
            IdentityResultAssert.IsSuccess(await userMgr.CreateAsync(user));
            IdentityResultAssert.IsSuccess(await userMgr.SetAuthenticationTokenAsync(user, "provider", "test", "value"));

            Assert.Equal("value", await userMgr.GetAuthenticationTokenAsync(user, "provider", "test"));

            IdentityResultAssert.IsSuccess(await userMgr.DeleteAsync(user));

            Assert.Null(await userMgr.GetAuthenticationTokenAsync(user, "provider", "test"));
        }

        [Fact]
        public async Task CanFindByName()
        {
            var name = Guid.NewGuid().ToString();
            var manager = CreateManager();
            var user = CreateTestUser(namePrefix: name, useNamePrefixAsUserName: true);
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(user));
            var fetch = await manager.FindByNameAsync(name);
            Assert.Equal(user, fetch);
        }

        [Fact]
        public async Task FindByLogin()
        {
            var user = CreateTestUser();
            var manager = CreateManager();
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(user));
            var createdUser = await manager.FindByIdAsync(await manager.GetUserIdAsync(user));
            IdentityResultAssert.IsSuccess(await manager.AddLoginAsync(user, new UserLoginInfo("provider", createdUser.Id.ToString(), "display")));
            var userByLogin = await manager.FindByLoginAsync("provider", user.Id.ToString());
            Assert.NotNull(userByLogin);
        }

        [Fact]
        public async Task DeleteUserRemovesTokens()
        {
            var userMgr = CreateManager();
            var user = CreateTestUser();
            IdentityResultAssert.IsSuccess(await userMgr.CreateAsync(user));
            IdentityResultAssert.IsSuccess(await userMgr.SetAuthenticationTokenAsync(user, "provider", "test", "value"));

            Assert.Equal("value", await userMgr.GetAuthenticationTokenAsync(user, "provider", "test"));

            IdentityResultAssert.IsSuccess(await userMgr.DeleteAsync(user));

            Assert.Null(await userMgr.GetAuthenticationTokenAsync(user, "provider", "test"));
        }

        [Fact]
        public async Task DeleteRoleNonEmptySucceedsTest()
        {
            var userMgr = CreateManager();
            var roleMgr = CreateRoleManager();
            var roleName = "delete" + Guid.NewGuid().ToString();
            var role = CreateTestRole(roleName, useRoleNamePrefixAsRoleName: true);
            Assert.False(await roleMgr.RoleExistsAsync(roleName));
            IdentityResultAssert.IsSuccess(await roleMgr.CreateAsync(role));
            var user = CreateTestUser();
            IdentityResultAssert.IsSuccess(await userMgr.CreateAsync(user));
            IdentityResultAssert.IsSuccess(await userMgr.AddToRoleAsync(user, roleName));
            var roles = await userMgr.GetRolesAsync(user);
            Assert.Single(roles);
            IdentityResultAssert.IsSuccess(await roleMgr.DeleteAsync(role));
            Assert.Null(await roleMgr.FindByNameAsync(roleName));
            Assert.False(await roleMgr.RoleExistsAsync(roleName));
            // REVIEW: We should throw if deleting a non empty role?
            roles = await userMgr.GetRolesAsync(user);

            Assert.Empty(roles);
        }

        [Fact]
        public async Task DeleteUserRemovesFromRoleTest()
        {
            // Need fail if not empty?
            var userMgr = CreateManager();
            var roleMgr = CreateRoleManager();
            var roleName = "deleteUserRemove" + Guid.NewGuid().ToString();
            var role = CreateTestRole(roleName, useRoleNamePrefixAsRoleName: true);
            Assert.False(await roleMgr.RoleExistsAsync(roleName));
            IdentityResultAssert.IsSuccess(await roleMgr.CreateAsync(role));
            var user = CreateTestUser();
            IdentityResultAssert.IsSuccess(await userMgr.CreateAsync(user));
            IdentityResultAssert.IsSuccess(await userMgr.AddToRoleAsync(user, roleName));

            var roles = await userMgr.GetRolesAsync(user);
            Assert.Single(roles);

            IdentityResultAssert.IsSuccess(await userMgr.DeleteAsync(user));

            roles = await userMgr.GetRolesAsync(user);
            Assert.Empty(roles);
        }

        protected override void AddRoleStore(IServiceCollection services, object context = null)
        {
            services.AddSingleton<IRoleStore<TestIdentityRole>>(new FirestoreRoleStore<TestIdentityRole>(new FirestoreDbContext(_db)));
        }

        protected override void AddUserStore(IServiceCollection services, object context = null)
        {
            services.AddSingleton<IUserStore<TestIdentityUser>>(new FirestoreUserStore<TestIdentityUser>(new FirestoreDbContext(_db)));
        }

        protected override object CreateTestContext()
        {
            return null;
        }

        protected override TestIdentityRole CreateTestRole(string roleNamePrefix = "", bool useRoleNamePrefixAsRoleName = false)
        {
            var roleName = useRoleNamePrefixAsRoleName ? roleNamePrefix : string.Format("{0}{1}", roleNamePrefix, Guid.NewGuid());
            return new TestIdentityRole(roleName);
        }

        protected override TestIdentityUser CreateTestUser(string namePrefix = "", string email = "", string phoneNumber = "", bool lockoutEnabled = false, DateTimeOffset? lockoutEnd = null, bool useNamePrefixAsUserName = false)
        {
            return new TestIdentityUser
            {
                UserName = useNamePrefixAsUserName ? namePrefix : string.Format("{0}{1}", namePrefix, Guid.NewGuid()),
                Email = email,
                PhoneNumber = phoneNumber,
                LockoutEnabled = lockoutEnabled,
                LockoutEnd = lockoutEnd
            };
        }

        protected override void SetUserPasswordHash(TestIdentityUser user, string hashedPassword)
        {
            user.PasswordHash = hashedPassword;
        }

        protected override Expression<Func<TestIdentityUser, bool>> UserNameEqualsPredicate(string userName) => u => u.UserName == userName;

        protected override Expression<Func<TestIdentityRole, bool>> RoleNameEqualsPredicate(string roleName) => r => r.Name == roleName;

        protected override Expression<Func<TestIdentityUser, bool>> UserNameStartsWithPredicate(string userName) => u => u.UserName.StartsWith(userName);

        protected override Expression<Func<TestIdentityRole, bool>> RoleNameStartsWithPredicate(string roleName) => r => r.Name.StartsWith(roleName);
    }
}
