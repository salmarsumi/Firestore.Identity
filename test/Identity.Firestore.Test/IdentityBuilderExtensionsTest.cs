using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using SMD.AspNetCore.Identity.Firestore;
using System.Linq;
using Xunit;

namespace Identity.Firestore.Test
{
    public class IdentityBuilderExtensionsTest
    {
        [Fact]
        public void AddFirestoreStores_GivenUserOnly_ShouldRegisterTypes()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddIdentityCore<IdentityUser>()
                .AddFirestoreStores();

            var describer = services.SingleOrDefault(d => d.ServiceType == typeof(IFirestoreDbContext));
            if (describer != null)
            {
                services.Remove(describer);
            }
            services.AddScoped(provider => new Mock<IFirestoreDbContext>().Object);
            using var scope = services.BuildServiceProvider();

            // Act
            var userStore = scope.GetRequiredService<IUserStore<IdentityUser>>();

            // Assert
            Assert.IsType<FirestoreUserOnlyStore<IdentityUser>>(userStore);
        }

        [Fact]
        public void AddFirestoreStores_GivenUserAndRole_ShouldRegisterTypes()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddIdentity<IdentityUser, IdentityRole>()
                .AddFirestoreStores();

            var describer = services.SingleOrDefault(d => d.ServiceType == typeof(IFirestoreDbContext));
            if (describer != null)
            {
                services.Remove(describer);
            }
            services.AddScoped(provider => new Mock<IFirestoreDbContext>().Object);
            using var scope = services.BuildServiceProvider();

            // Act
            var userStore = scope.GetRequiredService<IUserStore<IdentityUser>>();
            var roleStore = scope.GetRequiredService<IRoleStore<IdentityRole>>();

            // Assert
            Assert.IsType<FirestoreUserStore<IdentityUser, IdentityRole>>(userStore);
            Assert.IsType<FirestoreRoleStore<IdentityRole>>(roleStore);
        }
    }
}
