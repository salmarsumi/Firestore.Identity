using Google.Api.Gax;
using Google.Cloud.Firestore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;

namespace SMD.AspNetCore.Identity.Firestore
{
    /// <summary>
    /// Contains extension methods to <see cref="IdentityBuilder"/> for adding entity framework stores.
    /// </summary>
    public static class IdentityBuilderExtensions
    {
        /// <summary>
        /// Adds an Entity Framework implementation of identity information stores.
        /// </summary>
        /// <typeparam name="TContext">The Entity Framework database context to use.</typeparam>
        /// <param name="builder">The <see cref="IdentityBuilder"/> instance this method extends.</param>
        /// <returns>The <see cref="IdentityBuilder"/> instance this method extends.</returns>
        public static IdentityBuilder AddFirestoreStores(this IdentityBuilder builder)
        {
            AddFirestoreDb(builder.Services);
            AddStores(builder.Services, builder.UserType, builder.RoleType);
            return builder;
        }

        private static void AddFirestoreDb(IServiceCollection services)
        {
            services.AddScoped<IFirestoreDbContext, FirestoreDbContext>(provider =>
            {
                var options = provider.GetRequiredService<IOptions<FirestoreDbSettings>>();
                return new FirestoreDbContext(new FirestoreDbBuilder
                {
                    ProjectId = options.Value.ProjectId,
                    EmulatorDetection = EmulatorDetection.EmulatorOrProduction
                }.Build());
            });
        }

        private static void AddStores(IServiceCollection services, Type userType, Type roleType)
        {
            var identityUserType = FindGenericBaseType(userType, typeof(IdentityUser<string>));
            if (identityUserType == null)
            {
                throw new InvalidOperationException("AddFirestoreStores can only be called with a user that derives from IdentityUser<string>.");
            }

            Type userStoreType;
            if (roleType != null)
            {
                var identityRoleType = FindGenericBaseType(roleType, typeof(IdentityRole<string>));
                if (identityRoleType == null)
                {
                    throw new InvalidOperationException("AddFirestoreStores can only be called with a role that derives from IdentityRole<string>.");
                }

                Type roleStoreType = null;
                userStoreType = typeof(FirestoreUserStore<,>).MakeGenericType(userType, roleType);
                roleStoreType = typeof(FirestoreRoleStore<>).MakeGenericType(roleType);

                services.TryAddScoped(typeof(IUserStore<>).MakeGenericType(userType), userStoreType);
                services.TryAddScoped(typeof(IRoleStore<>).MakeGenericType(roleType), roleStoreType);
            }
            else
            {   // No Roles
                userStoreType = typeof(FirestoreUserOnlyStore<>).MakeGenericType(userType);
                services.TryAddScoped(typeof(IUserStore<>).MakeGenericType(userType), userStoreType);
            }
        }

        private static TypeInfo FindGenericBaseType(Type currentType, Type genericBaseType)
        {
            var type = currentType;
            while (type != null)
            {
                var typeInfo = type.GetTypeInfo();
                var genericType = type.IsGenericType ? type.GetGenericTypeDefinition() : null;
                if (genericType != null && genericType == genericBaseType)
                {
                    return typeInfo;
                }
                type = type.BaseType;
            }
            return null;
        }
    }
}
