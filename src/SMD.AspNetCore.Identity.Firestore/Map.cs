﻿using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Claims;

[assembly: InternalsVisibleTo("Identity.Firestore.Test")]
[assembly: InternalsVisibleTo("Identity.Firestore.IntegrationTests")]
namespace SMD.AspNetCore.Identity.Firestore
{
    internal static class Map
    {
        public static IDictionary<string, object> ToDictionary(this object source)
        {
            return source.GetType().GetProperties().ToDictionary(
                p => p.Name,
                p => p.GetValue(source, null));
        }

        public static IDictionary<string, object> ToDictionary(this Claim claim)
        {
            return new Dictionary<string, object>
            {
                { "Type", claim.Type },
                { "Value", claim.Value }
            };
        }

        public static T ToObject<T>(this IDictionary<string, object> source) where T : new()
        {
            T result = new T();
            object value;

            foreach(var property in result.GetType().GetProperties())
            {
                value = source[property.Name];
                if(property.PropertyType == value?.GetType())
                {
                    property.SetValue(result, value);
                }
            }

            return result;
        }
    }
}
