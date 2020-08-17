using Google.Cloud.Firestore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

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
