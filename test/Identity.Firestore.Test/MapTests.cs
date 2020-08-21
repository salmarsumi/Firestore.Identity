using System;
using Xunit;
using SMD.AspNetCore.Identity.Firestore;
using System.Collections.Generic;
using System.Security.Claims;

namespace Identity.Firestore.Test
{
    public class MapTests
    {
        [Fact]
        public void ToDictionary_GivenObject_ShouldReturnDictionary()
        {
            // Arrange
            int id = 1;
            string name = "name";

            object data = new { id, name };

            // Act
            var result = data.ToDictionary();

            // Assert
            Assert.NotNull(result);
            Assert.IsType<Dictionary<string, object>>(result);
            Assert.Equal(2, result.Count);
            Assert.Equal(id, (int)result["id"]);
            Assert.Equal(name, result["name"].ToString());
        }

        [Fact]
        public void ToDictionary_GivenClaim_ShouldReturnDictionary()
        {
            // Arrange
            string type = "claim type";
            string value = "claim value";

            Claim claim = new Claim(type, value);

            // Act
            var result = claim.ToDictionary();

            // Assert
            Assert.NotNull(result);
            Assert.IsType<Dictionary<string, object>>(result);
            Assert.Equal(2, result.Count);
            Assert.Equal(type, result["Type"].ToString());
            Assert.Equal(value, result["Value"].ToString());
        }

        [Fact]
        public void ToObject_GivenDictionary_ShouldReturnObject()
        {
            // Arrange
            var data = new Dictionary<string, object>
            {
                { "Id", 1 },
                { "Name", "Name Value" },
                { "Discarded", "Discarded" }
            };

            // Act
            var result = data.ToObject<TestType>();

            // Assert
            Assert.NotNull(result);
            Assert.IsType<TestType>(result);
            Assert.Equal((int)data["Id"], result.Id);
            Assert.Equal(data["Name"].ToString(), result.Name);
        }

        private class TestType
        {
            public int Id { get; set; }
            public string Name { get; set; }
        }
    }
}
