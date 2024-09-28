using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace API.FurnitureStore.Shared.Common
{
    public static class RandomGenerator
    {
        public static string GenerateRandomString(int seize)
        {
            var random = new Random();
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz$-_.";
            return new string(Enumerable.Repeat(chars, seize).
                Select(s => s[random.Next(s.Length)]).ToArray());
        }
    }
}
