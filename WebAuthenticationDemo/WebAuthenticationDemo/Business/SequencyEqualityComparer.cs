using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace WebAuthenticationDemo
{
    internal class SequencyEqualityComparer<T> : IEqualityComparer<IEnumerable<T>>
    {
        public bool Equals([AllowNull] IEnumerable<T> x, [AllowNull] IEnumerable<T> y)
        {
            return Enumerable.SequenceEqual(x, y);
        }

        public int GetHashCode([DisallowNull] IEnumerable<T> obj)
        {
            return obj.GetHashCode();
        }
    }
}