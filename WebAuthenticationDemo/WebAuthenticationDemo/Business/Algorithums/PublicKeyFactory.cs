using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using PeterO.Cbor;

namespace WebAuthenticationDemo.Business.Algorithums
{
    public class PublicKeyFactory
    {
        private Dictionary<int, Func<CBORObject, IPublicKey>> _lookup = new Dictionary<int, Func<CBORObject, IPublicKey>>
        {
            { PublicKeyES256.Alg, cBOR => new PublicKeyES256(cBOR) },
            //{ PublicKeyRS256.Alg, cBOR => new PublicKeyRS256(cBOR) },
        };

        public IPublicKey Create(int type, CBORObject cBOR)
        {
            if (_lookup.ContainsKey(type))
                return _lookup[type](cBOR);
            return null;
        }

        public int[] SupportedAlg => _lookup.Keys.ToArray();
    }
}
