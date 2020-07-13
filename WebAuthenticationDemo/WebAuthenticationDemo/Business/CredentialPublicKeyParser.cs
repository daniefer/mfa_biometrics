using System.Collections.Generic;
using System.Collections.Immutable;
using PeterO.Cbor;
using WebAuthenticationDemo.Business.Algorithums;
using WebAuthenticationDemo.Controllers;

namespace WebAuthenticationDemo.Business
{
    public class CredentialPublicKeyParser
    {
        private readonly PublicKeyFactory _publicKeyFactory;

        public CredentialPublicKeyParser(PublicKeyFactory publicKeyFactory)
        {
            _publicKeyFactory = publicKeyFactory;
        }

        public IPublicKey Parse(byte[] publicKeyCoseBuffer)
        {
            var cbor = CBORObject.DecodeFromBytes(publicKeyCoseBuffer);
            var alg = cbor[3].AsNumber().ToInt32Checked();
            return _publicKeyFactory.Create(alg, cbor);
        }

    }
}
