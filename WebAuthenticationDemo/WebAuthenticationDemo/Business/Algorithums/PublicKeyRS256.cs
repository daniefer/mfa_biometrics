using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using PeterO.Cbor;
using WebAuthenticationDemo.Controllers;

namespace WebAuthenticationDemo.Business.Algorithums
{
    public class PublicKeyRS256 : IPublicKey
    {
        public const int Alg = -257;
        public const string Kty = "RSA";

        public string Algorithum => "RS256";

        public RSAParameters Parameters { get; }

        public PublicKeyRS256(CBORObject cbor)
        {
            Parameters = new RSAParameters
            {
                Exponent = cbor[-2].GetByteString(),
                Modulus = cbor[-1].GetByteString(),
            };
        }

        public SecurityKey GetSecurityKey()
        {
            return new RsaSecurityKey(Parameters);
        }
    }
}
