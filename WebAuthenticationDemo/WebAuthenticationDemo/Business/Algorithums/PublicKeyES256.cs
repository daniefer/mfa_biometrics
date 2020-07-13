using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using PeterO.Cbor;
using WebAuthenticationDemo.Controllers;

namespace WebAuthenticationDemo.Business.Algorithums
{
    public class PublicKeyES256 : IPublicKey
    {
        public const int Alg = -7;
        public const string Kty = "EC";

        public string Algorithum => "ES256";

        public ECParameters Parameters { get; }

        public PublicKeyES256(CBORObject cbor)
        {
            Parameters = new ECParameters
            {
                //Curve = new ECCurve
                //{
                    
                //    CurveType = ECCurve.ECCurveType.Characteristic2
                //}, 
                Curve = ECCurve.CreateFromOid(new Oid("1.2.840.10045.3.1.7")), //P-256
                Q = new ECPoint
                {
                    X = cbor[-2].GetByteString(),
                    Y = cbor[-3].GetByteString()
                }
            };
        }

        public SecurityKey GetSecurityKey()
        {
            return new ECDsaSecurityKey(ECDsa.Create(Parameters));
        }
    }
}
