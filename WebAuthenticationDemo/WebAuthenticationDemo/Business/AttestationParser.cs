using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using PeterO.Cbor;
using WebAuthenticationDemo.Controllers;

namespace WebAuthenticationDemo.Business
{
    public class AttestationParser
    {
        private readonly AuthDataParser _authDataParser;

        public AttestationParser(AuthDataParser authDataParser)
        {
            _authDataParser = authDataParser;
        }

        public Attestation Parse(string base64String)
        {
            var bytes = Convert.FromBase64String(base64String);
            var obj = CBORObject.DecodeFromBytes(bytes);
            return new Attestation
            {
                Fmt = obj["fmt"].ToString(),
                AttStmt = obj["attStmt"].Count == 0 ? null : new AttestationStatement
                {
                    Alg = int.Parse(obj["attStmt"]["alg"].ToString()),
                    Ver = obj["attStmt"]["ver"].ToString(),
                    CertInfo = obj["attStmt"]["certInfo"].GetByteString(),
                    PubArea = obj["attStmt"]["pubArea"].GetByteString(),
                    Sig = obj["attStmt"]["sig"].GetByteString(),
                    X5c = obj["attStmt"]["x5c"].Values.Select(x => x.GetByteString()).ToArray(),
                },
                AuthData = _authDataParser.Parse(obj["authData"].GetByteString())
            };
        }
    }
}
