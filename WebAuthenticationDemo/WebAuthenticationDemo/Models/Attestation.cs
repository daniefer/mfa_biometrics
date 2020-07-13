using System;
using PeterO.Cbor;

namespace WebAuthenticationDemo.Controllers
{
    public class Attestation
    {
        public string Fmt { get; set; }

        public AttestationStatement AttStmt { get; set; }

        public AuthData AuthData { get; set; }
    }
}