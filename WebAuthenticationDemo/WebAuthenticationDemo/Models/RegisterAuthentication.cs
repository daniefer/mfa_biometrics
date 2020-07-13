using System;
using System.Linq;
using PeterO.Cbor;

namespace WebAuthenticationDemo.Controllers
{
    public class WebAuthenticationRegistrationRequest
    {
        public string Id { get; set; }
        public string Type { get; set; }
        public Extensions Extensions { get; set; }
        public string ClientDataJSON { get; set; }
        public string Base64CborAttestation { get; set; }
    }
}