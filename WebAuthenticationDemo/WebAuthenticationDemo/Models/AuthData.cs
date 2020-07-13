using System;
using WebAuthenticationDemo.Business.Algorithums;

namespace WebAuthenticationDemo.Controllers
{
    public class AuthData
    {
        public Guid AaGuid { get; internal set; }
        public ushort CredentialIdLength { get; internal set; }
        public byte[] CredentialId { get; internal set; }
        public string RpIdHash { get; internal set; }
        public AuthDataFlags Flags { get; internal set; }
        public uint SignCount { get; internal set; }
        internal IPublicKey PublicKey { get; set; }
        internal Extensions Extensions { get; set; }
    }
}