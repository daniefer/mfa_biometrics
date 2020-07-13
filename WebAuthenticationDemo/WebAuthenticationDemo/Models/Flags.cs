using System;

namespace WebAuthenticationDemo.Controllers
{
    [Flags]
    public enum AuthDataFlags : byte
    {
        UserPresent = 1,
        ReservedForFutureUse1 = 1 << 1,
        UserVerified = 1 << 2,
        ReservedForFutureUse3 = 1 << 3,
        ReservedForFutureUse4 = 1 << 4,
        ReservedForFutureUse5 = 1 << 5,
        HasAttestedCredentialDataIncluded = 1 << 6,
        HasExtensionDataIncluded = 1 << 7,
    }
}