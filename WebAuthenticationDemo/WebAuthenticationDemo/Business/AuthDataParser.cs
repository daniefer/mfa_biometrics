using System;
using WebAuthenticationDemo.Controllers;
using WebAuthenticationDemo.Utilities;

namespace WebAuthenticationDemo.Business
{
    public class AuthDataParser
    {
        private readonly CredentialPublicKeyParser _credentialPublicKeyParser;

        public AuthDataParser(CredentialPublicKeyParser credentialPublicKeyParser)
        {
            _credentialPublicKeyParser = credentialPublicKeyParser;
        }

        public AuthData Parse(byte[] bytes)
        {
            var rpIdHash = Convert.ToBase64String(bytes[0..32]);
            var flags = (AuthDataFlags)bytes[32];
            var signCount = BitConverterHelper.ParseBitEndianUInt32(bytes[33..37]);

            if (flags.HasFlag(AuthDataFlags.HasAttestedCredentialDataIncluded))
            {
                var aaGuid = new Guid(bytes[37..53]);
                var credentialIdLength = BitConverterHelper.ParseBitEndianUInt16(bytes[53..55]);
                var credentialId = bytes[55..(55 + credentialIdLength)];
                var publicKey = _credentialPublicKeyParser.Parse(bytes[(55 + credentialIdLength)..bytes.Length]);

                if (flags.HasFlag(AuthDataFlags.HasExtensionDataIncluded))
                {
                    // TODO: get extensions data
                    return new AuthData
                    {
                        RpIdHash = rpIdHash,
                        Flags = flags,
                        SignCount = signCount,
                        // attestedCredentialData
                        AaGuid = aaGuid,
                        CredentialIdLength = credentialIdLength,
                        CredentialId = credentialId,
                        PublicKey = publicKey,
                        Extensions = new Extensions
                        {

                        }
                    };
                }

                return new AuthData
                {
                    RpIdHash = rpIdHash,
                    Flags = flags,
                    SignCount = signCount,
                    // attestedCredentialData
                    AaGuid = aaGuid,
                    CredentialIdLength = credentialIdLength,
                    CredentialId = credentialId,
                    PublicKey = publicKey,
                    Extensions = new Extensions
                    {

                    }
                };
            }
            if (flags.HasFlag(AuthDataFlags.HasExtensionDataIncluded))
            {
                // TODO: get extensions data
                return new AuthData
                {
                    RpIdHash = rpIdHash,
                    Flags = flags,
                    SignCount = signCount,
                    Extensions = new Extensions
                    {

                    }
                };
            }
            return new AuthData
            {
                RpIdHash = rpIdHash,
                Flags = flags,
                SignCount = signCount,
            };

        }
    }
}
