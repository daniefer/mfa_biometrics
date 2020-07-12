using System;
using System.Linq;
using PeterO.Cbor;

namespace WebAuthenticationDemo.Controllers
{
    public class RegisterAuthentication
    {
        public string Id { get; set; }
        public string Type { get; set; }
        public Extensions Extensions { get; set; }
        public ClientData ClientData { get; set; }
        public string Base64CborAttestation { get; set; }

        public Attestation Attestation
        {
            get
            {
                var bytes = Convert.FromBase64String(Base64CborAttestation);
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
                    AuthDataArray = obj["authData"].GetByteString()
                };
            }
        }
    }

    public class Attestation
    {
        public string Fmt { get; set; }

        public AttestationStatement AttStmt { get; set; }
        public byte[] AuthDataArray { get; set; }

        public AuthData AuthData
        {
            get
            {
                var signCount = AuthDataArray[33..37];
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(signCount);
                var flags = (Flags)AuthDataArray[32];
                if (!flags.HasFlag(Flags.HasAttestedCredentialDataIncluded))
                {
                    return new AuthData
                    {
                        RpIdHash = Convert.ToBase64String(AuthDataArray[0..32]),
                        Flags = flags,
                        SignCount = BitConverter.ToUInt32(signCount),
                    };
                }

                var guid = AuthDataArray[37..53];
                var credentialIdLengthBytes = AuthDataArray[53..55];
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(credentialIdLengthBytes);
                var credentialIdLength = BitConverter.ToUInt16(credentialIdLengthBytes);
                var credentialId = AuthDataArray[55..(55 + credentialIdLength)];
                var publicKeyCoseBuffer = AuthDataArray[(55+ credentialIdLength)..AuthDataArray.Length];

                var cbor = CBORObject.DecodeFromBytes(publicKeyCoseBuffer);

                CredentialPublicKey credentialPublicKey = null;
                switch (cbor[3].AsNumber().ToInt64Checked())
                {
                    case (-7):
                        credentialPublicKey = new CredentialPublicKey
                        {
                            Alg = "-7",
                            Kty = "EC",
                            Crv = "P-256",
                            X = cbor[-2].GetByteString(),
                            Y = cbor[-3].GetByteString(),
                        };
                        break;
                    case (-257):
                        credentialPublicKey = new CredentialPublicKey
                        {
                            Alg = "-257",
                            Kty = "RSA",
                            N = cbor[-1].GetByteString(),
                            E = cbor[-2].GetByteString(),
                        };
                        break;
                    default:
                        break;
                }

                return new AuthData
                {
                    RpIdHash = Convert.ToBase64String(AuthDataArray[0..32]),
                    Flags = flags,
                    SignCount = BitConverter.ToUInt32(signCount),
                    AaGuid = new Guid(guid),
                    CredentialIdLength = credentialIdLength,
                    CredentialId = credentialId,
                    CredentialPublicKey = credentialPublicKey
                };
            }
        }
    }

    internal class CredentialPublicKey
    {
        public string Kty { get; internal set; }
        public string Alg { get; internal set; }
        public string Crv { get; internal set; }
        public byte[] X { get; internal set; }
        public byte[] Y { get; internal set; }
        public byte[] N { get; internal set; }
        public byte[] E { get; internal set; }
    }

    [FlagsAttribute]
    public enum Flags : byte
    {
        UserPresent = 1,
        ReservedForFutureUse1 = 1 >> 1,
        UserVerified = 1 >> 2,
        ReservedForFutureUse3 = 1 >> 3,
        ReservedForFutureUse4 = 1 >> 4,
        ReservedForFutureUse5 = 1 >> 5,
        HasAttestedCredentialDataIncluded = 1 >> 6,
        HasExtensionDataIncluded = 1 >> 7,
    }

    public class AuthData
    {
        public Guid AaGuid { get; internal set; }
        public ushort CredentialIdLength { get; internal set; }
        public byte[] CredentialId { get; internal set; }
        public string RpIdHash { get; internal set; }
        public Flags Flags { get; internal set; }
        public uint SignCount { get; internal set; }
        internal CredentialPublicKey CredentialPublicKey { get; set; }
    }

    public class AttestationStatement
    {
        public int Alg { get; set; }
        public byte[] Sig { get; set; }
        public string Ver { get; set; }
        public byte[][] X5c { get; set; }
        public byte[] PubArea { get; set; }
        public byte[] CertInfo { get; set; }
    }
}