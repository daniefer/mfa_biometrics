using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Policy;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using WebAuthenticationDemo.Business;
using WebAuthenticationDemo.Business.Algorithums;
using WebAuthenticationDemo.Controllers;
using WebAuthenticationDemo.Utilities;

namespace WebAuthenticationDemo
{
    public class CredentialManager
    {
        private static List<Credentials> Users = new List<Credentials>
        {
            new Credentials { Id = 1, Email = "dan@example.com", Username = "dan",  Password = "P@ssw0rd", Name = "Dan F." }
        };

        private readonly IConfiguration _config;
        private readonly HashSet<string> _allowedDomains;
        private readonly HashSet<byte[]> _allowedDomainHashes;
        private readonly AttestationParser _attestationParser;
        private readonly AuthDataParser _authDataParser;
        private readonly PublicKeyFactory _publicKeyFactory;
        private readonly JsonSerializerOptions _jsonSerializerOptions;

        public CredentialManager(IConfiguration config, AttestationParser attestationParser, AuthDataParser authDataParser, PublicKeyFactory publicKeyFactory)
        {
            _config = config;
            _allowedDomains = _config.GetSection("AllowedDomains").Get<HashSet<string>>();
            _allowedDomainHashes = _allowedDomains.Select(x => SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(x))).ToHashSet();
            _attestationParser = attestationParser;
            _authDataParser = authDataParser;
            _publicKeyFactory = publicKeyFactory;
            _jsonSerializerOptions = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        }

        public async Task<AuthenticationResult> Authenticate(Credentials credentials)
        {
            var user = Users.SingleOrDefault(x => x.Username == credentials.Username && x.Password == credentials.Password);
            if (user is null)
            {
                return new AuthenticationResult { Success = false };
            }
            return new AuthenticationResult
            {
                Success = true,
                Token = GenerateJWTToken(user),
                Id = user.Id.ToString(),
                Email = user.Email,
                Name = user.Name
            };
        }

        public async Task<AuthenticationResult> Authenticate(WebAuthenticationSignInRequest request)
        {
            var (user, credentials, signCount, publicKey) = Users
                .Select(x =>
                {
                    var credentials = x.Attestations.SingleOrDefault(x => x.Id == request.Id);
                    return (
                        user: x,
                        credentials,
                        signCount: credentials?.Attestation?.AuthData?.SignCount,
                        publicKey: credentials?.Attestation?.AuthData?.PublicKey
                    );
                })
                .Single(x => x.publicKey != null);

            if (user is null)
                return new AuthenticationResult { Success = false };

            if (!ValidateClientData(request.clientDataJSON, "webauthn.get"))
                return new AuthenticationResult { Success = false };

            if (!VerifySignature(request, publicKey))
                return new AuthenticationResult { Success = false };

            var assertion = _authDataParser.Parse(Convert.FromBase64String(request.Base64CborAssertion));
            if (!ValidateRpIdHash(assertion.RpIdHash))
                return new AuthenticationResult { Success = false };

            if (!assertion.Flags.HasFlag(AuthDataFlags.UserPresent))
                return new AuthenticationResult { Success = false };

            if (!assertion.Flags.HasFlag(AuthDataFlags.UserVerified))
                return new AuthenticationResult { Success = false };

            if (assertion.SignCount != 0 && assertion.SignCount < signCount)
                return new AuthenticationResult { Success = false };

            // update last sign count to avoid replays
            credentials.Attestation.AuthData.SignCount = assertion.SignCount;
            return new AuthenticationResult
            {
                Success = true,
                Token = GenerateJWTToken(user),
                Email = user.Email,
                Id = user.Id.ToString(),
                Name = user.Name
            };
        }

        private bool ValidateRpIdHash(string rpIdHash)
        {
            if (!_allowedDomainHashes.Contains(Convert.FromBase64String(rpIdHash), new SequencyEqualityComparer<byte>()))
                return false;
            return true;
        }

        private bool ValidateClientData(string clientDataJSON, string expectedType)
        {
            if (clientDataJSON is null)
                return false;

            var clientData = JsonSerializer.Deserialize<ClientData>(clientDataJSON, _jsonSerializerOptions);
            var challenge = clientData.Challenge.Length % 4 == 0 ? clientData.Challenge : clientData.Challenge + new string('=', 4 - clientData.Challenge.Length % 4);
            clientData.Challenge = Encoding.UTF8.GetString(Convert.FromBase64String(challenge));

            if (clientData.Type != expectedType)
                return false;

            if (!Uri.TryCreate(clientData.Origin, UriKind.Absolute, out var origin))
                return false;

            if (!_allowedDomains.Contains(origin.Host))
                return false;

            if (origin.Host != "localhost" && origin.Scheme != Uri.UriSchemeHttps)
                return false;

            if (!VerifyToken(clientData.Challenge))
                return false;

            // TODO: token binding status?

            return true;
        }

        private static bool VerifySignature(WebAuthenticationSignInRequest request, IPublicKey publicKey)
        {
            var hash = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(request.clientDataJSON));
            var assertion = Convert.FromBase64String(request.Base64CborAssertion);
            var data = assertion.Concat(hash).ToArray();
            var signature = Convert.FromBase64String(request.Signature);

            var sigProvider = new CryptoProviderFactory().CreateForVerifying(publicKey.GetSecurityKey(), publicKey.Algorithum);
            return sigProvider.Verify(data, signature);
        }

        internal async Task<ChallengeResult> Challenge()
        {

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:SecretKey"]));
            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };
            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(1),
                signingCredentials: signingCredentials
            );

            return new ChallengeResult
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                SupportedAlg = _publicKeyFactory.SupportedAlg
            };
        }

        public async Task Register(Credentials credentials)
        {
            if (Users.Any(x => x.Username == credentials.Username))
                throw new BadRequestException("Username already registered");
            Users.Add(credentials);
        }

        internal async Task RegisterAuthentication(WebAuthenticationRegistrationRequest registerAuthentication, IIdentity identity)
        {
            var identityId = (identity as ClaimsIdentity).Claims.Single(c => c.Type == JwtRegisteredClaimNames.Sid).Value;
            var user = Users.Single(x => x.Id.ToString() == identityId);

            if (!ValidateClientData(registerAuthentication.ClientDataJSON, "webauthn.create"))
                throw new BadRequestException("Registration failed validation.");

            var attestation = new RegisterAuthenticationAttestation
            {
                Id = registerAuthentication.Id,
                Type = registerAuthentication.Type,
                Extensions = registerAuthentication.Extensions,
                ClientData = JsonSerializer.Deserialize<ClientData>(registerAuthentication.ClientDataJSON, _jsonSerializerOptions),
                Attestation = _attestationParser.Parse(registerAuthentication.Base64CborAttestation),
            };
            var challenge = attestation.ClientData.Challenge.Length % 4 == 0 ? attestation.ClientData.Challenge : attestation.ClientData.Challenge + new string('=', 4 - attestation.ClientData.Challenge.Length % 4);
            attestation.ClientData.Challenge = Encoding.UTF8.GetString(Convert.FromBase64String(attestation.ClientData.Challenge));

            if (!ValidateRpIdHash(attestation.Attestation.AuthData.RpIdHash))
                throw new BadRequestException("Registration failed validation.");

            if (!attestation.Attestation.AuthData.Flags.HasFlag(AuthDataFlags.UserPresent))
                throw new BadRequestException("Registration failed validation.");

            if (!attestation.Attestation.AuthData.Flags.HasFlag(AuthDataFlags.UserVerified))
                throw new BadRequestException("Registration failed validation.");

            if (attestation.Attestation.AuthData.PublicKey == null) // Not a supported algorithum
                throw new BadRequestException("Registration failed validation.");



            user.Attestations.Add(attestation);
        }

        private bool VerifyToken(string token)
        {
            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:SecretKey"])),
                ValidAudience = _config["Jwt:Audience"],
                ValidIssuer = _config["Jwt:Issuer"],
            };
            try
            {
                var claimPrinciple = new JwtSecurityTokenHandler().ValidateToken(token, validationParameters, out var securityKey);
                var expirationClaim = claimPrinciple.FindFirst(JwtRegisteredClaimNames.Exp);
                var jtiClaim = claimPrinciple.FindFirst(JwtRegisteredClaimNames.Jti);
                if (jtiClaim is null || jtiClaim.Value is null)
                    return false;

                var expiration = int.Parse(expirationClaim.Value);
                var authTime = DateTimeUtilities.FromUnixTime(expiration);
                if (authTime < DateTime.UtcNow)
                    return false;
            }
            catch
            {
                return false;
            }
            return true;
        }

        private string GenerateJWTToken(Credentials userInfo) 
        { 
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:SecretKey"])); 
            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256); 
            var claims = new[] 
            { 
                new Claim(JwtRegisteredClaimNames.Sub, userInfo.Username), 
                new Claim("fullName", userInfo.Name), 
                new Claim(JwtRegisteredClaimNames.Sid, userInfo.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), 
            }; 
            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"], 
                audience: _config["Jwt:Audience"], 
                claims: claims, 
                expires: DateTime.Now.AddMinutes(30), 
                signingCredentials: signingCredentials
            ); 
            return new JwtSecurityTokenHandler().WriteToken(token); 
        }
    }
}
