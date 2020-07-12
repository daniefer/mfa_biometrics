using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using WebAuthenticationDemo.Controllers;

namespace WebAuthenticationDemo
{
    public class CredentialManager
    {
        private static List<Credentials> Users = new List<Credentials>
        {
            new Credentials { Id = 1, Email = "dan@example.com", Username = "dan",  Password = "P@ssw0rd", Name = "Dan F." }
        };

        private readonly IConfiguration _config;

        public CredentialManager(IConfiguration config)
        {
            _config = config;
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

        public async Task<AuthenticationResult> Authenticate(AuthenticationPrompt prompt)
        {
            var user = Users.SingleOrDefault(x => x.RegisterAuthentications.Any(x => x.Id == prompt.Id));
            if (user is null)
            {
                return new AuthenticationResult { Success = false };
            }
            var authentication = user.RegisterAuthentications.Single(x => x.Id == prompt.Id);
            var f = new RSACryptoServiceProvider(new CspParameters());
            f.ImportParameters(new RSAParameters
            {
                Exponent = authentication.Attestation.AuthData.CredentialPublicKey.E,
                Modulus = authentication.Attestation.AuthData.CredentialPublicKey.N,
            });
            var crypt = CryptoConfig.CreateFromName("SHA256");
            var hash = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(prompt.clientDataJSON));
            var data = Convert.FromBase64String(prompt.Base64CborAssertion).Concat(hash).ToArray();
            var result = f.VerifyData(data, crypt, Convert.FromBase64String(prompt.Signature));
            if (!result)
            {
                return new AuthenticationResult { Success = false };
            }
            return new AuthenticationResult
            {
                Success = true,
                Token = GenerateJWTToken(user),
                Email = user.Email,
                Id = user.Id.ToString(),
                Name = user.Name
            };
        }

        internal async Task<WebAuthenticationDemo.ChallengeResult> Challenge()
        {

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:SecretKey"]));
            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.AuthTime, DateTime.UtcNow.ToString("O")),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };
            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: signingCredentials
            );

            return new ChallengeResult
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token)
            };
        }

        public async Task Register(Credentials credentials)
        {
            if (Users.Any(x => x.Username == credentials.Username))
                throw new BadRequestException("Username already registered");
            Users.Add(credentials);
        }

        internal async Task RegisterAuthentication(RegisterAuthentication registerAuthentication, IIdentity identity)
        {
            var identityId = (identity as ClaimsIdentity).Claims.Single(c => c.Type == JwtRegisteredClaimNames.Sid).Value;
            var user = Users.Single(x => x.Id.ToString() == identityId);
            Console.WriteLine(registerAuthentication.Attestation.AuthData);
            user.RegisterAuthentications.Add(registerAuthentication);
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
