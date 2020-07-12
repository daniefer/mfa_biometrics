using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace WebAuthenticationDemo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly CredentialManager _credentialManager;

        public LoginController(CredentialManager credentialManager)
        {
            _credentialManager = credentialManager;
        }

        [HttpPost("register/user")]
        public async Task Register(Credentials credentials)
        {
            await _credentialManager.Register(credentials);
        }

        [HttpPost]
        public async Task<AuthenticationResult> Login(Credentials credentials)
        {
            return await _credentialManager.Authenticate(credentials);
        }

        [HttpGet("challenge")]
        public async Task<ChallengeResult> AuthenticationChallenge()
        {
            return await _credentialManager.Challenge();
        }

        [HttpPost("authenticate")]
        public async Task<AuthenticationResult> Authenticate(AuthenticationPrompt credentials)
        {
            return await _credentialManager.Authenticate(credentials);
        }

        [HttpPost("register/authentication")]
        [Authorize("default")]
        public async Task RegisterAuthentication(RegisterAuthentication registerAuthentication)
        {
            await _credentialManager.RegisterAuthentication(registerAuthentication, User.Identity);
        }
    }
}