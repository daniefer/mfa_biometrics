using System.Collections.Generic;
using WebAuthenticationDemo.Controllers;

namespace WebAuthenticationDemo
{
    public class Credentials
    {
        public int Id { get; internal set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        internal ICollection<RegisterAuthenticationAttestation> Attestations { get; } = new HashSet<RegisterAuthenticationAttestation>();
    }
}
