using System.Collections.Generic;
using WebAuthenticationDemo.Controllers;

namespace WebAuthenticationDemo
{
    public class Credentials
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string Name { get; set; }
        public ICollection<RegisterAuthentication> RegisterAuthentications { get; } = new HashSet<RegisterAuthentication>();
        public string Email { get; set; }
        public int Id { get; internal set; }
    }
}
