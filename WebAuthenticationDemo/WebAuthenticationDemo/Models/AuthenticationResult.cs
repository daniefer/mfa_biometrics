namespace WebAuthenticationDemo
{
    public class AuthenticationResult
    {
        public bool Success { get; internal set; }
        public string Token { get; internal set; }
        public string Id { get; set; }
        public string Email { get; set; }
        public string Name { get; set; }
    }
}
