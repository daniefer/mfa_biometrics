namespace WebAuthenticationDemo.Controllers
{
    public class AuthenticationPrompt
    {
        public string Id { get; set; }
        public string Type { get; set; }
        public Extensions Extensions { get; set; }
        public ClientData ClientData { get; set; }
        public string clientDataJSON { get; set; }
        public string UserHandle { get; set; }
        public string Signature { get; set; }
        public string Base64CborAssertion { get; set; }
    }
}