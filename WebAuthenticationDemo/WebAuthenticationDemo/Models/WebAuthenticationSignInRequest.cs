namespace WebAuthenticationDemo.Controllers
{
    public class WebAuthenticationSignInRequest
    {
        public string Id { get; set; }
        public string Type { get; set; }
        public Extensions Extensions { get; set; }
        public string clientDataJSON { get; set; }
        public string UserHandle { get; set; }
        public string Signature { get; set; }
        public string Base64CborAssertion { get; set; }
    }
}