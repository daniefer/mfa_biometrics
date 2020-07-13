namespace WebAuthenticationDemo.Controllers
{
    public class RegisterAuthenticationAttestation
    {
        public string Id { get; set; }
        public string Type { get; set; }
        public Extensions Extensions { get; set; }
        public ClientData ClientData { get; set; }
        public Attestation Attestation { get; set; }
    }
}