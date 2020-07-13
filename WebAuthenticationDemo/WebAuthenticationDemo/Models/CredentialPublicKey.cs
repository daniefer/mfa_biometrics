namespace WebAuthenticationDemo.Controllers
{
    public class CredentialPublicKey
    {
        public string Kty { get; internal set; }
        public int Alg { get; internal set; }
        public string Crv { get; internal set; }
        public byte[] X { get; internal set; }
        public byte[] Y { get; internal set; }
        public byte[] N { get; internal set; }
        public byte[] E { get; internal set; }
    }
}