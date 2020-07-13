namespace WebAuthenticationDemo.Controllers
{
    public class AttestationStatement
    {
        public int Alg { get; set; }
        public byte[] Sig { get; set; }
        public string Ver { get; set; }
        public byte[][] X5c { get; set; }
        public byte[] PubArea { get; set; }
        public byte[] CertInfo { get; set; }
    }
}