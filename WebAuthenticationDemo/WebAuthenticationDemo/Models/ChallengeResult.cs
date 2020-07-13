namespace WebAuthenticationDemo
{
    public class ChallengeResult
    {
        public string Token { get; internal set; }
        public int[] SupportedAlg { get; internal set; }
    }
}
