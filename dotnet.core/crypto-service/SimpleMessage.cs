namespace crypto_service
{
    internal class SimpleMessage
    {
        public SimpleMessage()
        {
        }

        public string AuthorizationHeader { get; internal set; }
        public string BodyContents { get; internal set; }
    }
}