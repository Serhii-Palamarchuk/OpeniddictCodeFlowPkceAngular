namespace ResourceServer
{
    public class AuthApiOptions
    {
        public const string Position = "AuthApiOptions";

        public string Url { get; set; }
        public string ValidateAccessPath { get; set; }

        public string Audience { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
    }
}
