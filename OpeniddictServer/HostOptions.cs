namespace AuthService
{
    public class EndpointPaths
    {
        public const string Configuration = "/.well-known/openid-configuration";
        public const string Cryptography = "/.well-known/jwks";
        public const string Authorization = "/connect/authorize";
        public const string Introspection = "/connect/introspect";
        public const string Token = "/connect/token";
        public const string Logout = "/connect/logout";
        public const string UserInfo = "/connect/userinfo";
        public const string Verify = "/connect/verify";
    }

    public class EndpointsOptions
    {
        public const string Position = "Endpoints";
        public string BaseUriHttp { get; set; }
        public string BaseUriHttps { get; set; }        

        public string[] ConfigurationUris => GenerateUris(EndpointPaths.Configuration);
        public string[] CryptographyUris => GenerateUris(EndpointPaths.Cryptography);
        public string[] AuthorizationUris => GenerateUris(EndpointPaths.Authorization);
        public string[] IntrospectionUris => GenerateUris(EndpointPaths.Introspection);
        public string[] TokenUris => GenerateUris(EndpointPaths.Token);
        public string[] LogoutUris => GenerateUris(EndpointPaths.Logout);
        public string[] UserInfoUris => GenerateUris(EndpointPaths.UserInfo);
        public string[] VerifyUris => GenerateUris(EndpointPaths.Verify);

        private string[] GenerateUris(string endpoint)
        {
            return new string[]
            {
                $"{BaseUriHttps}{endpoint}",
                $"{BaseUriHttp}{endpoint}"
            };
        }
    }
}
