
namespace AuthService
{
    public static class EndpointPaths
    {
        public const string BaseAuthPath = "api/auth/v1";

        public const string Configuration = ".well-known/openid-configuration";
        public const string Cryptography = ".well-known/jwks";
        public const string Authorization = "connect/authorize";
        public const string Introspection = "connect/introspect";
        public const string Token = "connect/token";
        public const string Logout = "connect/logout";
        public const string UserInfo = "connect/userinfo";
        public const string Verify = "connect/verify";

        public const string ConfigurationExt = $"{BaseAuthPath}/{Configuration}";
        public const string CryptographyExt = $"{BaseAuthPath}/{Cryptography}";
        public const string AuthorizationExt = $"{BaseAuthPath}/{Authorization}";
        public const string IntrospectionExt = $"{BaseAuthPath}/{Introspection}";
        public const string TokenExt = $"{BaseAuthPath}/{Token}";
        public const string LogoutExt = $"{BaseAuthPath}/{Logout}";
        public const string UserInfoExt = $"{BaseAuthPath}/{UserInfo}";
        public const string VerifyExt = $"{BaseAuthPath}/{Verify}";

        public const string CallbackLoginMicrosoft = "callback/login/Microsoft";
        public const string CallbackLoginMicrosoftExt = $"{BaseAuthPath}/{CallbackLoginMicrosoft}";
        
        public const string ValidateAccess = "validateAccess";
        public const string ValidateAccessExt = $"{BaseAuthPath}/{ValidateAccess}";
    }

    public class EndpointsOptions
    {
        public const string Position = "Endpoints";
        public string BaseUriHttps { get; set; }       

        public string[] ConfigurationUris => GenerateUris(EndpointPaths.Configuration);
        public string[] CryptographyUris => GenerateUris(EndpointPaths.Cryptography);
        public string[] AuthorizationUris => GenerateUris(EndpointPaths.Authorization);
        public string[] IntrospectionUris => GenerateUris(EndpointPaths.Introspection);
        public string[] TokenUris => GenerateUris(EndpointPaths.Token);
        public string[] LogoutUris => GenerateUris(EndpointPaths.Logout);
        public string[] UserInfoUris => GenerateUris(EndpointPaths.UserInfo);
        public string[] VerifyUris => GenerateUris(EndpointPaths.Verify);

        public string CallbackLoginMicrosoftUri => GenerateUris(EndpointPaths.CallbackLoginMicrosoft)[0];

        public string IssuerUri => $"{BaseUriHttps}/{EndpointPaths.BaseAuthPath}";

        private string[] GenerateUris(string endpoint)
        {
            return new string[]
            {
                $"{BaseUriHttps}/{EndpointPaths.BaseAuthPath}/{endpoint}"
            };
        }
    }
}
