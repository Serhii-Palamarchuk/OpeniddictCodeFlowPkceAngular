namespace OpeniddictServer.Controllers
{
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Text.Json;
    public class MicrosoftClient
    {

        public async Task<string> GetAccessTokenAsync(string authorizationCode, string clientId, string clientSecret, string redirectUri, string tenantId, string scope)
        {
            using var client = new HttpClient();

            var tokenEndpoint = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token";

            var content = new FormUrlEncodedContent(new[]
            {
            new KeyValuePair<string, string>("client_id", clientId),
            new KeyValuePair<string, string>("scope", scope),
            new KeyValuePair<string, string>("code", authorizationCode),
            new KeyValuePair<string, string>("redirect_uri", redirectUri),
            new KeyValuePair<string, string>("grant_type", "authorization_code"),
            new KeyValuePair<string, string>("client_secret", clientSecret),
        });

            var response = await client.PostAsync(tokenEndpoint, content);
            var responseBody = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidOperationException($"Failed to get access token: {responseBody}");
            }

            var tokenResponse = JsonSerializer.Deserialize<JsonElement>(responseBody);
            return tokenResponse.GetProperty("access_token").GetString();
        }
        public async Task<JsonElement> GetUserProfileAsync(string accessToken)
        {
            using var client = new HttpClient();
            var request = new HttpRequestMessage(HttpMethod.Get, "https://graph.microsoft.com/v1.0/me");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var response = await client.SendAsync(request);
            var responseBody = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidOperationException($"Failed to get user profile: {responseBody}");
            }

            return JsonSerializer.Deserialize<JsonElement>(responseBody);
        }
    }
}