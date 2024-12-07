using Microsoft.AspNetCore.Http;
using System.Text;

namespace OpeniddictServer.RabbitMQ.Models
{
    public class SerializableHttpResponse
    {
        public int StatusCode { get; set; }
        public Dictionary<string, string> Headers { get; set; }
        public string Body { get; set; }
        public string ContentType { get; set; }

        public static async Task<SerializableHttpResponse> FromHttpResponseAsync(HttpResponse response)
        {
            var serializableResponse = new SerializableHttpResponse
            {
                StatusCode = response.StatusCode,
                Headers = response.Headers.ToDictionary(h => h.Key, h => h.Value.ToString()),
                ContentType = response.ContentType
            };

            if (response.Body.CanRead)
            {
                response.Body.Seek(0, SeekOrigin.Begin); // Reset the stream position to the beginning
                using (StreamReader reader = new StreamReader(response.Body, Encoding.UTF8, leaveOpen: true))
                {
                    serializableResponse.Body = await reader.ReadToEndAsync();
                    response.Body.Position = 0; // Reset the stream position for any further usage
                }
            }

            return serializableResponse;
        }
    }
}
