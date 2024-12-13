using System.Collections.Generic;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpeniddictServer.RabbitMQ.Models
{
    public class Response
    {
        [JsonPropertyName("errorCode")]
        public int ErrorCode { get; set; }

        [JsonPropertyName("errorMessage")]
        public string ErrorMessage { get; set; }

        [JsonPropertyName("data")]
        public object Data { get; set; }

        [JsonPropertyName("contentType")]
        public string ContentType { get; set; }

        [JsonPropertyName("httpStatusCode")]
        public HttpStatusCode HttpStatusCode { get; set; }

        [JsonPropertyName("headers")]
        public Dictionary<string, string> Headers { get; set; }

        [JsonPropertyName("isWellFormed")]
        public bool IsWellFormed => Data != null || ContentType != null || ErrorCode > 0;

        public string Serialize()
        {
            return JsonSerializer.Serialize(this);
        }

        public string SerializeError()
        {
            return JsonSerializer.Serialize(new { errorCode = ErrorCode, errorMessage = ErrorMessage });
        }
    }
}
