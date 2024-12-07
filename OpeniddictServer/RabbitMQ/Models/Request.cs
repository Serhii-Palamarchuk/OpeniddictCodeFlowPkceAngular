using System.Text.Json.Serialization;

namespace OpeniddictServer.RabbitMQ.Models
{
    public class Request
    {
        [JsonPropertyName("requestId")]
        public string RequestId { get; set; }

        [JsonPropertyName("httpRequest")]
        public SerializableHttpRequest HttpRequest { get; set; }

        [JsonPropertyName("command")]
        public string Command { get; set; }

        [JsonPropertyName("version")]
        public string Version { get; set; }

        [JsonPropertyName("project")]
        public string Project { get; set; }

        [JsonPropertyName("queueName")]
        public string QueueName { get; set; }

        [JsonPropertyName("useProxy")]
        public bool? UseProxy { get; set; }

        [JsonPropertyName("callbackUrl")]
        public string CallbackUrl { get; set; }

        public string Serialize()
        {
            return System.Text.Json.JsonSerializer.Serialize(this);
        }
    }
}
