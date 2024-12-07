namespace OpeniddictServer.RabbitMQ.Models
{
    using Microsoft.AspNetCore.Http;
    using System.Text;
    using System.Text.Json;

    public class SerializableHttpRequest
    {
        public string Method { get; set; }
        public string Path { get; set; }
        public string QueryString { get; set; }
        public Dictionary<string, string> Headers { get; set; }
        public string Body { get; set; }
        public string ContentType { get; set; }

        public Dictionary<string, string> Cookies { get; set; }

    }


}
