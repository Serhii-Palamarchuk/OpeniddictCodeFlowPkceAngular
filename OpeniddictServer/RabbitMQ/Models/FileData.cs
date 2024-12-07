using System.Text.Json.Serialization;

namespace OpeniddictServer.RabbitMQ.Models
{
    public class FileData
    {
        [JsonPropertyName("fileName")]
        public string FileName { get; set; }

        // TODO: Как временное решение перейменован Data -> DataBytes
        // В дальнейшем рекомендую выполнять DeserializeObject к FileData
        // только в том случае если в Response ContentType равен чемуто из:
        // image/png || image/jpeg || application/pdf || text/html (список может быть дополнен)
        [JsonPropertyName("dataBytes")]
        public byte[] DataBytes { get; set; }

        [JsonPropertyName("dataBase64")]
        public string DataBase64 { get; set; }

        [JsonPropertyName("fileType")]
        public string FileType { get; set; }
    }
}
