using System;
using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Threading.Channels;
using System.Web;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using OpeniddictServer.RabbitMQ.Models;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using static Fido2NetLib.AuthenticatorAttestationRawResponse;

public class RabbitMQService : IDisposable
{
    private RabbitMQOptions _options;
    private readonly ILogger<RabbitMQService> _logger;
    private IConnection _connection;
    private IModel _channel;
    private readonly IDisposable _onChangeToken;
    private readonly IServiceProvider _serviceProvider;

    public RabbitMQService(IOptionsMonitor<RabbitMQOptions> optionsMonitor, ILogger<RabbitMQService> logger, IServiceProvider serviceProvider)
    {
        _options = optionsMonitor.CurrentValue;
        _logger = logger;
        InitializeRabbitMQ();
        _serviceProvider = serviceProvider;
    }

    public void UpdateOptions(RabbitMQOptions newOptions)
    {
        _options = newOptions;
        _logger.LogInformation("[uniGate]: RabbitMQ options have been updated.");
    }

    public void InitializeRabbitMQ()
    {
        var factory = new ConnectionFactory()
        {
            UserName = _options.UserName,
            Password = _options.Password,
            VirtualHost = _options.VHost,
        };

        var hosts = _options.Hosts.Split(',')
            .Select(h => h.Trim())
            .ToList();

        var endpoints = hosts.Select(host =>
        {
            var parts = host.Split(':');
            var hostName = parts[0];
            var port = parts.Length > 1 ? int.Parse(parts[1]) : _options.Port;
            return new AmqpTcpEndpoint(hostName, port);
        }).ToList();

        _connection = factory.CreateConnection(endpoints);
        _channel = _connection.CreateModel();
        _logger.LogInformation("RabbitMQ connection established.");
    }

    public void StartListening()
    {
        var queueType = _options.QueueType;
        var arguments = new Dictionary<string, object>
        {
            { "x-queue-type", queueType }
        };

        bool durable = queueType == "quorum";

        _channel.QueueDeclare(queue: _options.QueueName,
            durable: durable,
            exclusive: false,
            autoDelete: false,
            arguments: arguments);

        var consumer = new EventingBasicConsumer(_channel);

        consumer.Received += async (model, ea) =>
        {
            try
            {


                var body = ea.Body.ToArray();
                var message = Encoding.UTF8.GetString(body);
                var request = JsonConvert.DeserializeObject<Request>(message);

                Console.WriteLine($"Received from {_options.QueueName}: {message}");



                string path = request.HttpRequest.Path.Replace("/api/auth/v1/", "");

                Response response = new Response() { Headers = new Dictionary<string, string>() };
                using (var scope = _serviceProvider.CreateScope())
                {
                    var httpFactory = scope.ServiceProvider.GetRequiredService<IHttpClientFactory>();
                    var httpClient = httpFactory.CreateClient(nameof(RabbitMQService));
                    httpClient.BaseAddress = new Uri("https://localhost:44395");

                    //if (request.HttpRequest.Headers.Count > 0)
                    //    foreach (var header in request.HttpRequest.Headers)
                    //        httpClient.DefaultRequestHeaders.Add(header.Key, header.Value);

                    // Формуємо рядок заголовка Cookie
                    var cookieHeader = string.Join("; ", request.HttpRequest.Cookies.Select(kvp => $"{kvp.Key}={kvp.Value}"));

                    // Додаємо заголовок Cookie до запиту
                    using (var httpRequest = new HttpRequestMessage(HttpMethod.Parse(request.HttpRequest.Method), 
                        $"https://localhost:44395/{path}{request.HttpRequest.QueryString}"))
                    {


                        //httpRequest.Headers.Add("Cookie", cookieHeader);

                        //// Виконуємо запит
                        //var httpResponse = await httpClient.SendAsync(httpRequest);

                        if (request.HttpRequest.Path.EndsWith(".well-known/openid-configuration") ||
                            request.HttpRequest.Path.EndsWith("connect/authorize") ||
                            request.HttpRequest.Path.EndsWith("callback/login/Microsoft"))
                        {


                            using var httpResponse = await httpClient.SendAsync(httpRequest);
                            if (!httpResponse.IsSuccessStatusCode && httpResponse.StatusCode != System.Net.HttpStatusCode.Redirect)
                                throw new Exception($"Error: {httpResponse.StatusCode} - {httpResponse.ReasonPhrase}");

                            foreach (var header in httpResponse.Headers)
                                foreach (var value in header.Value)
                                    response.Headers.Add(header.Key, value);


                            if (request.HttpRequest.Path.EndsWith(".well-known/openid-configuration"))
                            {
                                var content = await httpResponse.Content.ReadAsStringAsync();

                                response.ContentType = request?.HttpRequest?.ContentType;
                                response.HttpStatusCode = System.Net.HttpStatusCode.OK;
                                response.Data = content;
                            }
                            else if (request.HttpRequest.Path.EndsWith("connect/authorize"))
                            {
                                response.ContentType = request?.HttpRequest?.ContentType;
                                response.HttpStatusCode = System.Net.HttpStatusCode.Redirect;
                                response.Data = "{}";
                            }
                            else if (request.HttpRequest.Path.EndsWith("callback/login/Microsoft"))
                            {

                            }

                        }
                        else
                        {

                            response.ContentType = request?.HttpRequest?.ContentType;
                            response.HttpStatusCode = System.Net.HttpStatusCode.BadRequest;
                            response.Data = new FileData() { FileName = "file.png", FileType = "image/png", DataBytes = System.IO.File.ReadAllBytes("C:\\Users\\spalamarchuk\\Pictures\\Screenpresso\\2024-10-29_16h37_33.png") };

                        }
                    }
                }

                //var responseBody = Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(new Response
                //{

                //    ContentType = request?.HttpRequest?.ContentType,
                //    HttpStatusCode = System.Net.HttpStatusCode.OK,
                //    Data = new { result = 1234, requestId = request.RequestId, message = "Слава Украине" }
                //}));
                //var json = JObject.Parse(request.HttpRequest.Body);
                //var number = Convert.ToInt32(json["number"]);
                //int result = number * number;

                //var responseBody = Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(new Response
                //{
                //    ContentType = request?.HttpRequest?.ContentType,
                //    HttpStatusCode = System.Net.HttpStatusCode.OK,
                //    Data = new
                //    {
                //        message = $"Demo. Піднесення до квадрату числа {number} = {result}!",
                //        result = result,
                //    }
                //}));


                //var json = JObject.Parse(message);

                //var responseQueue = json["queueName"].ToString();
                //var number = Convert.ToInt32(json["requestBody"]["number"]);
                //int result = number * number;
                //var responseBody = Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(new
                //{
                //    message = $"Demo. Піднесення до квадрату числа {number} = {result}!",
                //    result = result,
                //}));

                var props = _channel.CreateBasicProperties();
                props.CorrelationId = request.RequestId;
                _channel.BasicPublish(exchange: "",
                                    routingKey: request.QueueName,
                                    basicProperties: props,
                                    body: Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(response))
                                    );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error while processing message");
            }
        };

        _channel.BasicConsume(queue: _options.QueueName, autoAck: true, consumer: consumer);
        _logger.LogInformation("Started listening to queue {queueName}", _options.QueueName);
    }

    public void Dispose()
    {
        _onChangeToken?.Dispose();
        _channel?.Close();
        _connection?.Close();
    }
}