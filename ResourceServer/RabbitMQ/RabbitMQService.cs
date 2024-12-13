using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Channels;
using System.Web;
using AuthService;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using OpeniddictServer.RabbitMQ.Models;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;

public class RabbitMQService : IDisposable
{
    private RabbitMQOptions _options;
    private readonly ILogger<RabbitMQService> _logger;
    private IConnection _connection;
    private IModel _channel;
    private readonly IDisposable _onChangeToken;
    private readonly IServiceProvider _serviceProvider;
    private readonly EndpointsOptions _endpointsOptions;

    public RabbitMQService(IOptionsMonitor<RabbitMQOptions> optionsMonitor, ILogger<RabbitMQService> logger, IServiceProvider serviceProvider, IOptions<EndpointsOptions> endpointsOptions)
    {
        _options = optionsMonitor.CurrentValue;
        _logger = logger;
        InitializeRabbitMQ();
        _serviceProvider = serviceProvider;
        _endpointsOptions = endpointsOptions.Value;
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

                Response response = new Response() { Headers = new Dictionary<string, string>() };
                using (var scope = _serviceProvider.CreateScope())
                {
                    var httpFactory = scope.ServiceProvider.GetRequiredService<IHttpClientFactory>();
                    var httpClient = httpFactory.CreateClient(nameof(RabbitMQService));
                    httpClient.Timeout = TimeSpan.FromSeconds(60);

                    var selfUrl = $"https://localhost:44390{request.HttpRequest.Path.Replace("/api/resource/v1", "")}{request.HttpRequest.QueryString}";
                    using (var httpRequest = new HttpRequestMessage(HttpMethod.Parse(request.HttpRequest.Method), selfUrl))
                    {
                        foreach (var header in request.HttpRequest.Headers)
                            httpRequest.Headers.TryAddWithoutValidation(header.Key, header.Value);

                        if (request.HttpRequest.Headers.FirstOrDefault(_ => _.Key == "Content-Type").Value == "application/x-www-form-urlencoded")//if (request.HttpRequest.Path.EndsWith("connect/token"))
                        {
                            var content = JsonConvert.DeserializeObject<Dictionary<string, string>>(request.HttpRequest.Body);
                            httpRequest.Content = new FormUrlEncodedContent(content);
                        }

                        using var httpResponse = await httpClient.SendAsync(httpRequest);
                        if (!httpResponse.IsSuccessStatusCode && httpResponse.StatusCode != System.Net.HttpStatusCode.Redirect)
                            _logger.LogError($"Error: {httpResponse.StatusCode} - {httpResponse.ReasonPhrase}");

                        foreach (var header in httpResponse.Headers)
                            foreach (var value in header.Value)
                                response.Headers.TryAdd(header.Key, value);

                        var respContent = await httpResponse.Content.ReadAsStringAsync();
                        response.ContentType = request?.HttpRequest?.ContentType;
                        response.HttpStatusCode = httpResponse.StatusCode;
                        response.Data = string.IsNullOrWhiteSpace(respContent) ? "{}" : respContent;
                    }

                    var props = _channel.CreateBasicProperties();
                    props.CorrelationId = request.RequestId;
                    _channel.BasicPublish(exchange: "",
                                        routingKey: request.QueueName,
                                        basicProperties: props,
                                        body: Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(response))
                                        );
                }
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