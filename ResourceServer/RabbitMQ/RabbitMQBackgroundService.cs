using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using System;
using System.Threading;
using System.Threading.Tasks;


public class RabbitMQBackgroundService : BackgroundService
{
    private readonly RabbitMQService _rabbitMQService;
    private readonly IDisposable _onChangeToken;

    public RabbitMQBackgroundService(RabbitMQService rabbitMQService, IOptionsMonitor<RabbitMQOptions> optionsMonitor)
    {
        _rabbitMQService = rabbitMQService;
        _onChangeToken = optionsMonitor.OnChange(newOptions =>
        {
            _rabbitMQService.UpdateOptions(newOptions);
            _rabbitMQService.InitializeRabbitMQ();
            _rabbitMQService.StartListening();
        });
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _rabbitMQService.InitializeRabbitMQ();
        _rabbitMQService.StartListening();
        return Task.CompletedTask;
    }

    public override void Dispose()
    {
        _onChangeToken?.Dispose();
        base.Dispose();
    }
}