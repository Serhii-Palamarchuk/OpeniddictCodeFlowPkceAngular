using AuthService;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;

namespace OpeniddictServer
{
    public class ReplaceHostFilter : IResourceFilter
    {
        private readonly string _host;

        public ReplaceHostFilter(IOptions<EndpointsOptions> options)
        {
            var uri = new Uri(options.Value.ExternalUri);
            _host = $"{uri.Host}:{uri.Port}";
        }

        public void OnResourceExecuting(ResourceExecutingContext context)
        {
            // Заменяем Host в заголовке запроса
            if (context.HttpContext.Request.Headers.ContainsKey("Host"))
                context.HttpContext.Request.Headers["Host"] = _host;
        }

        public void OnResourceExecuted(ResourceExecutedContext context)
        {
            // Здесь можно реализовать пост-обработку, если нужно
        }
    }
}
