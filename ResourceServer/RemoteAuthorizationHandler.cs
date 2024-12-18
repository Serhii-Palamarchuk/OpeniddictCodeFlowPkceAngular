﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Specialized;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace ResourceServer
{
    public class RemoteAuthorizationHandler : AuthorizationHandler<RemoteAuthorizationRequirement>
    {
        private readonly ILogger<RemoteAuthorizationHandler> _logger;
        private readonly AuthApiOptions _options;
        private readonly HttpClient _client;
        public RemoteAuthorizationHandler(ILogger<RemoteAuthorizationHandler> logger, IOptions<AuthApiOptions> options, IHttpClientFactory httpClientFactory)
        {
            _logger = logger;
            _options = options.Value;
            _client = httpClientFactory.CreateClient(nameof(RemoteAuthorizationHandler));
        }

        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, RemoteAuthorizationRequirement requirement)
        {
            bool isSucceed = false;
            if (context.Resource is HttpContext httpContext)
            {
                var endpoint = httpContext.GetEndpoint();
                var descriptor = endpoint.Metadata.GetMetadata<ControllerActionDescriptor>();

                var authHeader = httpContext.Request.Headers["Authorization"].First();
                var queryPars = HttpUtility.ParseQueryString(string.Empty);
                queryPars.Add("clientName", requirement.Client);
                queryPars.Add("controllerName", descriptor.ControllerName);
                queryPars.Add("actionName", descriptor.ActionName);
                
                var builder = new UriBuilder($"{_options.AuthUrl}/ValidateAccess");
                builder.Query = queryPars.ToString();
                using (var request = new HttpRequestMessage(HttpMethod.Post, builder.ToString()))
                {
                    request.Headers.Add("Authorization", authHeader);

                    using var response = await _client.SendAsync(request);
                    if (response.IsSuccessStatusCode)
                        isSucceed = true;
                    else
                        _logger.LogWarning($"Remote authorization failed with status code {response.StatusCode}. Content: {response.Content.ReadAsStringAsync()}");
                }
            }

            // Перевіряємо, чи є у користувача необхідна роль
            if (isSucceed)
            {
                // Якщо авторизація успішна
                context.Succeed(requirement);
                _logger.LogTrace("User is authorized to access this resource.");
            }
            else
            {
                // повертаємо помилку 403 (Forbidden)
                context.Fail();
                _logger.LogWarning("User is not authorized to access this resource.");
            }

            return;// Task.CompletedTask;
        }
    }

    public class RemoteAuthorizationRequirement : IAuthorizationRequirement
    {
        public RemoteAuthorizationRequirement(string client)
        {
            Client = client;
        }

        public string Client { get; }
    }
}
