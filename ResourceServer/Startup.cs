using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.OpenApi.Models;
using OpenIddict.Validation.AspNetCore;
using ResourceServer.Model;
using ResourceServer.Repositories;
using System;

namespace ResourceServer;

public class Startup
{
    public Startup(IConfiguration configuration)
    {
        Configuration = configuration;
    }

    public IConfiguration Configuration { get; }

    public void ConfigureServices(IServiceCollection services)
    {
        var connection = Configuration.GetConnectionString("DefaultConnection");

        var _options = Configuration.GetSection(AuthApiOptions.Position).Get<AuthApiOptions>();

        services.Configure<AuthApiOptions>(Configuration.GetSection(AuthApiOptions.Position));

        services.AddDbContext<DataEventRecordContext>(options =>
            options.UseSqlite(connection)
        );

        services.AddCors(options =>
        {
            options.AddPolicy("AllowAllOrigins",
                builder =>
                {
                    builder
                        .AllowCredentials()
                        .WithOrigins("https://localhost:4200")
                        .SetIsOriginAllowedToAllowWildcardSubdomains()
                        .AllowAnyHeader()
                        .AllowAnyMethod();
                });
        });

        var guestPolicy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .RequireClaim("scope", "dataEventRecords")
            .Build();

        services.AddAuthentication(options =>
        {
            options.DefaultScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
        });

        // Register the OpenIddict validation components.
        services.AddOpenIddict()
            .AddValidation(options =>
            {
                // Note: the validation handler uses OpenID Connect discovery
                // to retrieve the address of the introspection endpoint.
                options.SetIssuer(_options.AuthUrl);
                options.AddAudiences(_options.Audience);

                // Configure the validation handler to use introspection and register the client
                // credentials used when communicating with the remote introspection endpoint.
                options.UseIntrospection()
                        .SetClientId(_options.ClientId)
                        .SetClientSecret(_options.ClientSecret);

                // Register the System.Net.Http integration.
                options.UseSystemNetHttp();

                // Register the ASP.NET Core host.
                options.UseAspNetCore();
            });

        services.AddScoped<IAuthorizationHandler, RequireScopeHandler>();

        services.AddAuthorization(options =>
        {
            //options.AddPolicy("dataEventRecordsPolicy", policyUser =>
            //{
            //    policyUser.Requirements.Add(new RequireScope());
            //});
            options.DefaultPolicy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser() // Or add other requirements as needed
            .AddRequirements(new RemoteAuthorizationRequirement(_options.ClientId))
            .Build();
        });
        services.AddScoped<IAuthorizationHandler, RemoteAuthorizationHandler>();

        services.AddSwaggerGen(c =>
        {
            // add JWT Authentication
            //var securityScheme = new OpenApiSecurityScheme
            //{
            //    Name = "JWT Authentication",
            //    Description = "Enter JWT Bearer token **_only_**",
            //    In = ParameterLocation.Header,
            //    Type = SecuritySchemeType.Http,
            //    Scheme = "bearer", // must be lower case
            //    BearerFormat = "JWT",
            //    Reference = new OpenApiReference
            //    {
            //        Id = JwtBearerDefaults.AuthenticationScheme,
            //        Type = ReferenceType.SecurityScheme
            //    }
            //};
            //c.AddSecurityDefinition(securityScheme.Reference.Id, securityScheme);
            //c.AddSecurityRequirement(new OpenApiSecurityRequirement
            //{
            //    {securityScheme, new string[] { }}
            //});

            c.SwaggerDoc("v1", new OpenApiInfo
            {
                Title = "Resource server",
                Version = "v1",
                Description = "Recource Server",
                Contact = new OpenApiContact
                {
                    Name = "damienbod",
                    Email = string.Empty,
                    Url = new Uri("https://damienbod.com/"),
                },
            });
        });


        services.AddControllers()
            .AddNewtonsoftJson();

        services.AddScoped<DataEventRecordRepository>();
    }

    public void Configure(IApplicationBuilder app)
    {
        app.UseSwagger();
        app.UseSwaggerUI(c =>
        {
            c.SwaggerEndpoint("/swagger/v1/swagger.json", "Resource Server");
            c.RoutePrefix = string.Empty;
        });

        app.UseExceptionHandler("/Home/Error");
        app.UseCors("AllowAllOrigins");
        app.UseStaticFiles();

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers();
        });
    }
}
