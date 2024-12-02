using Fido2Identity;
using Fido2NetLib;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Validation.AspNetCore;
using OpeniddictServer.Data;
using Quartz;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpeniddictServer;

public class Startup
{
    public Startup(IConfiguration configuration)
        => Configuration = configuration;

    public IConfiguration Configuration { get; }

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddControllersWithViews();
        services.AddRazorPages();

        services.AddDbContext<ApplicationDbContext>(options =>
        {
            // Configure the context to use Microsoft SQL Server.
            options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"));

            // Register the entity sets needed by OpenIddict.
            // Note: use the generic overload if you need
            // to replace the default OpenIddict entities.
            options.UseOpenIddict();
        });

        services.AddDatabaseDeveloperPageExceptionFilter();

        services.AddIdentity<ApplicationUser, IdentityRole>()
          .AddEntityFrameworkStores<ApplicationDbContext>()
          .AddDefaultTokenProviders()
          .AddDefaultUI()
          .AddTokenProvider<Fido2UserTwoFactorTokenProvider>("FIDO2");

        services.Configure<Fido2Configuration>(Configuration.GetSection("fido2"));
        services.AddScoped<Fido2Store>();

        services.AddDistributedMemoryCache();

        services.AddSession(options =>
        {
            options.IdleTimeout = TimeSpan.FromMinutes(2);
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.None;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        });

        services.Configure<IdentityOptions>(options =>
        {
            // Configure Identity to use the same JWT claims as OpenIddict instead
            // of the legacy WS-Federation claims it uses by default (ClaimTypes),
            // which saves you from doing the mapping in your authorization controller.
            options.ClaimsIdentity.UserNameClaimType = Claims.Name;
            options.ClaimsIdentity.UserIdClaimType = Claims.Subject;
            options.ClaimsIdentity.RoleClaimType = Claims.Role;
            options.ClaimsIdentity.EmailClaimType = Claims.Email;

            // Note: to require account confirmation before login,
            // register an email sender service (IEmailSender) and
            // set options.SignIn.RequireConfirmedAccount to true.
            //
            // For more information, visit https://aka.ms/aspaccountconf.
            options.SignIn.RequireConfirmedAccount = false;
        });

        // OpenIddict offers native integration with Quartz.NET to perform scheduled tasks
        // (like pruning orphaned authorizations/tokens from the database) at regular intervals.
        services.AddQuartz(options =>
        {
            options.UseMicrosoftDependencyInjectionJobFactory();
            options.UseSimpleTypeLoader();
            options.UseInMemoryStore();
        });

        services.AddCors(options =>
        {
            options.AddPolicy("AllowAllOrigins",
                builder =>
                {
                    builder
                        .AllowCredentials()
                        .WithOrigins(
                            "https://localhost:4200", "https://localhost:4204", "http://localhost:4200")
                        .SetIsOriginAllowedToAllowWildcardSubdomains()
                        .AllowAnyHeader()
                        .AllowAnyMethod();
                });
        });

        // Register the Quartz.NET service and configure it to block shutdown until jobs are complete.
        services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);

        //services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        //    .AddOpenIdConnect("KeyCloak", "KeyCloak", options =>
        //    {
        //        options.SignInScheme = "Identity.External";
        //        //Keycloak server
        //        options.Authority = Configuration.GetSection("Keycloak")["ServerRealm"];
        //        //Keycloak client ID
        //        options.ClientId = Configuration.GetSection("Keycloak")["ClientId"];
        //        //Keycloak client secret in user secrets for dev
        //        options.ClientSecret = Configuration.GetSection("Keycloak")["ClientSecret"];
        //        //Keycloak .wellknown config origin to fetch config
        //        options.MetadataAddress = Configuration.GetSection("Keycloak")["Metadata"];
        //        //Require keycloak to use SSL

        //        options.GetClaimsFromUserInfoEndpoint = true;
        //        options.Scope.Add("openid");
        //        options.Scope.Add("profile");
        //        options.SaveTokens = true;
        //        options.ResponseType = OpenIdConnectResponseType.Code;
        //        options.RequireHttpsMetadata = false; //dev

        //        options.TokenValidationParameters = new TokenValidationParameters
        //        {
        //            NameClaimType = "name",
        //            RoleClaimType = ClaimTypes.Role,
        //            ValidateIssuer = true
        //        };
        //    })
        //    ;

        services.AddOpenIddict()
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore()
                       .UseDbContext<ApplicationDbContext>();

                options.UseQuartz();
            })
    // Register the OpenIddict client components.
    .AddClient(options =>
    {
        // Note: this sample uses the code flow, but you can enable the other flows if necessary.
        options.AllowPasswordFlow()
               .AllowClientCredentialsFlow()
               .AllowRefreshTokenFlow()
               .AllowAuthorizationCodeFlow()
               ;

        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();
        //options.AddSigningCertificate(certificate);
        //options.AddEncryptionCertificate(certificate);

        // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
        options.UseAspNetCore()
               .EnableRedirectionEndpointPassthrough()
               .DisableTransportSecurityRequirement();

        // Register the System.Net.Http integration and use the identity of the current
        // assembly as a more specific user agent, which can be useful when dealing with
        // providers that use the user agent as a way to throttle requests (e.g Reddit).
        options.UseSystemNetHttp()
               .SetProductInformation(typeof(Program).Assembly);

        // Register the Web providers integrations.
        //
        // Note: to mitigate mix-up attacks, it's recommended to use a unique redirection endpoint
        // URI per provider, unless all the registered providers support returning a special "iss"
        // parameter containing their URL as part of authorization responses. For more information,
        // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.4.
        options.UseWebProviders()
               .AddMicrosoft(options =>
               {
                   options.SetProviderName("Microsoft")
                          .SetTenant("6f80195d-51ab-4c14-aaff-b04c01e5be9c")
                          .SetClientId("d186b2f4-cb66-4b10-b670-3f9b0c4f29d3")
                          .SetClientSecret("ZJO8Q~wN_jVB_nqhH321-Wa4GtLDTqWggBUkSde8")
                          .SetRedirectUri($"https://localhost:44395/callback/login/Microsoft")
                          .AddScopes(Scopes.OpenId, Scopes.Profile, Scopes.Email, Scopes.Phone)
                          ;
               })
               .AddGitHub(options =>
               {
                   options.SetProviderName("GitHub")
                          .SetClientId("Ov23lia1Jj87inESrWQL")
                          .SetClientSecret("c58949026d25d6edb5c6c47a00cc5377b2e6fb02")
                          .SetRedirectUri($"https://localhost:44395/callback/login/github")
                          ;
               })
               ;
    })
            .AddServer(options =>
            {
                // Enable the authorization, logout, token and userinfo endpoints.
                options.SetAuthorizationEndpointUris("connect/authorize")
                   //.SetDeviceEndpointUris("connect/device")
                   .SetIntrospectionEndpointUris("connect/introspect")
                   .SetLogoutEndpointUris("connect/logout")
                   .SetTokenEndpointUris("connect/token")
                   .SetUserinfoEndpointUris("connect/userinfo")
                   .SetVerificationEndpointUris("connect/verify");

                options.AllowAuthorizationCodeFlow()
                       .AllowHybridFlow()
                       .AllowClientCredentialsFlow()
                       .AllowRefreshTokenFlow();

                options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, "dataEventRecords");

                options.AddDevelopmentEncryptionCertificate()
                       .AddDevelopmentSigningCertificate();

                options.UseAspNetCore()
                       .EnableAuthorizationEndpointPassthrough()
                       .EnableLogoutEndpointPassthrough()
                       .EnableTokenEndpointPassthrough()
                       .EnableUserinfoEndpointPassthrough()
                       .EnableStatusCodePagesIntegration();
            })
            .AddValidation(options =>
            {
                options.UseLocalServer();
                options.UseAspNetCore();
            });

        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie();

        services.AddHostedService<Worker>();
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        IdentityModelEventSource.ShowPII = true;

        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
            app.UseMigrationsEndPoint();
        }
        else
        {
            app.UseStatusCodePagesWithReExecute("~/error");
            //app.UseExceptionHandler("~/error");

            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            //app.UseHsts();
        }

        app.UseHttpsRedirection();
        app.UseStaticFiles();

        app.UseRouting();

        app.UseCors("AllowAllOrigins");

        app.UseAuthentication();
        app.UseAuthorization();

        app.UseSession();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers();
            endpoints.MapDefaultControllerRoute();
            endpoints.MapRazorPages();
        });
    }
}
