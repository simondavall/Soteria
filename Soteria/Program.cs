using DotNetEnv;
using FluentValidation;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using MudBlazor.Services;
using OpenIddict.Abstractions;
using Soteria.Components;
using Soteria.Components.Account;
using Soteria.Components.Account.Email;
using Soteria.Components.Features.Clients;
using Soteria.Components.Features.Clients.Queries;
using Soteria.Components.Features.Shared;
using Soteria.Data;
using Soteria.Data.OpenIddict;

namespace Soteria;

public class Program
{
    public static async Task Main(string[] args)
    {
        Env.TraversePath().Load();
        
        var builder = WebApplication.CreateBuilder(args);

        // Add services to the container.
        builder.Services.AddRazorComponents()
            .AddInteractiveServerComponents();
        builder.Services.AddMudServices();

        builder.Services.AddCascadingAuthenticationState();
        builder.Services.AddScoped<IdentityRedirectManager>();
        builder.Services.AddScoped<AuthenticationStateProvider, IdentityRevalidatingAuthenticationStateProvider>();

        builder.Services.AddAuthentication(options =>
            {
                options.DefaultScheme = IdentityConstants.ApplicationScheme;
                options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
            })
            .AddIdentityCookies();

        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.LoginPath = "/Account/Login";
            options.ReturnUrlParameter = "ReturnUrl";
        });

        var connectionString = builder.Configuration.GetConnectionString("SoteriaDb")
            ?? throw new InvalidOperationException(
                "Connection string 'SoteriaDb' not found.");

        builder.Services.AddDbContext<SoteriaDbContext>(options =>
            options.UseSqlite(connectionString));
        builder.Services.AddDatabaseDeveloperPageExceptionFilter();

        builder.Services.AddIdentityCore<ApplicationUser>(options =>
            {
                options.SignIn.RequireConfirmedAccount = true;
                options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
            })
            .AddEntityFrameworkStores<SoteriaDbContext>()
            .AddSignInManager()
            .AddDefaultTokenProviders();

        var tokenConfiguration = builder.Configuration.GetRequiredSection("OpenIddict:Tokens");

        var accessTokenLifetimeMinutes = tokenConfiguration.GetValue<int>("AccessTokenLifetimeMinutes");
        if (accessTokenLifetimeMinutes <= 0)
        {
            throw new InvalidOperationException("OpenIddict:Tokens:AccessTokenLifetimeMinutes must be greater than zero.");
        }

        var refreshTokenLifetimeDays = tokenConfiguration.GetValue<int>("RefreshTokenLifetimeDays");
        if (refreshTokenLifetimeDays <= 0)
        {
            throw new InvalidOperationException("OpenIddict:Tokens:RefreshTokenLifetimeDays must be greater than zero.");
        }
        
        var encryptionKey = builder.Configuration["OpenIddict:EncryptionKey"]
                            ?? throw new InvalidOperationException(
                                "The OpenIddict:EncryptionKey configuration value is required.");
        
        builder.Services.AddOpenIddict()
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore()
                    .UseDbContext<SoteriaDbContext>()
                    .ReplaceDefaultEntities<
                        SoteriaApplication,
                        SoteriaAuthorization,
                        SoteriaScope,
                        SoteriaToken,
                        Guid>();
            })
            .AddServer(options =>
            {
                options.SetAuthorizationEndpointUris("/connect/authorize")
                    .SetEndSessionEndpointUris("/connect/logout")
                    .SetTokenEndpointUris("/connect/token");
                
                options.SetAccessTokenLifetime(TimeSpan.FromMinutes(accessTokenLifetimeMinutes))
                    .SetRefreshTokenLifetime(TimeSpan.FromDays(refreshTokenLifetimeDays));

                //options.DisableAccessTokenEncryption();
                
                options.RegisterScopes(
                    OpenIddictConstants.Scopes.Email,
                    OpenIddictConstants.Scopes.Profile,
                    OpenIddictConstants.Scopes.OfflineAccess);

                options.AllowAuthorizationCodeFlow()
                    .AllowRefreshTokenFlow()
                    .RequireProofKeyForCodeExchange();

                options.UseAspNetCore()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableEndSessionEndpointPassthrough();

                if (builder.Environment.IsDevelopment())
                {
                    options.AddDevelopmentSigningCertificate();
                    //options.AddDevelopmentEncryptionCertificate();
                    options.AddEncryptionKey(new SymmetricSecurityKey(Convert.FromBase64String(encryptionKey)));
                }
            });
        
        builder.Services.AddSingleton<IEmailSender<ApplicationUser>, DevelopmentEmailSender>();
        
        builder.Services.AddScoped<OpenIddictInitializer>();
        
        builder.Services.AddScoped<IClientApplicationLookup, ClientApplicationLookup>();
        builder.Services.AddScoped<ClientService>();
        
        builder.Services.AddTransient<CreateClientValidator>();
        builder.Services.AddTransient<IValidator<CreateClientRequest>>(
            provider => provider.GetRequiredService<CreateClientValidator>());
        builder.Services.AddTransient<IMudValidator<CreateClientRequest>>(
            provider => provider.GetRequiredService<CreateClientValidator>());

        builder.Services.AddTransient<EditClientValidator>();
        builder.Services.AddTransient<IValidator<EditClientRequest>>(
            provider => provider.GetRequiredService<EditClientValidator>());
        builder.Services.AddTransient<IMudValidator<EditClientRequest>>(
            provider => provider.GetRequiredService<EditClientValidator>());
        
        var app = builder.Build();

        await using (var scope = app.Services.CreateAsyncScope())
        {
            var initializer = scope.ServiceProvider.GetRequiredService<OpenIddictInitializer>();
            await initializer.InitializeAsync();
        }

        // Configure the HTTP request pipeline.
        if (app.Environment.IsDevelopment())
        {
            app.UseMigrationsEndPoint();
        }
        else
        {
            app.UseExceptionHandler("/Error");
            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            app.UseHsts();
        }

        app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
        app.UseHttpsRedirection();

        app.UseAuthentication();
        app.UseAuthorization();

        app.UseAntiforgery();

        app.MapStaticAssets();
        app.MapRazorComponents<App>()
            .AddInteractiveServerRenderMode();

        // Add additional endpoints required by the Identity /Account Razor components.
        app.MapAdditionalIdentityEndpoints();

        app.MapSoteriaAuthorizationEndpoint();
        app.MapSoteriaLogoutEndpoint();

        await app.RunAsync();
    }
}