using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MudBlazor.Services;
using OpenIddict.Abstractions;
using Soteria.Components;
using Soteria.Components.Account;
using Soteria.Components.Account.Email;
using Soteria.Data;

namespace Soteria;

public class Program
{
    public static async Task Main(string[] args)
    {
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

        var connectionString = builder.Configuration.GetConnectionString("SoteriaDb") ??
                               throw new InvalidOperationException("Connection string 'SoteriaDb' not found.");
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
        
        builder.Services.AddOpenIddict()
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore()
                    .UseDbContext<SoteriaDbContext>()
                    .ReplaceDefaultEntities<Guid>();
            })
            .AddServer(options =>
            {
                options.SetAuthorizationEndpointUris("/connect/authorize")
                    .SetTokenEndpointUris("/connect/token");

                options.RegisterScopes(
                    OpenIddictConstants.Scopes.Email,
                    OpenIddictConstants.Scopes.Profile);
                    
                options.AllowAuthorizationCodeFlow()
                    .RequireProofKeyForCodeExchange();

                options.UseAspNetCore()
                    .EnableAuthorizationEndpointPassthrough();

                if (builder.Environment.IsDevelopment())
                {
                    options.AddDevelopmentSigningCertificate()
                        .AddDevelopmentEncryptionCertificate();
                }
            });
        
        builder.Services.AddSingleton<IEmailSender<ApplicationUser>, DevelopmentEmailSender>();
        builder.Services.AddScoped<OpenIddictInitializer>();
        
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
        
        app.Run();
    }
}