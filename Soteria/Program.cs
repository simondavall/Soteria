using DotNetEnv;
using MudBlazor.Services;
using Serilog;
using Soteria.Components;
using Soteria.Components.Account;
using Soteria.Components.Features;
using Soteria.Components.Features.Authorization;
using Soteria.Components.Features.OpenIdConnect;
using Soteria.Data;
using Soteria.Infrastructure.Logging;

namespace Soteria;

public class Program
{
    public static async Task Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        _ = bool.TryParse(Environment.GetEnvironmentVariable("SOTERIA_LOCAL_EXECUTION"), out var isLocalExecution);
        if (isLocalExecution)
        {
            Env.NoClobber()
                .TraversePath()
                .Load();

            builder.Configuration.AddEnvironmentVariables();

            builder.WebHost.UseStaticWebAssets();
        }

        builder.AddSoteriaLogging();
        Log.Information("Soteria is starting...");
        
        builder.Services.AddRazorComponents()
            .AddInteractiveServerComponents();
        builder.Services.AddMudServices();

        builder.Services.AddSoteriaDataProtection(builder.Environment, builder.Configuration);
        builder.Services.AddSoteriaPersistence(builder.Configuration);
        builder.Services.AddSoteriaIdentity(builder.Environment, builder.Configuration);
        builder.Services.AddSoteriaAuthorization();
        builder.Services.AddSoteriaOpenIddict(builder.Environment, builder.Configuration);
        builder.Services.AddSoteriaFeatures();

        var app = builder.Build();

        await app.InitialiseSoteriaAsync();

        if (app.Environment.IsDevelopment())
        {
            app.UseMigrationsEndPoint();
        }
        else
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }

        app.UseStatusCodePagesWithReExecute("/connect/error", createScopeForStatusCodePages: true);
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
        
        Log.Information("Soteria is shutting down...");
    }
}