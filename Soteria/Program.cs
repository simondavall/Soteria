using DotNetEnv;
using MudBlazor.Services;
using Serilog;
using Soteria.Components;
using Soteria.Components.Account;
using Soteria.Components.Features;
using Soteria.Components.Features.Authorization;
using Soteria.Components.Features.OpenIdConnect;
using Soteria.Data;
using Soteria.Data.Authorization;

namespace Soteria;

public class Program
{
    public static async Task Main(string[] args)
    {
        var productionLoggingConfigured = false;

        try
        {
            var builder = WebApplication.CreateBuilder(args);

            if (builder.Environment.IsDevelopment())
            {
                Env.NoClobber()
                    .TraversePath()
                    .Load();

                builder.Configuration.AddEnvironmentVariables();
            }
            else
            {
                SoteriaLogging.Configure(builder);
                productionLoggingConfigured = true;

                Log.Information("Starting Soteria in {EnvironmentName}", builder.Environment.EnvironmentName);
            }

            builder.Services.AddRazorComponents()
                .AddInteractiveServerComponents();
            builder.Services.AddMudServices();

            builder.Services.AddSoteriaDataProtection(builder.Environment, builder.Configuration);
            
            builder.Services.AddSoteriaPersistence(builder.Configuration);
            
            builder.Services.AddSoteriaIdentity(builder.Environment, builder.Configuration);
            builder.Services.AddSoteriaAuthorization();
            builder.Services.AddSoteriaOpenIddict(builder.Environment, builder.Configuration);

            builder.Services.AddSingleton<SoteriaAdministratorInitializer>();

            builder.Services.AddSoteriaFeatures();
            
            var app = builder.Build();

            await using (var scope = app.Services.CreateAsyncScope())
            {
                if (app.Environment.IsDevelopment())
                {
                    var openIddictInitializer = scope.ServiceProvider.GetRequiredService<OpenIddictInitializer>();
                    await openIddictInitializer.InitializeAsync();
                }

                var soteriaAdminInitializer = scope.ServiceProvider.GetRequiredService<SoteriaAdministratorInitializer>();
                await soteriaAdminInitializer.InitializeAsync();
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

            if (productionLoggingConfigured)
            {
                Log.Information("Soteria stopped normally");
            }
        }
        catch (Exception exception) when (productionLoggingConfigured)
        {
            Log.Fatal(exception, "Soteria terminated unexpectedly");
            throw;
        }
        finally
        {
            if (productionLoggingConfigured)
            {
                await Log.CloseAndFlushAsync();
            }
        }
    }
}