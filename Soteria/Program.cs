using DotNetEnv;
using FluentValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using MudBlazor.Services;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using Serilog;
using static OpenIddict.Server.OpenIddictServerEvents;
using Soteria.Components;
using Soteria.Components.Account;
using Soteria.Components.Account.Email;
using Soteria.Components.Features.Authorization;
using Soteria.Components.Features.ClientMemberships;
using Soteria.Components.Features.ClientMemberships.Queries;
using Soteria.Components.Features.Clients;
using Soteria.Components.Features.Clients.Queries;
using Soteria.Components.Features.OpenIdConnect;
using Soteria.Components.Features.Shared;
using Soteria.Components.Features.Users;
using Soteria.Components.Features.Users.Queries;
using Soteria.Data;
using Soteria.Data.Authorization;
using Soteria.Data.OpenIddict;

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

            builder.Services.AddSoteriaDataProtection(builder.Environment);

            builder.Services.AddCascadingAuthenticationState();

            builder.Services.AddAuthorization(options =>
            {
                options.AddPolicy(SoteriaAuthorizationPolicies.SoteriaAdministrator, policy =>
                {
                    policy.RequireAuthenticatedUser();
                    policy.AddRequirements(new SoteriaAdminRequirement());
                });

                options.AddPolicy(SoteriaAuthorizationPolicies.Administration, policy =>
                {
                    policy.RequireAuthenticatedUser();
                    policy.AddRequirements(new AdministrationRequirement());
                });
            });

            builder.Services.AddHttpContextAccessor();

            builder.Services.AddScoped<IAuthorizationHandler, SoteriaAdminAuthorizationHandler>();
            builder.Services.AddScoped<IAuthorizationHandler, AdministrationAuthorizationHandler>();
            builder.Services.AddScoped<ICurrentUserContext, CurrentUserContext>();

            builder.Services.AddScoped<IOpenIdClientMembershipResolver, OpenIdClientMembershipResolver>();
            builder.Services.AddScoped<IOpenIdAuthorizationContext, OpenIdAuthorizationContext>();
            builder.Services.AddScoped<IOpenIdPrincipalFactory, OpenIdPrincipalFactory>();

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
                options.Cookie.Name = "Soteria.Identity";
                options.LoginPath = "/Account/Login";
                options.ReturnUrlParameter = "ReturnUrl";
            });

            var connectionString = builder.Configuration.GetConnectionString("SoteriaDb")
                                   ?? throw new InvalidOperationException("Connection string 'SoteriaDb' not found.");

            builder.Services.AddDbContext<SoteriaDbContext>(options => options.UseSqlite(connectionString));
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

                    options.AddEventHandler<ValidateAuthorizationRequestContext>(b => b
                        .UseScopedHandler<ValidateClientIsEnabled>()
                        .SetOrder(int.MaxValue - 100_000));

                    options.AddEventHandler<ValidateTokenRequestContext>(b => b
                        .UseScopedHandler<ValidateClientIsEnabled>()
                        .SetOrder(int.MaxValue - 100_000));

                    options.AddEventHandler<HandleTokenRequestContext>(b => b
                        .UseScopedHandler<ValidateClientMembership>()
                        .SetOrder(
                            OpenIddictServerHandlers.Exchange.AttachPrincipal.Descriptor.Order +
                            1_000));

                    options.UseAspNetCore()
                        .EnableAuthorizationEndpointPassthrough()
                        .EnableEndSessionEndpointPassthrough()
                        .EnableStatusCodePagesIntegration();

                    options.AddSoteriaCredentials(builder.Environment, builder.Configuration);
                });

            if (builder.Environment.IsDevelopment())
            {
                builder.Services.AddSingleton<IEmailSender<ApplicationUser>, DevelopmentEmailSender>();
            }
            else
            {
                var emailOptions = EmailOptionsLoader.Load(builder.Configuration);
                builder.Services.AddSingleton(emailOptions);
                builder.Services.AddSingleton<IEmailSender<ApplicationUser>, EmailSender>();
            }

            //builder.Services.AddSingleton<IEmailSender<ApplicationUser>, DevelopmentEmailSender>();

            builder.Services.AddScoped<OpenIddictInitializer>();
            builder.Services.AddSingleton<SoteriaAdministratorInitializer>();

            builder.Services.AddScoped<IClientApplicationLookup, ClientApplicationLookup>();
            builder.Services.AddScoped<ClientService>();
            builder.Services.AddTransient<CreateClientValidator>();
            builder.Services.AddTransient<IValidator<CreateClientRequest>>(provider => provider.GetRequiredService<CreateClientValidator>());
            builder.Services.AddTransient<IMudValidator<CreateClientRequest>>(provider => provider.GetRequiredService<CreateClientValidator>());
            builder.Services.AddTransient<EditClientValidator>();
            builder.Services.AddTransient<IValidator<EditClientRequest>>(provider => provider.GetRequiredService<EditClientValidator>());
            builder.Services.AddTransient<IMudValidator<EditClientRequest>>(provider => provider.GetRequiredService<EditClientValidator>());

            builder.Services.AddScoped<IUserLookup, UserLookup>();
            builder.Services.AddScoped<UserService>();

            builder.Services.AddScoped<CreateUserValidator>();
            builder.Services.AddScoped<IValidator<CreateUserRequest>>(provider => provider.GetRequiredService<CreateUserValidator>());
            builder.Services.AddScoped<IMudValidator<CreateUserRequest>>(provider => provider.GetRequiredService<CreateUserValidator>());

            builder.Services.AddScoped<EditUserValidator>();
            builder.Services.AddScoped<IValidator<EditUserRequest>>(provider => provider.GetRequiredService<EditUserValidator>());
            builder.Services.AddScoped<IMudValidator<EditUserRequest>>(provider => provider.GetRequiredService<EditUserValidator>());

            builder.Services.AddScoped<IClientMembershipLookup, ClientMembershipLookup>();
            builder.Services.AddScoped<IClientMembershipService, ClientMembershipService>();

            builder.Services.AddScoped<CreateClientMembershipValidator>();
            builder.Services.AddScoped<IValidator<CreateClientMembershipRequest>>(provider =>
                provider.GetRequiredService<CreateClientMembershipValidator>());
            builder.Services.AddScoped<IMudValidator<CreateClientMembershipRequest>>(provider =>
                provider.GetRequiredService<CreateClientMembershipValidator>());

            builder.Services.AddScoped<EditClientMembershipValidator>();
            builder.Services.AddScoped<IValidator<EditClientMembershipRequest>>(provider =>
                provider.GetRequiredService<EditClientMembershipValidator>());
            builder.Services.AddScoped<IMudValidator<EditClientMembershipRequest>>(provider =>
                provider.GetRequiredService<EditClientMembershipValidator>());

            builder.Services.AddScoped<RemoveClientMembershipValidator>();
            builder.Services.AddScoped<IValidator<RemoveClientMembershipRequest>>(provider =>
                provider.GetRequiredService<RemoveClientMembershipValidator>());

            builder.Services.AddScoped<IApplicationRoleLookup, ApplicationRoleLookup>();

            builder.Services.AddTransient<CreateApplicationRoleValidator>();
            builder.Services.AddTransient<IValidator<CreateApplicationRoleRequest>>(provider =>
                provider.GetRequiredService<CreateApplicationRoleValidator>());
            builder.Services.AddTransient<IMudValidator<CreateApplicationRoleRequest>>(provider =>
                provider.GetRequiredService<CreateApplicationRoleValidator>());

            builder.Services.AddTransient<EditApplicationRoleValidator>();
            builder.Services.AddTransient<IValidator<EditApplicationRoleRequest>>(provider =>
                provider.GetRequiredService<EditApplicationRoleValidator>());
            builder.Services.AddTransient<IMudValidator<EditApplicationRoleRequest>>(provider =>
                provider.GetRequiredService<EditApplicationRoleValidator>());

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