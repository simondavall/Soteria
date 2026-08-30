using OpenIddict.Abstractions;
using OpenIddict.Server;
using Soteria.Data;
using Soteria.Data.OpenIddict;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Soteria.Components.Features.OpenIdConnect;

internal static class SoteriaOpenIddictServiceCollectionExtensions
{
    public static IServiceCollection AddSoteriaOpenIddict(this IServiceCollection services, 
        IWebHostEnvironment environment, 
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(configuration);

        var tokenConfiguration = configuration.GetRequiredSection("OpenIddict:Tokens");
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

        services.AddScoped<IOpenIdClientMembershipResolver, OpenIdClientMembershipResolver>();
        services.AddScoped<IOpenIdAuthorizationContext, OpenIdAuthorizationContext>();
        services.AddScoped<IOpenIdPrincipalFactory, OpenIdPrincipalFactory>();

        services.AddOpenIddict()
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

                options.AddEventHandler<ValidateAuthorizationRequestContext>(
                    builder => builder
                        .UseScopedHandler<ValidateClientIsEnabled>()
                        .SetOrder(int.MaxValue - 100_000));

                options.AddEventHandler<ValidateTokenRequestContext>(
                    builder => builder
                        .UseScopedHandler<ValidateClientIsEnabled>()
                        .SetOrder(int.MaxValue - 100_000));

                options.AddEventHandler<HandleTokenRequestContext>(
                    builder => builder
                        .UseScopedHandler<ValidateClientMembership>()
                        .SetOrder(
                            OpenIddictServerHandlers.Exchange
                                .AttachPrincipal
                                .Descriptor
                                .Order + 1_000));

                options.UseAspNetCore()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableEndSessionEndpointPassthrough()
                    .EnableStatusCodePagesIntegration();

                options.AddSoteriaCredentials(environment, configuration);
            });

        services.AddScoped<OpenIddictInitializer>();

        return services;
    }
}