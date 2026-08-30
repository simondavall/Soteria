using Microsoft.AspNetCore.Authorization;
using Soteria.Components.Features.Shared;
using Soteria.Data.Authorization;

namespace Soteria.Components.Features.Authorization;

internal static class SoteriaAuthorizationServiceCollectionExtensions
{
    public static IServiceCollection AddSoteriaAuthorization(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAuthorization(options =>
        {
            options.AddPolicy(
                SoteriaAuthorizationPolicies.SoteriaAdministrator,
                policy =>
                {
                    policy.RequireAuthenticatedUser();
                    policy.AddRequirements(new SoteriaAdminRequirement());
                });

            options.AddPolicy(
                SoteriaAuthorizationPolicies.Administration,
                policy =>
                {
                    policy.RequireAuthenticatedUser();
                    policy.AddRequirements(new AdministrationRequirement());
                });
        });

        services.AddHttpContextAccessor();

        services.AddScoped<IAuthorizationHandler, SoteriaAdminAuthorizationHandler>();
        services.AddScoped<IAuthorizationHandler, AdministrationAuthorizationHandler>();
        services.AddScoped<ICurrentUserContext, CurrentUserContext>();
        
        services.AddSingleton<SoteriaAdministratorInitializer>();
        
        return services;
    }
}