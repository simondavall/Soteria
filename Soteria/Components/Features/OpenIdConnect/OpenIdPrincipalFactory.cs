using System.Security.Claims;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace Soteria.Components.Features.OpenIdConnect;

public interface IOpenIdPrincipalFactory
{
    Task<ClaimsPrincipal> CreateAsync(ResolvedOpenIdAuthorizationContext authorizationContext, IEnumerable<string> scopes, 
        CancellationToken cancellationToken = default);
}

public sealed class OpenIdPrincipalFactory(IOpenIddictScopeManager scopeManager) : IOpenIdPrincipalFactory
{
    public async Task<ClaimsPrincipal> CreateAsync(ResolvedOpenIdAuthorizationContext authorizationContext, IEnumerable<string> scopes,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authorizationContext);
        ArgumentNullException.ThrowIfNull(scopes);

        cancellationToken.ThrowIfCancellationRequested();

        var userName = authorizationContext.User.UserName
                       ?? throw new InvalidOperationException(
                           "The authenticated user does not have a user name.");

        var email = authorizationContext.User.Email
                    ?? throw new InvalidOperationException(
                        "The authenticated user does not have an email address.");

        var identity =
            new ClaimsIdentity(
                authenticationType: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                nameType: OpenIddictConstants.Claims.Name,
                roleType: OpenIddictConstants.Claims.Role);

        identity.AddClaim(OpenIddictConstants.Claims.Subject, authorizationContext.User.Id.ToString());

        identity.AddClaim(OpenIddictConstants.Claims.Name, userName);

        identity.AddClaim(OpenIddictConstants.Claims.Email, email);

        foreach (var applicationRoleName in authorizationContext.ApplicationRoleNames)
        {
            identity.AddClaim(OpenIddictConstants.Claims.Role, applicationRoleName);
        }

        var principal = new ClaimsPrincipal(identity);
        principal.SetScopes(scopes);

        var resources = new List<string>();
        await foreach (var resource in scopeManager.ListResourcesAsync(principal.GetScopes(), cancellationToken))
        {
            resources.Add(resource);
        }

        principal.SetResources(resources);

        principal.SetDestinations(static claim =>
            claim.Type switch
            {
                OpenIddictConstants.Claims.Subject =>
                [
                    OpenIddictConstants.Destinations.IdentityToken,
                    OpenIddictConstants.Destinations.AccessToken
                ],

                OpenIddictConstants.Claims.Name when claim.Subject?.HasScope(OpenIddictConstants.Scopes.Profile) is true =>
                [
                    OpenIddictConstants.Destinations.IdentityToken,
                    OpenIddictConstants.Destinations.AccessToken
                ],

                OpenIddictConstants.Claims.Email when claim.Subject?.HasScope(OpenIddictConstants.Scopes.Email) is true =>
                [
                    OpenIddictConstants.Destinations.IdentityToken,
                    OpenIddictConstants.Destinations.AccessToken
                ],

                OpenIddictConstants.Claims.Role =>
                [
                    OpenIddictConstants.Destinations.IdentityToken,
                    OpenIddictConstants.Destinations.AccessToken
                ],

                _ => []
            });

        return principal;
    }
}