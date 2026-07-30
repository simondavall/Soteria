using System.Security.Claims;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace Soteria.Components.Features.OpenIdConnect;

public interface IOpenIdPrincipalFactory
{
    Task<ClaimsPrincipal> CreateAsync(ResolvedOpenIdAuthorizationContext authorizationContext, IEnumerable<string> scopes, 
        CancellationToken cancellationToken = default);
    Task RefreshAsync(ClaimsPrincipal principal, ResolvedOpenIdAuthorizationContext authorizationContext, 
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

        var identity = 
            new ClaimsIdentity(
                authenticationType: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                nameType: OpenIddictConstants.Claims.Name,
                roleType: OpenIddictConstants.Claims.Role);

        var principal = new ClaimsPrincipal(identity);

        AddCurrentClaims(identity, authorizationContext);

        principal.SetScopes(scopes);

        var resources = new List<string>();

        await foreach (var resource in scopeManager.ListResourcesAsync(principal.GetScopes(), cancellationToken))
        {
            resources.Add(resource);
        }

        principal.SetResources(resources);
        SetDestinations(principal);

        return principal;
    }

    public Task RefreshAsync(ClaimsPrincipal principal, ResolvedOpenIdAuthorizationContext authorizationContext, 
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(authorizationContext);

        cancellationToken.ThrowIfCancellationRequested();

        var identity = principal.Identity as ClaimsIdentity
                       ?? throw new InvalidOperationException(
                           "The OpenIddict principal does not contain a claims identity.");

        RemoveClaims(identity, OpenIddictConstants.Claims.Subject);
        RemoveClaims(identity, OpenIddictConstants.Claims.Name);
        RemoveClaims(identity, OpenIddictConstants.Claims.Email);
        RemoveClaims(identity, OpenIddictConstants.Claims.Role);

        AddCurrentClaims(identity, authorizationContext);
        SetDestinations(principal);

        return Task.CompletedTask;
    }

    private static void AddCurrentClaims(ClaimsIdentity identity, ResolvedOpenIdAuthorizationContext authorizationContext)
    {
        var userName = authorizationContext.User.UserName
                       ?? throw new InvalidOperationException(
                           "The authenticated user does not have a user name.");

        var email = authorizationContext.User.Email
                    ?? throw new InvalidOperationException(
                        "The authenticated user does not have an email address.");

        identity.AddClaim(OpenIddictConstants.Claims.Subject, authorizationContext.User.Id.ToString());
        identity.AddClaim(OpenIddictConstants.Claims.Name, userName);
        identity.AddClaim(OpenIddictConstants.Claims.Email, email);

        foreach (var applicationRoleName in authorizationContext.ApplicationRoleNames)
        {
            identity.AddClaim(OpenIddictConstants.Claims.Role, applicationRoleName);
        }
    }

    private static void RemoveClaims(ClaimsIdentity identity, string claimType)
    {
        foreach (var claim in identity.FindAll(claimType).ToList())
        {
            identity.RemoveClaim(claim);
        }
    }

    private static void SetDestinations(ClaimsPrincipal principal)
    {
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
    }
}