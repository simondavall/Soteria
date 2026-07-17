using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Soteria.Data;
// ReSharper disable CheckNamespace

namespace Microsoft.AspNetCore.Routing;

internal static class AuthorizationEndpointRouteBuilderExtensions
{
    public static IEndpointConventionBuilder MapSoteriaAuthorizationEndpoint(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        return endpoints.MapMethods(
            "/connect/authorize",
            [HttpMethods.Get, HttpMethods.Post],
            HandleAuthorizationAsync);
    }

    private static async Task<IResult> HandleAuthorizationAsync(
        HttpContext context,
        UserManager<ApplicationUser> userManager,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictScopeManager scopeManager)
    {
        var authenticationResult = await context.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        if (!authenticationResult.Succeeded)
        {
            var returnUrl = context.Request.GetEncodedPathAndQuery();
            var loginUrl = QueryHelpers.AddQueryString("/Account/Login", "ReturnUrl", returnUrl);
            context.Response.Redirect(loginUrl);
            return Results.Empty;
        }

        var request = context.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException(
                "The OpenIddict authorization request is unavailable.");

        var user = await userManager.GetUserAsync(authenticationResult.Principal);
        if (user is null)
        {
            await context.SignOutAsync(IdentityConstants.ApplicationScheme);
            context.Response.Redirect("/Account/Login");
            return Results.Empty;
        }

        var application = await applicationManager.FindByClientIdAsync(
            request.ClientId
            ?? throw new InvalidOperationException(
                "The OpenIddict client identifier is unavailable."),
            context.RequestAborted);

        if (application is null)
        {
            throw new InvalidOperationException("The OpenIddict client application is unavailable.");
        }

        var consentType = await applicationManager.GetConsentTypeAsync(application, context.RequestAborted);
        if (!string.Equals(consentType, OpenIddictConstants.ConsentTypes.Implicit, StringComparison.Ordinal))
        {
            var properties = new AuthenticationProperties(
                new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] =
                        OpenIddictConstants.Errors.ConsentRequired,

                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The client application requires user consent."
                });

            return Results.Forbid(properties, [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
        }

        var userName = await userManager.GetUserNameAsync(user)
            ?? throw new InvalidOperationException("The authenticated user does not have a user name.");

        var email = await userManager.GetEmailAsync(user)
            ?? throw new InvalidOperationException("The authenticated user does not have an email address.");

        var identity = new ClaimsIdentity(
            authenticationType: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            nameType: OpenIddictConstants.Claims.Name,
            roleType: OpenIddictConstants.Claims.Role);

        identity.AddClaim(OpenIddictConstants.Claims.Subject, user.Id.ToString());
        identity.AddClaim(OpenIddictConstants.Claims.Name, userName);
        identity.AddClaim(OpenIddictConstants.Claims.Email, email);

        var principal = new ClaimsPrincipal(identity);
        principal.SetScopes(request.GetScopes());

        var resources = new List<string>();
        await foreach (var resource in scopeManager.ListResourcesAsync(principal.GetScopes(), context.RequestAborted))
        {
            resources.Add(resource);
        }

        principal.SetResources(resources);

        principal.SetDestinations(static claim => claim.Type switch
        {
            OpenIddictConstants.Claims.Subject =>
            [
                OpenIddictConstants.Destinations.IdentityToken,
                OpenIddictConstants.Destinations.AccessToken
            ],

            OpenIddictConstants.Claims.Name
                when claim.Subject?.HasScope(OpenIddictConstants.Scopes.Profile) is true =>
                [
                    OpenIddictConstants.Destinations.IdentityToken,
                    OpenIddictConstants.Destinations.AccessToken
                ],

            OpenIddictConstants.Claims.Email
                when claim.Subject?.HasScope(OpenIddictConstants.Scopes.Email) is true =>
                [
                    OpenIddictConstants.Destinations.IdentityToken,
                    OpenIddictConstants.Destinations.AccessToken
                ],

            _ => []
        });

        return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}