using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Soteria.Components.Features.OpenIdConnect;

// ReSharper disable CheckNamespace

namespace Microsoft.AspNetCore.Routing;

internal static class AuthorizationEndpointRouteBuilderExtensions
{
    public static IEndpointConventionBuilder MapSoteriaAuthorizationEndpoint(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        return endpoints.MapMethods("/connect/authorize", [HttpMethods.Get, HttpMethods.Post], HandleAuthorizationAsync);
    }

    private static async Task<IResult> HandleAuthorizationAsync(
        HttpContext context,
        IOpenIdConnectAuthorizationContext authorizationContext,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictScopeManager scopeManager)
    {
        var resolution = await authorizationContext.GetAsync(context.RequestAborted);

        if (resolution.Failure == OpenIdConnectAuthorizationResolutionFailure.NotAuthenticated)
        {
            return RedirectToLogin(context);
        }

        if (resolution.Failure == OpenIdConnectAuthorizationResolutionFailure.IdentityUserNotFound)
        {
            await context.SignOutAsync(IdentityConstants.ApplicationScheme);

            context.Response.Redirect("/Account/Login");
            return Results.Empty;
        }

        ThrowForUnresolvableRequest(resolution);

        var resolvedContext = resolution.Context
                              ?? throw new InvalidOperationException(
                                  "The OpenID Connect authorisation context is unavailable.");

        var request = context.GetOpenIddictServerRequest()
                      ?? throw new InvalidOperationException(
                          "The OpenIddict authorization request is unavailable.");

        var consentType = await applicationManager.GetConsentTypeAsync(resolvedContext.Application, context.RequestAborted);

        // Soteria supports only administrator-managed clients, which use
        // implicit consent. Other consent types require workflows that are
        // not currently supported.
        if (!string.Equals(consentType, OpenIddictConstants.ConsentTypes.Implicit, StringComparison.Ordinal))
        {
            var properties =
                new AuthenticationProperties(
                    new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] =
                            OpenIddictConstants.Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The client application requires user consent."
                    });

            return Results.Forbid(properties, [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
        }

        var userName = GetRequiredUserNameAsync(resolvedContext.User, context.RequestAborted);
        var email = GetRequiredEmailAsync(resolvedContext.User, context.RequestAborted);

        var identity =
            new ClaimsIdentity(
                authenticationType: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                nameType: OpenIddictConstants.Claims.Name,
                roleType: OpenIddictConstants.Claims.Role);

        identity.AddClaim(OpenIddictConstants.Claims.Subject, resolvedContext.User.Id.ToString());
        identity.AddClaim(OpenIddictConstants.Claims.Name, userName);
        identity.AddClaim(OpenIddictConstants.Claims.Email, email);

        foreach (var applicationRoleName in resolvedContext.ApplicationRoleNames)
        {
            identity.AddClaim(OpenIddictConstants.Claims.Role, applicationRoleName);
        }

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

            OpenIddictConstants.Claims.Role =>
            [
                OpenIddictConstants.Destinations.IdentityToken,
                OpenIddictConstants.Destinations.AccessToken
            ],

            _ => []
        });

        return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static IResult RedirectToLogin(HttpContext context)
    {
        var returnUrl = context.Request.GetEncodedPathAndQuery();
        var loginUrl = QueryHelpers.AddQueryString("/Account/Login", "ReturnUrl", returnUrl);
        context.Response.Redirect(loginUrl);

        return Results.Empty;
    }

    private static void ThrowForUnresolvableRequest(OpenIdConnectAuthorizationResolution resolution)
    {
        switch (resolution.Failure)
        {
            case OpenIdConnectAuthorizationResolutionFailure.None:
            case OpenIdConnectAuthorizationResolutionFailure.ClientMembershipNotFound:
                return;

            case OpenIdConnectAuthorizationResolutionFailure.AuthorizationRequestUnavailable:
                throw new InvalidOperationException(
                    "The OpenIddict authorization request is unavailable.");

            case OpenIdConnectAuthorizationResolutionFailure.ClientIdentifierUnavailable:
                throw new InvalidOperationException(
                    "The OpenIddict client identifier is unavailable.");

            case OpenIdConnectAuthorizationResolutionFailure.ClientApplicationNotFound:
                throw new InvalidOperationException(
                    "The OpenIddict client application is unavailable.");

            case OpenIdConnectAuthorizationResolutionFailure.ClientApplicationIdentifierInvalid:
                throw new InvalidOperationException(
                    "The OpenIddict client application identifier is invalid.");

            case OpenIdConnectAuthorizationResolutionFailure.NotAuthenticated:
            case OpenIdConnectAuthorizationResolutionFailure.IdentityUserNotFound:
                throw new InvalidOperationException(
                    "The Identity user resolution failure was not handled.");

            default:
                throw new ArgumentOutOfRangeException(nameof(resolution.Failure), resolution.Failure,
                    "The OpenID Connect authorisation resolution failure is unknown.");
        }
    }

    private static string GetRequiredUserNameAsync(Soteria.Data.ApplicationUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return user.UserName ?? throw new InvalidOperationException("The authenticated user does not have a user name.");
    }

    private static string GetRequiredEmailAsync(Soteria.Data.ApplicationUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return user.Email ?? throw new InvalidOperationException("The authenticated user does not have an email address.");
    }
}