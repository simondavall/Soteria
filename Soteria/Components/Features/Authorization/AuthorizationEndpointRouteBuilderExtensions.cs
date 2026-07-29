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
    private const string ClientMembershipRequiredDescription = "The authenticated user does not have access to the client application.";

    public static IEndpointConventionBuilder MapSoteriaAuthorizationEndpoint(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        return endpoints.MapMethods("/connect/authorize", [HttpMethods.Get, HttpMethods.Post], HandleAuthorizationAsync);
    }

    private static async Task<IResult> HandleAuthorizationAsync(
        HttpContext context,
        IOpenIdAuthorizationContext authorizationContext,
        IOpenIdPrincipalFactory principalFactory,
        IOpenIddictApplicationManager applicationManager)
    {
        var resolution = await authorizationContext.GetAsync(context.RequestAborted);

        if (resolution.Failure == OpenIdAuthorizationResolutionFailure.NotAuthenticated)
        {
            return RedirectToLogin(context);
        }

        if (resolution.Failure == OpenIdAuthorizationResolutionFailure.IdentityUserNotFound)
        {
            await context.SignOutAsync(IdentityConstants.ApplicationScheme);
            context.Response.Redirect("/Account/Login");

            return Results.Empty;
        }

        if (resolution.Failure == OpenIdAuthorizationResolutionFailure.ClientMembershipNotFound)
        {
            return RejectMissingClientMembership();
        }

        ThrowForUnresolvableRequest(resolution);

        var resolvedContext = resolution.Context
                              ?? throw new InvalidOperationException(
                                  "The OpenID authorisation context is unavailable.");

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

        var principal = await principalFactory.CreateAsync(resolvedContext, request.GetScopes(), context.RequestAborted);

        return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static IResult RejectMissingClientMembership()
    {
        var properties =
            new AuthenticationProperties(
                new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] =
                        OpenIddictConstants.Errors.AccessDenied,

                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        ClientMembershipRequiredDescription
                });

        return Results.Forbid(properties, [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
    }

    private static IResult RedirectToLogin(HttpContext context)
    {
        var returnUrl = context.Request.GetEncodedPathAndQuery();
        var loginUrl = QueryHelpers.AddQueryString("/Account/Login", "ReturnUrl", returnUrl);
        context.Response.Redirect(loginUrl);

        return Results.Empty;
    }

    private static void ThrowForUnresolvableRequest(OpenIdAuthorizationResolution resolution)
    {
        switch (resolution.Failure)
        {
            case OpenIdAuthorizationResolutionFailure.None:
                return;

            case OpenIdAuthorizationResolutionFailure.AuthorizationRequestUnavailable:
                throw new InvalidOperationException(
                    "The OpenIddict authorization request is unavailable.");

            case OpenIdAuthorizationResolutionFailure.ClientIdentifierUnavailable:
                throw new InvalidOperationException(
                    "The OpenIddict client identifier is unavailable.");

            case OpenIdAuthorizationResolutionFailure.ClientApplicationNotFound:
                throw new InvalidOperationException(
                    "The OpenIddict client application is unavailable.");

            case OpenIdAuthorizationResolutionFailure.ClientApplicationIdentifierInvalid:
                throw new InvalidOperationException(
                    "The OpenIddict client application identifier is invalid.");

            case OpenIdAuthorizationResolutionFailure.NotAuthenticated:
            case OpenIdAuthorizationResolutionFailure.IdentityUserNotFound:

            case OpenIdAuthorizationResolutionFailure.ClientMembershipNotFound:
                throw new InvalidOperationException(
                    "The OpenID authorisation resolution failure was not handled.");

            default:
                throw new ArgumentOutOfRangeException(nameof(resolution.Failure), resolution.Failure,
                    "The OpenID authorisation resolution failure is unknown.");
        }
    }
}