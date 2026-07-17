using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Server.AspNetCore;
// ReSharper disable CheckNamespace

namespace Microsoft.AspNetCore.Routing;

internal static class AuthorizationEndpointRouteBuilderExtensions
{
    public static IEndpointConventionBuilder MapSoteriaAuthorizationEndpoint(
        this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        return endpoints.MapMethods(
            "/connect/authorize",
            [HttpMethods.Get, HttpMethods.Post],
            HandleAuthorizationAsync);
    }

    private static async Task<IResult> HandleAuthorizationAsync(
        HttpContext context)
    {
        var authenticationResult =
            await context.AuthenticateAsync(IdentityConstants.ApplicationScheme);

        if (!authenticationResult.Succeeded)
        {
            var properties = new AuthenticationProperties
            {
                RedirectUri = context.Request.GetEncodedPathAndQuery()
            };

            return TypedResults.Challenge(
                properties,
                [IdentityConstants.ApplicationScheme]);
        }

        var request = context.GetOpenIddictServerRequest()
                      ?? throw new InvalidOperationException(
                          "The OpenIddict authorization request is unavailable.");

        await context.SignOutAsync(IdentityConstants.ApplicationScheme);

        return TypedResults.LocalRedirect("/Account/Login");
    }
}