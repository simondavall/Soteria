using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
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

    private static async Task HandleAuthorizationAsync(HttpContext context)
    {
        var authenticationResult = await context.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        if (!authenticationResult.Succeeded)
        {
            var returnUrl = context.Request.GetEncodedPathAndQuery();
            var loginUrl = QueryHelpers.AddQueryString("/Account/Login", "ReturnUrl", returnUrl);
            context.Response.Redirect(loginUrl);
            return;
        }

        var request = context.GetOpenIddictServerRequest()
                      ?? throw new InvalidOperationException(
                          "The OpenIddict authorization request is unavailable.");

        await context.SignOutAsync(IdentityConstants.ApplicationScheme);
        context.Response.Redirect("/Account/Login");
    }
}