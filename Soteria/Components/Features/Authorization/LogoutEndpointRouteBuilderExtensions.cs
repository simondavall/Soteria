using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Server.AspNetCore;

// ReSharper disable CheckNamespace

namespace Microsoft.AspNetCore.Routing;

internal static class LogoutEndpointRouteBuilderExtensions
{
    public static IEndpointConventionBuilder MapSoteriaLogoutEndpoint(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        return endpoints.MapMethods("/connect/logout", [HttpMethods.Get, HttpMethods.Post], HandleLogoutAsync);
    }
    
    private static async Task HandleLogoutAsync(HttpContext context)
    {
        await context.SignOutAsync(IdentityConstants.ApplicationScheme);

        await context.SignOutAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            new AuthenticationProperties
            {
                RedirectUri = "/"
            });
    }
}