using OpenIddict.Abstractions;
using OpenIddict.Server;
using Soteria.Components.Features.OpenIdConnect;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Soteria.Data.OpenIddict;

public sealed class ValidateClientMembership(IOpenIdClientMembershipResolver clientMembershipResolver, IOpenIdPrincipalFactory principalFactory)
    : IOpenIddictServerHandler<HandleTokenRequestContext>
{
    private const string ErrorDescription =
        "The user is no longer authorised to access this client application.";

    public async ValueTask HandleAsync(HandleTokenRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!context.Request.IsAuthorizationCodeGrantType() && !context.Request.IsRefreshTokenGrantType())
        {
            return;
        }

        var principal = context.Principal
                        ?? throw new InvalidOperationException(
                            "The token request principal is unavailable.");

        var subject = principal.GetClaim(OpenIddictConstants.Claims.Subject);
        
        var resolution = await clientMembershipResolver.ResolveAsync(context.Request.ClientId, subject, context.CancellationToken);
        if (!resolution.IsSuccessful || resolution.Context is null)
        {
            context.Reject(error: OpenIddictConstants.Errors.InvalidGrant, description: ErrorDescription);
            return;
        }

        await principalFactory.RefreshAsync(principal, resolution.Context, context.CancellationToken);
    }
}