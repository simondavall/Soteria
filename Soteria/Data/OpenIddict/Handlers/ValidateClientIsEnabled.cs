using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Soteria.Data.OpenIddict;

public sealed class ValidateClientIsEnabled :
    IOpenIddictServerHandler<ValidateAuthorizationRequestContext>,
    IOpenIddictServerHandler<ValidateTokenRequestContext>
{
    private const string ErrorDescription = "The client application is disabled.";
    private readonly IOpenIddictApplicationManager _applicationManager;

    public ValidateClientIsEnabled(IOpenIddictApplicationManager applicationManager)
    {
        _applicationManager = applicationManager;
    }

    public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (await IsClientEnabledAsync(context.ClientId))
        {
            return;
        }

        context.Reject(error: OpenIddictConstants.Errors.UnauthorizedClient, description: ErrorDescription);
    }

    public async ValueTask HandleAsync(ValidateTokenRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (await IsClientEnabledAsync(context.ClientId))
        {
            return;
        }

        context.Reject(error: OpenIddictConstants.Errors.InvalidClient, description: ErrorDescription);
    }

    private async ValueTask<bool> IsClientEnabledAsync(string? clientId)
    {
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return true;
        }

        var application = await _applicationManager.FindByClientIdAsync(clientId);

        if (application is null)
        {
            return true;
        }

        if (application is not SoteriaApplication soteriaApplication)
        {
            throw new InvalidOperationException(
                "The OpenIddict application is not using the Soteria application entity.");
        }

        return soteriaApplication.IsEnabled;
    }
}