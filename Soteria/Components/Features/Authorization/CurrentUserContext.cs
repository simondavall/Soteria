using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Authorization;

namespace Soteria.Components.Features.Authorization;

public interface ICurrentUserContext
{
    Task<bool> IsSoteriaAdministratorAsync(CancellationToken cancellationToken = default);
}

public sealed class CurrentUserContext(
    AuthenticationStateProvider authenticationStateProvider,
    IAuthorizationService authorizationService)
    : ICurrentUserContext
{
    private bool? _isSoteriaAdministrator;

    public async Task<bool> IsSoteriaAdministratorAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (_isSoteriaAdministrator.HasValue)
        {
            return _isSoteriaAdministrator.Value;
        }

        var authenticationState = await authenticationStateProvider.GetAuthenticationStateAsync();

        cancellationToken.ThrowIfCancellationRequested();

        var result =
            await authorizationService.AuthorizeAsync(
                authenticationState.User,
                resource: null,
                SoteriaAuthorizationPolicies.SoteriaAdministrator);

        _isSoteriaAdministrator = result.Succeeded;

        return result.Succeeded;
    }
}