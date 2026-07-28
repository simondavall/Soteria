using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.EntityFrameworkCore;
using Soteria.Data;
using Soteria.Data.Authorization;

namespace Soteria.Components.Features.Authorization;

public interface ICurrentUserContext
{
    Task<CurrentUserAdministrationScope> GetAdministrationScopeAsync(CancellationToken cancellationToken = default);
    Task<bool> IsSoteriaAdministratorAsync(CancellationToken cancellationToken = default);
    Task<bool> IsClientAdministratorAsync(CancellationToken cancellationToken = default);
    Task<bool> CanAccessAdministrationAsync(CancellationToken cancellationToken = default);
    Task<IReadOnlySet<Guid>> GetAdministeredClientIdsAsync(CancellationToken cancellationToken = default);
}

public sealed record CurrentUserAdministrationScope(bool IsSoteriaAdministrator, IReadOnlySet<Guid> AdministeredClientIds)
{
    public bool IsClientAdministrator => AdministeredClientIds.Count > 0;

    public bool CanAccessAdministration => IsSoteriaAdministrator || IsClientAdministrator;
}

public sealed class CurrentUserContext(
    AuthenticationStateProvider authenticationStateProvider,
    IAuthorizationService authorizationService,
    SoteriaDbContext dbContext)
    : ICurrentUserContext
{
    private CurrentUserAdministrationScope? _administrationScope;

    public async Task<CurrentUserAdministrationScope> GetAdministrationScopeAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (_administrationScope is not null)
        {
            return _administrationScope;
        }

        var authenticationState = await authenticationStateProvider.GetAuthenticationStateAsync();

        cancellationToken.ThrowIfCancellationRequested();

        var principal = authenticationState.User;
        if (principal.Identity?.IsAuthenticated != true)
        {
            _administrationScope =
                new CurrentUserAdministrationScope(
                    IsSoteriaAdministrator: false,
                    AdministeredClientIds: new HashSet<Guid>());

            return _administrationScope;
        }

        var userIdValue = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userIdValue, out var userId))
        {
            _administrationScope =
                new CurrentUserAdministrationScope(
                    IsSoteriaAdministrator: false,
                    AdministeredClientIds: new HashSet<Guid>());

            return _administrationScope;
        }

        var soteriaAdministratorResult =
            await authorizationService.AuthorizeAsync(principal, resource: null, SoteriaAuthorizationPolicies.SoteriaAdministrator);

        cancellationToken.ThrowIfCancellationRequested();

        var administeredClientIds =
            await dbContext.ClientMemberships
                .AsNoTracking()
                .Where(membership => membership.UserId == userId && membership.MembershipLevel == MembershipLevel.Administrator)
                .Select(membership => membership.ApplicationId)
                .ToHashSetAsync(cancellationToken);

        _administrationScope =
            new CurrentUserAdministrationScope(
                soteriaAdministratorResult.Succeeded,
                administeredClientIds);

        return _administrationScope;
    }

    public async Task<bool> IsSoteriaAdministratorAsync(CancellationToken cancellationToken = default)
    {
        var scope = await GetAdministrationScopeAsync(cancellationToken);
        return scope.IsSoteriaAdministrator;
    }

    public async Task<bool> IsClientAdministratorAsync(CancellationToken cancellationToken = default)
    {
        var scope = await GetAdministrationScopeAsync(cancellationToken);
        return scope.IsClientAdministrator;
    }

    public async Task<bool> CanAccessAdministrationAsync(CancellationToken cancellationToken = default)
    {
        var scope = await GetAdministrationScopeAsync(cancellationToken);
        return scope.CanAccessAdministration;
    }

    public async Task<IReadOnlySet<Guid>> GetAdministeredClientIdsAsync(CancellationToken cancellationToken = default)
    {
        var scope = await GetAdministrationScopeAsync(cancellationToken);
        return scope.AdministeredClientIds;
    }
}