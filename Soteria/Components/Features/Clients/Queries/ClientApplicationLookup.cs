using Microsoft.EntityFrameworkCore;
using Soteria.Components.Features.Authorization;
using Soteria.Data;
using Soteria.Data.OpenIddict;

namespace Soteria.Components.Features.Clients.Queries;

public interface IClientApplicationLookup
{
    Task<bool> ClientIdExistsAsync(
        string clientId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ClientApplicationLookupItem>>
        GetAvailableClientsAsync(
            Guid userId,
            CancellationToken cancellationToken = default);
}

public sealed class ClientApplicationLookup(
    SoteriaDbContext dbContext,
    ICurrentUserContext currentUserContext)
    : IClientApplicationLookup
{
    public Task<bool> ClientIdExistsAsync(
        string clientId,
        CancellationToken cancellationToken = default)
    {
        return dbContext
            .Set<SoteriaApplication>()
            .AsNoTracking()
            .AnyAsync(
                application => application.ClientId == clientId,
                cancellationToken);
    }

    public async Task<IReadOnlyList<ClientApplicationLookupItem>>
        GetAvailableClientsAsync(
            Guid userId,
            CancellationToken cancellationToken = default)
    {
        var administrationScope =
            await currentUserContext.GetAdministrationScopeAsync(
                cancellationToken);

        if (!administrationScope.IsSoteriaAdministrator
            && administrationScope.AdministeredClientIds.Count == 0)
        {
            return [];
        }

        var query =
            dbContext
                .Set<SoteriaApplication>()
                .AsNoTracking()
                .Where(
                    application =>
                        application.ClientId != null
                        && application.ClientMemberships.All(
                            membership => membership.UserId != userId));

        if (!administrationScope.IsSoteriaAdministrator)
        {
            query =
                query.Where(
                    application =>
                        administrationScope.AdministeredClientIds.Contains(
                            application.Id));
        }

        return await query
            .OrderBy(
                application =>
                    application.DisplayName ?? application.ClientId)
            .ThenBy(application => application.ClientId)
            .Select(
                application =>
                    new ClientApplicationLookupItem(
                        application.ClientId!,
                        application.DisplayName
                        ?? application.ClientId!))
            .ToListAsync(cancellationToken);
    }
}

public sealed record ClientApplicationLookupItem(
    string ClientId,
    string DisplayName);