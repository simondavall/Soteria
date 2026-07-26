using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using Soteria.Data;
using Soteria.Data.OpenIddict;

namespace Soteria.Components.Features.Clients.Queries;

public interface IClientApplicationLookup
{
    Task<bool> ClientIdExistsAsync(string clientId, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ClientApplicationLookupItem>> GetAvailableClientsAsync(Guid userId, CancellationToken cancellationToken = default);
}

public sealed class ClientApplicationLookup(SoteriaDbContext dbContext) : IClientApplicationLookup
{
    public Task<bool> ClientIdExistsAsync(string clientId, CancellationToken cancellationToken = default)
    {
        return dbContext
            .Set<OpenIddictEntityFrameworkCoreApplication<Guid>>()
            .AsNoTracking()
            .AnyAsync(
                application => application.ClientId == clientId,
                cancellationToken);
    }

    public async Task<IReadOnlyList<ClientApplicationLookupItem>> GetAvailableClientsAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        return await dbContext
            .Set<SoteriaApplication>()
            .AsNoTracking()
            .Where(application =>
                application.ClientId != null
                && application.ClientMemberships.All(membership => membership.UserId != userId))
            .OrderBy(application =>
                application.DisplayName ?? application.ClientId)
            .ThenBy(application => application.ClientId)
            .Select(application => new ClientApplicationLookupItem(
                application.ClientId!,
                application.DisplayName ?? application.ClientId!))
            .ToListAsync(cancellationToken);
    }
}

public sealed record ClientApplicationLookupItem(
    string ClientId,
    string DisplayName);