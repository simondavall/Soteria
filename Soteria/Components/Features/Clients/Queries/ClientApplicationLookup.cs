using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using Soteria.Data;

namespace Soteria.Components.Features.Clients.Queries;

public interface IClientApplicationLookup
{
    Task<bool> ClientIdExistsAsync(string clientId, CancellationToken cancellationToken = default);
}

public sealed class ClientApplicationLookup(SoteriaDbContext dbContext) : IClientApplicationLookup
{
    public Task<bool> ClientIdExistsAsync(string clientId, CancellationToken cancellationToken = default)
    {
        return dbContext
            .Set<OpenIddictEntityFrameworkCoreApplication<Guid>>()
            .AsNoTracking()
            .AnyAsync(application => application.ClientId == clientId, cancellationToken);
    }
}