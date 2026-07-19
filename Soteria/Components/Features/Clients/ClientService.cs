using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using Soteria.Data;

namespace Soteria.Components.Features.Clients;

public sealed class ClientService
{
    private readonly SoteriaDbContext _dbContext;

    public ClientService(SoteriaDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<IReadOnlyList<ClientSummary>> GetClientsAsync(CancellationToken cancellationToken = default)
    {
        return await _dbContext.Set<OpenIddictEntityFrameworkCoreApplication<Guid>>()
            .OrderBy(a => a.DisplayName)
            .Select(a => new ClientSummary(
                a.ClientId!,
                a.DisplayName ?? a.ClientId!,
                a.ClientType ?? string.Empty,
                a.ConsentType ?? string.Empty))
            .ToListAsync(cancellationToken);
    }
}

public sealed record ClientSummary(
    string ClientId,
    string DisplayName,
    string ClientType,
    string ConsentType);