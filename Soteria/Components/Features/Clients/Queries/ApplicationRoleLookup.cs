using Microsoft.EntityFrameworkCore;
using Soteria.Data;

namespace Soteria.Components.Features.Clients.Queries;

public interface IApplicationRoleLookup
{
    Task<bool> NameExistsAsync(string clientId, string name, CancellationToken cancellationToken = default);
}

public sealed class ApplicationRoleLookup(SoteriaDbContext dbContext) : IApplicationRoleLookup
{
    public async Task<bool> NameExistsAsync(string clientId, string name, CancellationToken cancellationToken = default)
    {
        return await dbContext.ApplicationRoles
            .AsNoTracking()
            .AnyAsync(role => role.Application.ClientId == clientId && role.Name == name, cancellationToken);
    }
}