using Microsoft.EntityFrameworkCore;
using Soteria.Data;
using Soteria.Data.Authorization;

namespace Soteria.Components.Features.ClientMemberships.Queries;

public interface IClientMembershipLookup
{
    Task<ClientMembershipValidationState?> GetValidationStateAsync(Guid userId, Guid clientMembershipId,
        CancellationToken cancellationToken = default);

    Task<bool> AnotherClientAdministratorExistsAsync(Guid applicationId, Guid excludedClientMembershipId,
        CancellationToken cancellationToken = default);
}

public sealed class ClientMembershipLookup(SoteriaDbContext dbContext) : IClientMembershipLookup
{
    public Task<ClientMembershipValidationState?> GetValidationStateAsync(Guid userId, Guid clientMembershipId,
        CancellationToken cancellationToken = default)
    {
        return dbContext.ClientMemberships
            .AsNoTracking()
            .Where(membership =>
                membership.Id == clientMembershipId &&
                membership.UserId == userId)
            .Select(membership =>
                new ClientMembershipValidationState(
                    membership.ApplicationId,
                    membership.MembershipLevel))
            .SingleOrDefaultAsync(cancellationToken);
    }

    public Task<bool> AnotherClientAdministratorExistsAsync(Guid applicationId, Guid excludedClientMembershipId,
        CancellationToken cancellationToken = default)
    {
        return dbContext.ClientMemberships
            .AsNoTracking()
            .AnyAsync(membership =>
                    membership.ApplicationId == applicationId &&
                    membership.Id != excludedClientMembershipId &&
                    membership.MembershipLevel == MembershipLevel.Administrator,
                cancellationToken);
    }
}

public sealed record ClientMembershipValidationState(
    Guid ApplicationId,
    MembershipLevel MembershipLevel);