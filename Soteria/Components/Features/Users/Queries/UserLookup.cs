using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Soteria.Data;
using Soteria.Data.Authorization;

namespace Soteria.Components.Features.Users.Queries;

public interface IUserLookup
{
    Task<bool> EmailExistsAsync(string email, CancellationToken cancellationToken = default);
    Task<bool> HasSoteriaAdministratorAssignmentAsync(Guid userId, CancellationToken cancellationToken = default);
    Task<bool> AnotherSoteriaAdministratorExistsAsync(Guid excludedUserId, CancellationToken cancellationToken = default);

    Task<ClientMembershipValidationState?> GetClientMembershipValidationStateAsync(Guid userId, Guid clientMembershipId,
        CancellationToken cancellationToken = default);

    Task<bool> AnotherClientAdministratorExistsAsync(Guid applicationId, Guid excludedClientMembershipId,
        CancellationToken cancellationToken = default);
}

public sealed class UserLookup(UserManager<ApplicationUser> userManager, SoteriaDbContext dbContext) : IUserLookup
{
    public async Task<bool> EmailExistsAsync(string email, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var user = await userManager.FindByEmailAsync(email.Trim());
        return user is not null;
    }

    public Task<bool> HasSoteriaAdministratorAssignmentAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        return dbContext.UserSystemRoles
            .AsNoTracking()
            .AnyAsync(assignment => assignment.UserId == userId && assignment.SystemRoleId == SystemRoleIds.SoteriaAdministrator,
                cancellationToken);
    }

    public Task<bool> AnotherSoteriaAdministratorExistsAsync(Guid excludedUserId, CancellationToken cancellationToken = default)
    {
        return dbContext.UserSystemRoles
            .AsNoTracking()
            .AnyAsync(assignment => assignment.UserId != excludedUserId && assignment.SystemRoleId == SystemRoleIds.SoteriaAdministrator,
                cancellationToken);
    }

    public Task<ClientMembershipValidationState?>
        GetClientMembershipValidationStateAsync(Guid userId, Guid clientMembershipId, CancellationToken cancellationToken = default)
    {
        return dbContext.ClientMemberships
            .AsNoTracking()
            .Where(membership => membership.Id == clientMembershipId && membership.UserId == userId)
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