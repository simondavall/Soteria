using Microsoft.EntityFrameworkCore;
using Soteria.Data;

namespace Soteria.Components.Features.Users;

public sealed class UserService(SoteriaDbContext dbContext)
{
    public async Task<IReadOnlyList<UserSummary>> GetUsersAsync(
        CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;

        return await dbContext.Users
            .AsNoTracking()
            .OrderBy(user => user.UserName)
            .ThenBy(user => user.Id)
            .Select(user => new UserSummary(
                user.Id,
                user.UserName ?? string.Empty,
                user.DisplayName,
                user.Email ?? string.Empty,
                user.EmailConfirmed,
                user.LockoutEnd.HasValue && user.LockoutEnd.Value > now))
            .ToListAsync(cancellationToken);
    }
}

public sealed record UserSummary(
    Guid UserId,
    string UserName,
    string? DisplayName,
    string Email,
    bool EmailConfirmed,
    bool IsLockedOut);