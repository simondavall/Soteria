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

    public async Task<UserDetailsModel?> GetUserAsync(
        Guid userId,
        CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;

        return await dbContext.Users
            .AsNoTracking()
            .Where(user => user.Id == userId)
            .Select(user => new UserDetailsModel(
                user.Id,
                user.UserName ?? string.Empty,
                user.DisplayName,
                user.Email ?? string.Empty,
                user.EmailConfirmed,
                user.LockoutEnd.HasValue && user.LockoutEnd.Value > now,
                user.LockoutEnd))
            .SingleOrDefaultAsync(cancellationToken);
    }
}

public sealed record UserSummary(
    Guid UserId,
    string UserName,
    string? DisplayName,
    string Email,
    bool EmailConfirmed,
    bool IsLockedOut);

public sealed record UserDetailsModel(
    Guid UserId,
    string UserName,
    string? DisplayName,
    string Email,
    bool EmailConfirmed,
    bool IsLockedOut,
    DateTimeOffset? LockoutEnd);