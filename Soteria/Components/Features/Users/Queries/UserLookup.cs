using Microsoft.AspNetCore.Identity;
using Soteria.Data;

namespace Soteria.Components.Features.Users.Queries;

public interface IUserLookup
{
    Task<bool> EmailExistsAsync(string email, CancellationToken cancellationToken = default);
}

public sealed class UserLookup(UserManager<ApplicationUser> userManager) : IUserLookup
{
    public async Task<bool> EmailExistsAsync(string email, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        
        var user = await userManager.FindByEmailAsync(email.Trim());
        return user is not null;
    }
}