using Microsoft.AspNetCore.Identity;
using Soteria.Data.Authorization;

namespace Soteria.Data;

public class ApplicationUser : IdentityUser<Guid>
{
    public string? DisplayName { get; set; } = string.Empty;
    
    public bool RequiresPasswordChange { get; set; } = false;

    public ICollection<UserSystemRole> UserSystemRoles { get; set; } = [];

    public ICollection<ClientMembership> ClientMemberships { get; set; } = [];
}