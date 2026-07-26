namespace Soteria.Components.Features.Users;

public sealed record ClientMembershipApplicationRoleItem(
    Guid ApplicationRoleId,
    string Name,
    string DisplayName,
    string? Description);