using Soteria.Data.Authorization;

namespace Soteria.Components.Features.ClientMemberships;

public sealed record ClientMembershipDetailsModel(
    Guid ClientMembershipId,
    string ApplicationName,
    string MembershipLevel,
    IReadOnlyList<string> ApplicationRoles);

public sealed record ClientMembershipApplicationRoleItem(
    Guid ApplicationRoleId,
    string Name,
    string DisplayName,
    string? Description);

internal sealed record ClientMembershipQueryResult(
    Guid ClientMembershipId,
    string ApplicationName,
    MembershipLevel MembershipLevel);

internal sealed record ClientMembershipRoleQueryResult(
    Guid ClientMembershipId,
    string ApplicationRoleName);