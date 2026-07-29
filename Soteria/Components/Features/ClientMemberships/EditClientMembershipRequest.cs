using Soteria.Data.Authorization;

namespace Soteria.Components.Features.ClientMemberships;

public sealed class EditClientMembershipRequest
{
    public Guid UserId { get; set; }
    public Guid ClientMembershipId { get; set; }
    public string ClientId { get; set; } = string.Empty;
    public string ApplicationName { get; set; } = string.Empty;
    public MembershipLevel MembershipLevel { get; set; }
    public IReadOnlyList<Guid> AvailableApplicationRoleIds { get; set; } = [];
    public HashSet<Guid> SelectedApplicationRoleIds { get; set; } = [];
}