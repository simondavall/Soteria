using Soteria.Data.Authorization;

namespace Soteria.Components.Features.Users;

public sealed class CreateClientMembershipRequest
{
    public Guid UserId { get; set; }
    public string ClientId { get; set; } = string.Empty;
    public MembershipLevel MembershipLevel { get; set; } = MembershipLevel.User;
}