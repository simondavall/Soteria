namespace Soteria.Components.Features.ClientMemberships;

public sealed class RemoveClientMembershipRequest
{
    public Guid UserId { get; set; }
    public Guid ClientMembershipId { get; set; }
}