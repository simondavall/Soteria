namespace Soteria.Components.Features.Users;

public sealed class RemoveClientMembershipRequest
{
    public Guid UserId { get; set; }
    public Guid ClientMembershipId { get; set; }
}