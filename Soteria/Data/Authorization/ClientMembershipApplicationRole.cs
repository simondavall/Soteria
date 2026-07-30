namespace Soteria.Data.Authorization;

public class ClientMembershipApplicationRole
{
    public Guid ClientMembershipId { get; set; }
    public Guid ApplicationRoleId { get; set; }
    public Guid ApplicationId { get; set; }
    public ClientMembership ClientMembership { get; set; } = null!;
    public ApplicationRole ApplicationRole { get; set; } = null!;
}