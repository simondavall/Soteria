using Soteria.Data.OpenIddict;

namespace Soteria.Data.Authorization;

public class ClientMembership
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    public Guid ApplicationId { get; set; }

    public MembershipLevel MembershipLevel { get; set; }

    public DateTime CreatedUtc { get; set; }

    public ApplicationUser User { get; set; } = null!;

    public SoteriaApplication Application { get; set; } = null!;

    public ICollection<ClientMembershipApplicationRole> ApplicationRoleAssignments { get; set; } = [];
}