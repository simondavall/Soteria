using Soteria.Data.OpenIddict;

namespace Soteria.Data.Authorization;

public class ApplicationRole
{
    public Guid Id { get; set; }

    public Guid ApplicationId { get; set; }

    public string Name { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string? Description { get; set; }

    public SoteriaApplication Application { get; set; } = null!;

    public ICollection<ClientMembershipApplicationRole> ClientMembershipAssignments { get; set; } = [];
}