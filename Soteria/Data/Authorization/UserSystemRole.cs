namespace Soteria.Data.Authorization;

public class UserSystemRole
{
    public Guid UserId { get; set; }

    public Guid SystemRoleId { get; set; }

    public ApplicationUser User { get; set; } = null!;

    public SystemRole SystemRole { get; set; } = null!;
}