namespace Soteria.Data.Authorization;

public class SystemRole
{
    public Guid Id { get; set; }

    public string Name { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string? Description { get; set; }

    public ICollection<UserSystemRole> UserSystemRoles { get; set; } = [];
}