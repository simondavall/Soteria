namespace Soteria.Components.Features.Users;

public sealed class EditUserRequest
{
    public Guid UserId { get; init; }
    public string UserName { get; init; } = string.Empty;
    public string? DisplayName { get; init; }
    public string Email { get; init; } = string.Empty;
    public bool EmailConfirmed { get; init; }
    public bool IsLockedOut { get; set; }
    public DateTimeOffset? LockoutEnd { get; set; }
    public bool UnlockRequested { get; set; }
    public bool IsSoteriaAdministrator { get; set; }
}