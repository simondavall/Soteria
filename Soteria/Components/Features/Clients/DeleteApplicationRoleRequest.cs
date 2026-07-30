namespace Soteria.Components.Features.Clients;

public sealed class DeleteApplicationRoleRequest
{
    public string ClientId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public int AssignmentCount { get; set; }
}