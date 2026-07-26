namespace Soteria.Components.Features.Clients;

public sealed class RemoveApplicationRoleRequest
{
    public string ClientId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public int AssignmentCount { get; set; }
}