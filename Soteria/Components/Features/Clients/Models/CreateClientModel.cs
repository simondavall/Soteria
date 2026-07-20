namespace Soteria.Components.Features.Clients.Models;

public sealed class CreateClientModel
{
    public string ClientId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string ClientHost { get; set; } = string.Empty;
}