namespace Soteria.Components.Features.Clients;

public sealed class CreateClientRequest
{
    public string ClientId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string ClientHost { get; set; } = string.Empty;
}
