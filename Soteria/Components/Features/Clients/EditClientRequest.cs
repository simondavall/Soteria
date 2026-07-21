namespace Soteria.Components.Features.Clients;

public sealed class EditClientRequest
{
    public string ClientId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string ClientHost { get; set; } = string.Empty;

    public string RedirectUri =>
        BuildRedirectUri("/signin-oidc");

    public string PostLogoutRedirectUri =>
        BuildRedirectUri("/signout-callback-oidc");

    private string BuildRedirectUri(string path)
    {
        return string.IsNullOrWhiteSpace(ClientHost)
            ? string.Empty
            : $"{ClientHost.Trim().TrimEnd('/')}{path}";
    }
}