namespace Soteria.Components.Features.OpenIdConnect;

public sealed class OpenIdConnectErrorViewModel
{
    public required string Title { get; init; }

    public required string Message { get; init; }

    public string? ErrorCode { get; init; }

    public string? ErrorDescription { get; init; }
}