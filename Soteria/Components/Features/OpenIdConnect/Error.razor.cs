using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Components;
using OpenIddict.Abstractions;

namespace Soteria.Components.Features.OpenIdConnect;

public partial class Error
{
    private const string DisabledClientDescription = "The client application is disabled.";

    [CascadingParameter]
    private HttpContext? HttpContext { get; set; }

    [Inject]
    private IWebHostEnvironment Environment { get; set; } = null!;

    private string? ErrorCode { get; set; }

    private string? ErrorDescription { get; set; }

    private string? ErrorUri { get; set; }

    private OpenIdConnectErrorViewModel Model { get; set; } = CreateFallbackModel();

    private bool ShowTechnicalDetails =>
        Environment.IsDevelopment()
        && (!string.IsNullOrWhiteSpace(ErrorCode)
            || !string.IsNullOrWhiteSpace(ErrorDescription)
            || !string.IsNullOrWhiteSpace(ErrorUri));

    protected override void OnParametersSet()
    {
        var response = HttpContext?.GetOpenIddictServerResponse();

        ErrorCode = response?.Error;
        ErrorDescription = response?.ErrorDescription;
        ErrorUri = response?.ErrorUri;

        Model = CreateModel(ErrorCode, ErrorDescription);
    }

    private static OpenIdConnectErrorViewModel CreateModel(string? error, string? description)
    {
        return (error, description) switch
        {
            (OpenIddictConstants.Errors.UnauthorizedClient, DisabledClientDescription) =>
                new OpenIdConnectErrorViewModel(
                    "Application unavailable",
                    "This application has been disabled by an administrator."),

            (OpenIddictConstants.Errors.UnauthorizedClient, _) =>
                new OpenIdConnectErrorViewModel(
                    "Application unavailable",
                    "This application is not permitted to start the requested authentication flow."),

            (OpenIddictConstants.Errors.InvalidClient, _) =>
                new OpenIdConnectErrorViewModel(
                    "Application could not be verified",
                    "Soteria could not verify the application requesting access."),

            (OpenIddictConstants.Errors.InvalidRequest, _) =>
                new OpenIdConnectErrorViewModel(
                    "Invalid authentication request",
                    "The authentication request could not be processed."),

            (OpenIddictConstants.Errors.InvalidScope, _) =>
                new OpenIdConnectErrorViewModel(
                    "Unsupported access request",
                    "The application requested access that is not available."),

            (OpenIddictConstants.Errors.AccessDenied, _) =>
                new OpenIdConnectErrorViewModel(
                    "Access denied",
                    "The authentication request was not approved."),

            (OpenIddictConstants.Errors.ConsentRequired, _) =>
                new OpenIdConnectErrorViewModel(
                    "Consent required",
                    "The application requires consent through a workflow that is not currently available."),

            _ => CreateFallbackModel()
        };
    }

    private static OpenIdConnectErrorViewModel CreateFallbackModel()
    {
        return new OpenIdConnectErrorViewModel(
            "Authentication could not be completed",
            "Soteria could not complete the authentication request. Please return to the application and try again.");
    }

    private static string DisplayValue(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? "Not provided" : value;
    }

    private sealed record OpenIdConnectErrorViewModel(string Title, string Message);
}