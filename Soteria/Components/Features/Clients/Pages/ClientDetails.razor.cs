using Microsoft.AspNetCore.Components;
using OpenIddict.Abstractions;

namespace Soteria.Components.Features.Clients.Pages;

public partial class ClientDetails
{
    [Parameter]
    public string ClientId { get; set; } = string.Empty;

    [Inject]
    private ClientService ClientService { get; set; } = default!;

    [Inject]
    private NavigationManager NavigationManager { get; set; } = default!;

    private ClientApplicationDetails? Client { get; set; }

    private bool IsLoading { get; set; }

    protected override async Task OnParametersSetAsync()
    {
        IsLoading = true;

        try
        {
            Client = await ClientService.GetClientAsync(ClientId);
        }
        finally
        {
            IsLoading = false;
        }
    }

    private void ReturnToClientList()
    {
        NavigationManager.NavigateTo("/clients");
    }

    private static string FormatClientType(string value)
    {
        return value switch
        {
            OpenIddictConstants.ClientTypes.Confidential => "Confidential",
            OpenIddictConstants.ClientTypes.Public => "Public",
            _ => FormatValue(value)
        };
    }

    private static string FormatConsentType(string value)
    {
        return value switch
        {
            OpenIddictConstants.ConsentTypes.Explicit => "Explicit",
            OpenIddictConstants.ConsentTypes.External => "External",
            OpenIddictConstants.ConsentTypes.Implicit => "Implicit",
            OpenIddictConstants.ConsentTypes.Systematic => "Systematic",
            _ => FormatValue(value)
        };
    }

    private static string FormatValue(string value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? "Not configured"
            : value;
    }
}