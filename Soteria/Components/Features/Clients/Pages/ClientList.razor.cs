using Microsoft.AspNetCore.Components;
using OpenIddict.Abstractions;

namespace Soteria.Components.Features.Clients.Pages;

public partial class ClientList
{
    [Inject]
    private ClientService ClientService { get; set; } = default!;

    [Inject]
    private NavigationManager NavigationManager { get; set; } = default!;

    private IReadOnlyList<ClientSummary> Clients = [];

    protected override async Task OnInitializedAsync()
    {
        Clients = await ClientService.GetClientsAsync();
    }

    private void OpenClient(ClientSummary client)
    {
        NavigationManager.NavigateTo($"/clients/{client.ClientId}");
    }

    private static string FormatClientType(string value)
    {
        return value switch
        {
            OpenIddictConstants.ClientTypes.Confidential => "Confidential",
            OpenIddictConstants.ClientTypes.Public => "Public",
            _ => value
        };
    }

    private static string FormatConsentType(string value)
    {
        return value switch
        {
            OpenIddictConstants.ConsentTypes.Implicit => "Implicit",
            OpenIddictConstants.ConsentTypes.Explicit => "Explicit",
            OpenIddictConstants.ConsentTypes.External => "External",
            OpenIddictConstants.ConsentTypes.Systematic => "Systematic",
            _ => value
        };
    }
}