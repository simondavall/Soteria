using Microsoft.AspNetCore.Components;
using MudBlazor;
using OpenIddict.Abstractions;
using Soteria.Components.Features.Clients.Dialogs;

namespace Soteria.Components.Features.Clients.Pages;

public partial class ClientList
{
    [Inject]
    private ClientService ClientService { get; set; } = default!;
    [Inject]
    private IDialogService DialogService { get; set; } = default!;
    [Inject]
    private ISnackbar Snackbar { get; set; } = default!;
    [Inject]
    private NavigationManager Navigation { get; set; } = default!;

    protected IReadOnlyList<ClientSummary> Clients = [];

    protected override async Task OnInitializedAsync()
    {
        await LoadClientsAsync();
    }

    private async Task CreateClientAsync()
    {
        var options = new DialogOptions
        {
            CloseButton = true,
            FullWidth = true,
            MaxWidth = MaxWidth.Small,
            BackdropClick = false
        };

        var dialog = await DialogService.ShowAsync<CreateClientDialog>("Create client application", options);

        var result = await dialog.Result;
        if (result is null || result.Canceled)
        {
            return;
        }

        await LoadClientsAsync();

        Snackbar.Add("Client application created.", Severity.Success);
    }

    private async Task LoadClientsAsync()
    {
        Clients = await ClientService.GetClientsAsync();
    }

    private void SelectClient(TableRowClickEventArgs<ClientSummary> args)
    {
        Navigation.NavigateTo($"/clients/{args.Item?.ClientId ?? string.Empty}");
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