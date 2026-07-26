using Microsoft.AspNetCore.Components;
using MudBlazor;
using OpenIddict.Abstractions;
using Soteria.Components.Features.Clients.Dialogs;

namespace Soteria.Components.Features.Clients.Pages;

public partial class ClientDetails
{
    [Inject]
    private ClientService ClientService { get; set; } = default!;
    [Inject]
    private NavigationManager NavigationManager { get; set; } = default!;
    [Inject]
    private IDialogService DialogService { get; set; } = default!;
    
    [Parameter]
    public string ClientId { get; set; } = string.Empty;
    
    private ClientApplicationDetails? Client { get; set; }
    private IReadOnlyList<ApplicationRoleSummary> ApplicationRoles { get; set; } = [];
    private bool IsLoading { get; set; }

    protected override async Task OnParametersSetAsync()
    {
        await LoadClientAsync();
    }

    private async Task LoadClientAsync()
    {
        IsLoading = true;

        try
        {
            Client = await ClientService.GetClientAsync(ClientId);
            ApplicationRoles = Client is null ? [] : await ClientService.GetApplicationRolesAsync(ClientId);
        }
        finally
        {
            IsLoading = false;
        }
    }
    
    private async Task EditClientAsync()
    {
        var request = await ClientService.GetClientForEditAsync(ClientId);
        if (request is null)
        {
            Client = null;
            return;
        }

        var parameters = new DialogParameters
        {
            [nameof(EditClientDialog.Request)] = request
        };

        var options = new DialogOptions
        {
            MaxWidth = MaxWidth.Small,
            FullWidth = true,
            CloseButton = true,
            CloseOnEscapeKey = true
        };

        var dialog = await DialogService.ShowAsync<EditClientDialog>("Edit client application", parameters, options);
        var result = await dialog.Result;
        if (result is null || result.Canceled)
        {
            return;
        }

        await LoadClientAsync();
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
        return string.IsNullOrWhiteSpace(value) ? "Not configured" : value;
    }
}