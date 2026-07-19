using Microsoft.AspNetCore.Components;

namespace Soteria.Components.Features.Clients.Pages;

public partial class ClientDetails
{
    [Parameter]
    public string ClientId { get; set; } = string.Empty;

    [Inject]
    private NavigationManager NavigationManager { get; set; } = default!;

    private void ReturnToClientList()
    {
        NavigationManager.NavigateTo("/clients");
    }
}