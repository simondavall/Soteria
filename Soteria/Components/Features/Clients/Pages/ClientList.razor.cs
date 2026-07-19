using Microsoft.AspNetCore.Components;

namespace Soteria.Components.Features.Clients.Pages;

public partial class ClientList
{
    private const string ExampleClientId = "reference-web";

    [Inject]
    private NavigationManager NavigationManager { get; set; } = default!;

    private void OpenExampleClient()
    {
        NavigationManager.NavigateTo($"/clients/{ExampleClientId}");
    }
}