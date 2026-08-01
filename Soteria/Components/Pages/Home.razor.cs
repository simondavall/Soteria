using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;

namespace Soteria.Components.Pages;

public partial class Home
{
    [Inject]
    private AuthenticationStateProvider AuthenticationStateProvider { get; set; } = default!;
    [Inject]
    private NavigationManager NavigationManager { get; set; } = default!;

    protected override async Task OnInitializedAsync()
    {
        var authenticationState = await AuthenticationStateProvider.GetAuthenticationStateAsync();

        var destination = authenticationState.User.Identity?.IsAuthenticated == true
                ? "/Account/Manage"
                : "/Account/Login";

        NavigationManager.NavigateTo(destination, forceLoad: true);
    }
}