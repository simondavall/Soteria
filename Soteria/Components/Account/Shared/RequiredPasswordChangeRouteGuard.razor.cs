using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Soteria.Components.Account.Pages.Manage;
using Soteria.Data;

namespace Soteria.Components.Account.Shared;

public partial class RequiredPasswordChangeRouteGuard
{
    private bool _canRender;

    [Inject] 
    private AuthenticationStateProvider AuthenticationStateProvider { get; set; } = null!;
    [Inject] 
    private UserManager<ApplicationUser> UserManager { get; set; } = null!;
    [Inject] 
    private NavigationManager NavigationManager { get; set; } = null!;

    [Parameter, EditorRequired]
    public Microsoft.AspNetCore.Components.RouteData RouteData { get; set; } = null!;
    [Parameter, EditorRequired] 
    public RenderFragment ChildContent { get; set; } = null!;

    protected override async Task OnParametersSetAsync()
    {
        _canRender = false;

        var authenticationState = await AuthenticationStateProvider.GetAuthenticationStateAsync();
        if (authenticationState.User.Identity?.IsAuthenticated != true)
        {
            _canRender = true;
            return;
        }

        if (RouteData.PageType == typeof(ChangePassword))
        {
            _canRender = true;
            return;
        }

        var user = await UserManager.GetUserAsync(authenticationState.User);
        if (user?.RequiresPasswordChange != true)
        {
            _canRender = true;
            return;
        }

        var returnUrl = NavigationManager.ToBaseRelativePath(NavigationManager.Uri);

        var changePasswordUrl = 
            NavigationManager.GetUriWithQueryParameters(
                "Account/Manage/ChangePassword", 
                new Dictionary<string, object?>
                {
                    ["ReturnUrl"] = returnUrl
                });

        NavigationManager.NavigateTo(changePasswordUrl, forceLoad: true);
    }
}