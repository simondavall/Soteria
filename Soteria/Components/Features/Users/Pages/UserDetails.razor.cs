using Microsoft.AspNetCore.Components;

namespace Soteria.Components.Features.Users.Pages;

public partial class UserDetails
{
    [Inject]
    private UserService UserService { get; set; } = default!;
    [Inject]
    private NavigationManager NavigationManager { get; set; } = default!;

    [Parameter]
    public Guid UserId { get; set; }

    private UserDetailsModel? User { get; set; }
    private bool IsLoading { get; set; }

    protected override async Task OnParametersSetAsync()
    {
        IsLoading = true;

        try
        {
            User = await UserService.GetUserAsync(UserId);
        }
        finally
        {
            IsLoading = false;
        }
    }

    private static string FormatLockoutEnd(DateTimeOffset? lockoutEnd)
    {
        return lockoutEnd?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'") ?? string.Empty;
    }

    private void ReturnToUserList()
    {
        NavigationManager.NavigateTo("/users");
    }
}