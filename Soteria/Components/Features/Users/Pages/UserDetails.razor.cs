using Microsoft.AspNetCore.Components;
using MudBlazor;
using Soteria.Components.Features.Users.Dialogs;

namespace Soteria.Components.Features.Users.Pages;

public partial class UserDetails
{
    [Parameter]
    public Guid UserId { get; set; }

    [Inject]
    private UserService UserService { get; set; } = default!;

    [Inject]
    private IDialogService DialogService { get; set; } = default!;

    [Inject]
    private NavigationManager Navigation { get; set; } = default!;

    private UserDetailsModel? User { get; set; }
    private bool IsLoading { get; set; }

    protected override async Task OnParametersSetAsync()
    {
        await LoadUserAsync();
    }

    private async Task LoadUserAsync()
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

    private async Task EditUserAsync()
    {
        var request = await UserService.GetUserForEditAsync(UserId);
        if (request is null)
        {
            User = null;
            return;
        }

        var parameters = new DialogParameters<EditUserDialog>
        {
            { dialog => dialog.Request, request }
        };

        var options = new DialogOptions
        {
            CloseButton = true,
            MaxWidth = MaxWidth.Medium,
            FullWidth = true,
            BackdropClick = false
        };

        var dialog = await DialogService.ShowAsync<EditUserDialog>("Edit user", parameters, options);
        var result = await dialog.Result;

        if (result is null || result.Canceled || result.Data is not true)
        {
            return;
        }

        await LoadUserAsync();
    }

    private void ReturnToUserList()
    {
        Navigation.NavigateTo("/users");
    }

    private static string FormatLockoutEnd(DateTimeOffset? lockoutEnd)
    {
        return lockoutEnd?.ToLocalTime().ToString("g") ?? "Not locked out";
    }
}