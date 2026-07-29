using Microsoft.AspNetCore.Components;
using MudBlazor;
using Soteria.Components.Features.ClientMemberships;
using Soteria.Components.Features.ClientMemberships.Dialogs;
using Soteria.Components.Features.Users.Dialogs;

namespace Soteria.Components.Features.Users.Pages;

public partial class UserDetails
{
    [Parameter]
    public Guid UserId { get; set; }

    [Inject]
    private UserService UserService { get; set; } = default!;
    [Inject]
    private IClientMembershipService ClientMembershipService { get; set; } = default!;
    [Inject]
    private IDialogService DialogService { get; set; } = default!;
    [Inject]
    private NavigationManager Navigation { get; set; } = default!;
    
    private UserDetailsModel? User { get; set; }
    private IReadOnlyList<ClientMembershipDetailsModel> ClientMemberships { get; set; } = [];
    private bool IsLoading { get; set; }


    protected override async Task OnParametersSetAsync()
    {
        await LoadUserAsync();
    }

    private async Task LoadUserAsync()
    {
        IsLoading = true;
        ClientMemberships = [];

        try
        {
            User = await UserService.GetUserAsync(UserId);
            if (User is not null)
            {
                ClientMemberships = await ClientMembershipService.GetForUserAsync(UserId);
            }
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
            ClientMemberships = [];
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

    private Task AssignClientAsync()
    {
        return OpenClientMembershipDialogAsync();
    }
    
    private Task EditClientMembershipAsync(ClientMembershipDetailsModel membership)
    {
        return OpenClientMembershipDialogAsync(membership.ClientMembershipId);
    }

    private async Task OpenClientMembershipDialogAsync(Guid? clientMembershipId = null)
    {
        var parameters = new DialogParameters<ClientMembershipDialog>
        {
            { dialog => dialog.UserId, UserId }
        };

        if (clientMembershipId.HasValue)
        {
            parameters.Add(dialog => dialog.ClientMembershipId, clientMembershipId.Value);
        }

        var options = new DialogOptions
        {
            CloseButton = true,
            MaxWidth = MaxWidth.Small,
            FullWidth = true,
            BackdropClick = false
        };

        var title = clientMembershipId.HasValue ? "Edit client assignment" : "Assign client";

        var dialog = await DialogService.ShowAsync<ClientMembershipDialog>(title, parameters, options);
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