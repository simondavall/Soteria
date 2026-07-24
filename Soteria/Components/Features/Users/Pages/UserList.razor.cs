using Microsoft.AspNetCore.Components;
using MudBlazor;

namespace Soteria.Components.Features.Users.Pages;

public partial class UserList
{
    [Inject]
    private UserService UserService { get; set; } = default!;

    [Inject]
    private NavigationManager Navigation { get; set; } = default!;

    private IReadOnlyList<UserSummary> Users { get; set; } = [];
    private string _searchText = string.Empty;

    protected override async Task OnInitializedAsync()
    {
        Users = await UserService.GetUsersAsync();
    }

    private bool FilterUser(UserSummary user)
    {
        if (string.IsNullOrWhiteSpace(_searchText))
        {
            return true;
        }

        var searchText = _searchText.Trim();

        return user.DisplayName.Contains(searchText, StringComparison.OrdinalIgnoreCase)
               || user.Email.Contains(searchText, StringComparison.OrdinalIgnoreCase)
               || user.EmailConfirmed.ToString().Contains(searchText, StringComparison.OrdinalIgnoreCase)
               || user.IsLockedOut.ToString().Contains(searchText, StringComparison.OrdinalIgnoreCase);
    }

    private void SelectUser(TableRowClickEventArgs<UserSummary> args)
    {
        if (args.Item is null)
        {
            return;
        }

        Navigation.NavigateTo($"/users/{args.Item.UserId}");
    }
}