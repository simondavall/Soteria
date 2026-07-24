using Microsoft.AspNetCore.Components;
using MudBlazor;

namespace Soteria.Components.Features.Users.Pages;

public partial class UserList
{
    [Inject]
    private NavigationManager Navigation { get; set; } = default!;

    private IReadOnlyList<UserSummary> Users { get; } = [];

    private void SelectUser(TableRowClickEventArgs<UserSummary> args)
    {
        if (args.Item is null)
        {
            return;
        }

        Navigation.NavigateTo($"/users/{args.Item.UserId}");
    }

    private sealed record UserSummary(
        Guid UserId,
        string DisplayName,
        string Email,
        bool EmailConfirmed,
        bool IsLockedOut);
}