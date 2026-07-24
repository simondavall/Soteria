using Microsoft.AspNetCore.Components;

namespace Soteria.Components.Features.Users.Pages;

public partial class UserDetails
{
    [Inject]
    private NavigationManager NavigationManager { get; set; } = default!;

    [Parameter]
    public Guid UserId { get; set; }

    private void ReturnToUserList()
    {
        NavigationManager.NavigateTo("/users");
    }
}