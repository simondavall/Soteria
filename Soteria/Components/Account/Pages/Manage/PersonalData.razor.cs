using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Soteria.Data;

namespace Soteria.Components.Account.Pages.Manage;

public partial class PersonalData
{
    [Inject]
    private UserManager<ApplicationUser> UserManager { get; set; } = null!;

    [Inject]
    private IdentityRedirectManager RedirectManager { get; set; } = null!;

    [CascadingParameter]
    private HttpContext HttpContext { get; set; } = null!;

    protected override async Task OnInitializedAsync()
    {
        var user = await UserManager.GetUserAsync(HttpContext.User);

        if (user is null)
        {
            RedirectManager.RedirectToInvalidUser(
                UserManager,
                HttpContext);
        }
    }
}