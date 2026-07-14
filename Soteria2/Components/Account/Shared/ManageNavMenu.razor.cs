using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Soteria2.Data;

namespace Soteria2.Components.Account.Shared;

public partial class ManageNavMenu
{
    private bool _hasExternalLogins;

    [Inject]
    private SignInManager<ApplicationUser> SignInManager { get; set; } = default!;

    protected override async Task OnInitializedAsync()
    {
        var externalAuthenticationSchemes = await SignInManager.GetExternalAuthenticationSchemesAsync();
        _hasExternalLogins = externalAuthenticationSchemes.Any();
    }
}