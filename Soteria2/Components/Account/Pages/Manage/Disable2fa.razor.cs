using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Soteria2.Data;

namespace Soteria2.Components.Account.Pages.Manage;

public partial class Disable2fa
{
    private ApplicationUser? _user;

    [Inject] private UserManager<ApplicationUser> UserManager { get; set; } = default!;
    [Inject] private IdentityRedirectManager RedirectManager { get; set; } = default!;
    [Inject] private ILogger<Disable2fa> Logger { get; set; } = default!;

    [CascadingParameter] private HttpContext HttpContext { get; set; } = default!;

    protected override async Task OnInitializedAsync()
    {
        _user = await UserManager.GetUserAsync(HttpContext.User);
        if (_user is null)
        {
            RedirectManager.RedirectToInvalidUser(UserManager, HttpContext);
            return;
        }

        if (HttpMethods.IsGet(HttpContext.Request.Method) && !await UserManager.GetTwoFactorEnabledAsync(_user))
        {
            RedirectManager.RedirectToWithStatus(
                "Account/Manage/TwoFactorAuthentication",
                "Two-factor authentication is not currently enabled.",
                HttpContext);
        }
    }

    private async Task OnSubmitAsync()
    {
        if (_user is null)
        {
            RedirectManager.RedirectToInvalidUser(UserManager, HttpContext);
            return;
        }

        var result = await UserManager.SetTwoFactorEnabledAsync(_user, false);
        if (!result.Succeeded)
        {
            RedirectManager.RedirectToWithStatus(
                "Account/Manage/TwoFactorAuthentication",
                "Error: Failed to disable two-factor authentication.",
                HttpContext);

            return;
        }

        var userId = await UserManager.GetUserIdAsync(_user);

        Logger.LogInformation("User with ID '{UserId}' disabled two-factor authentication.", userId);

        RedirectManager.RedirectToWithStatus(
            "Account/Manage/TwoFactorAuthentication",
            "Two-factor authentication has been disabled. " +
            "You can enable it again by configuring an authenticator app.",
            HttpContext);
    }
}