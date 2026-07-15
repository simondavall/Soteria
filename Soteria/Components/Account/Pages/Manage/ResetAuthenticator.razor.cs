using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Soteria.Data;

namespace Soteria.Components.Account.Pages.Manage;

public partial class ResetAuthenticator
{
    [Inject] private UserManager<ApplicationUser> UserManager { get; set; } = null!;
    [Inject] private SignInManager<ApplicationUser> SignInManager { get; set; } = null!;
    [Inject] private IdentityRedirectManager RedirectManager { get; set; } = null!;
    [Inject] private ILogger<ResetAuthenticator> Logger { get; set; } = null!;

    [CascadingParameter] private HttpContext HttpContext { get; set; } = null!;

    private async Task OnSubmitAsync()
    {
        var user = await UserManager.GetUserAsync(HttpContext.User);
        if (user is null)
        {
            RedirectManager.RedirectToInvalidUser(UserManager, HttpContext);
            return;
        }

        await UserManager.SetTwoFactorEnabledAsync(user, false);
        await UserManager.ResetAuthenticatorKeyAsync(user);

        var userId = await UserManager.GetUserIdAsync(user);

        Logger.LogInformation("User with ID '{UserId}' reset their authenticator app key.", userId);

        await SignInManager.RefreshSignInAsync(user);

        RedirectManager.RedirectToWithStatus(
            "Account/Manage/EnableAuthenticator",
            "Your authenticator app key has been reset. " +
            "Configure your authenticator app using the new key.",
            HttpContext);
    }
}