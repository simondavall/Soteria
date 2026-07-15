using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Soteria.Data;

namespace Soteria.Components.Account.Pages.Manage;

public partial class GenerateRecoveryCodes
{
    private string? _message;
    private ApplicationUser? _user;
    private IEnumerable<string>? _recoveryCodes;

    [Inject] private UserManager<ApplicationUser> UserManager { get; set; } = null!;
    [Inject] private IdentityRedirectManager RedirectManager { get; set; } = null!;
    [Inject] private ILogger<GenerateRecoveryCodes> Logger { get; set; } = null!;

    [CascadingParameter] private HttpContext HttpContext { get; set; } = null!;

    protected override async Task OnInitializedAsync()
    {
        _user = await UserManager.GetUserAsync(HttpContext.User);
        if (_user is null)
        {
            RedirectManager.RedirectToInvalidUser(UserManager, HttpContext);
            return;
        }

        var isTwoFactorEnabled = await UserManager.GetTwoFactorEnabledAsync(_user);

        if (!isTwoFactorEnabled)
        {
            RedirectManager.RedirectToWithStatus(
                "Account/Manage/TwoFactorAuthentication",
                "Cannot generate recovery codes. " +
                "Two factor authentication is not enabled.",
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

        var userId = await UserManager.GetUserIdAsync(_user);
        _recoveryCodes = await UserManager.GenerateNewTwoFactorRecoveryCodesAsync(_user, 10);
        _message = "You have generated new recovery codes.";

        Logger.LogInformation("User with ID '{UserId}' generated new 2FA recovery codes.", userId);
    }
}