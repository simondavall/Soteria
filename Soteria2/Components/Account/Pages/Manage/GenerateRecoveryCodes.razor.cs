using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Soteria2.Data;

namespace Soteria2.Components.Account.Pages.Manage;

public partial class GenerateRecoveryCodes
{
    private string? _message;
    private ApplicationUser? _user;
    private IEnumerable<string>? _recoveryCodes;

    [Inject] private UserManager<ApplicationUser> UserManager { get; set; } = default!;
    [Inject] private IdentityRedirectManager RedirectManager { get; set; } = default!;
    [Inject] private ILogger<GenerateRecoveryCodes> Logger { get; set; } = default!;

    [CascadingParameter] private HttpContext HttpContext { get; set; } = default!;

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