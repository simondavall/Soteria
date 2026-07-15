using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Soteria.Data;

namespace Soteria.Components.Account.Pages;

public partial class LoginWithRecoveryCode
{
    private string? _message;

    [Inject] private SignInManager<ApplicationUser> SignInManager { get; set; } = null!;
    [Inject] private ILogger<LoginWithRecoveryCode> Logger { get; set; } = null!;
    [Inject] private IdentityRedirectManager RedirectManager { get; set; } = null!;

    [SupplyParameterFromForm] private InputModel? Input { get; set; }
    [SupplyParameterFromQuery] private string? ReturnUrl { get; set; }

    protected override async Task OnInitializedAsync()
    {
        Input ??= new InputModel();

        var user =
            await SignInManager.GetTwoFactorAuthenticationUserAsync();

        if (user is null)
        {
            RedirectManager.RedirectTo(
                "Account/Login",
                new Dictionary<string, object?> { ["ReturnUrl"] = ReturnUrl }
            );
        }
    }

    private async Task OnValidSubmitAsync()
    {
        var recoveryCode = Input!.RecoveryCode.Replace(" ", string.Empty);
        var result = await SignInManager.TwoFactorRecoveryCodeSignInAsync(recoveryCode);

        if (result.Succeeded)
        {
            Logger.LogInformation("User logged in with a recovery code.");
            RedirectManager.RedirectTo(ReturnUrl);
        }
        else if (result.IsLockedOut)
        {
            Logger.LogWarning("User account locked out.");
            RedirectManager.RedirectTo("Account/Lockout");
        }
        else
        {
            _message = "Error: Invalid recovery code entered.";
        }
    }

    private sealed class InputModel
    {
        [Required]
        [DataType(DataType.Text)]
        [Display(Name = "Recovery code")]
        public string RecoveryCode { get; set; } = string.Empty;
    }
}