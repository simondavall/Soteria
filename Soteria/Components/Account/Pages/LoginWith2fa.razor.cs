using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Soteria.Data;

namespace Soteria.Components.Account.Pages;

public partial class LoginWith2fa
{
    private string? _message;
    private ApplicationUser _user = null!;

    private string? Message => _message;
    
    [Inject] private SignInManager<ApplicationUser> SignInManager { get; set; } = null!;
    [Inject] private UserManager<ApplicationUser> UserManager { get; set; } = null!;
    [Inject] private IdentityRedirectManager RedirectManager { get; set; } = null!;
    [Inject] private ILogger<LoginWith2fa> Logger { get; set; } = null!;

    [SupplyParameterFromForm] private InputModel? Input { get; set; }
    [SupplyParameterFromQuery] private string? ReturnUrl { get; set; }
    [SupplyParameterFromQuery] private bool RememberMe { get; set; }

    protected override async Task OnInitializedAsync()
    {
        Input ??= new InputModel();

        // Ensure the user has gone through the username & password screen first
        _user = await SignInManager.GetTwoFactorAuthenticationUserAsync() ??
               throw new InvalidOperationException("Unable to load two-factor authentication user.");
    }

    private async Task OnValidSubmitAsync()
    {
        var authenticatorCode = Input!.TwoFactorCode!.Replace(" ", string.Empty).Replace("-", string.Empty);
        var result = await SignInManager.TwoFactorAuthenticatorSignInAsync(authenticatorCode, RememberMe, Input.RememberMachine);
        var userId = await UserManager.GetUserIdAsync(_user);

        if (result.Succeeded)
        {
            Logger.LogInformation("User with ID '{UserId}' logged in with 2fa.", userId);
            RedirectManager.RedirectTo(ReturnUrl);
        }
        else if (result.IsLockedOut)
        {
            Logger.LogWarning("User with ID '{UserId}' account locked out.", userId);
            RedirectManager.RedirectTo("Account/Lockout");
        }
        else
        {
            Logger.LogWarning("Invalid authenticator code entered for user with ID '{UserId}'.", userId);
            _message = "Error: Invalid authenticator code.";
        }
    }

    private sealed class InputModel
    {
        [Required]
        [StringLength(7, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.",
            MinimumLength = 6)]
        [DataType(DataType.Text)]
        [Display(Name = "Authenticator code")]
        public string? TwoFactorCode { get; set; }

        [Display(Name = "Remember this machine")]
        public bool RememberMachine { get; set; }
    }
}